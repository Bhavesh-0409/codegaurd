"""
Sentinel backend.

NOTE on scope (intentional hackathon simplifications):
- No real auth/roles system. `user_id` is just a string passed by the client
  (e.g. a name typed into the UI). Swap for real auth before this touches
  production.
- Threat-intel doc is stored in-memory per process, not per-session/user.
  Fine for a single-demo hackathon run; would need proper session/user scoping
  for a real multi-tenant deployment.
"""

import time

from dotenv import load_dotenv

load_dotenv()  # reads backend/.env automatically - set GEMINI_API_KEY there once

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import db
from extractor import extract_python_imports, filter_third_party
from agent.orchestrator import verify_package
from agent.prompt_injection import check_prompt_injection
from agent.tools import parse_threat_doc
from agent.gemini_utils import generate_security_patch
from models import PromptCheckRequest, PromptCheckResponse, FixRequest, FixResponse

app = FastAPI(title="Sentinel API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before any real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)

db.init_db()

# in-memory threat-intel doc store (see NOTE above)
_threat_doc_entries: list[dict] = []


def _severity_for(verdict: str) -> str:
    return {
        "malicious": "high",
        "hallucinated": "high",
        "typosquat": "medium",
        "unverified": "low",
        "clean": "low",
        "injection_detected": "high",
        "confirmed_injection": "high",
        "suspected_injection": "medium",
        "benign": "low",
        "out_of_scope": "low",
    }.get(verdict, "low")


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Feature 1: Prompt injection check
# ---------------------------------------------------------------------------

@app.post("/api/check-prompt", response_model=PromptCheckResponse)
def check_prompt(req: PromptCheckRequest):
    result = check_prompt_injection(req.prompt)
    security_status = result.get("security_status", "safe")
    scope_status = result.get("scope_status", "in_scope")
    reasoning_notes = result.get("reasoning_notes", "")

    verdict = "benign"
    if security_status == "malicious":
        verdict = "confirmed_injection"
    elif scope_status == "out_of_scope":
        verdict = "out_of_scope"

    if verdict != "benign":
        db.log_event(
            user_id=req.user_id,
            scan_type="prompt",
            verdict=verdict,
            flagged_item=req.prompt[:200],
            reason=reasoning_notes,
            severity=_severity_for(verdict),
        )
    return result


# ---------------------------------------------------------------------------
# Feature: One-Click Fix
# ---------------------------------------------------------------------------

@app.post("/api/fix", response_model=FixResponse)
def fix_code(req: FixRequest):
    # Reuse the orchestrator client for simplicity
    from agent.orchestrator import _get_client
    client = _get_client()
    patched = generate_security_patch(client, req.vulnerable_code)
    return {"patched_code": patched}


# ---------------------------------------------------------------------------
# Threat-intel doc upload (feeds into Feature 2)
# ---------------------------------------------------------------------------

@app.post("/api/upload-threat-doc")
async def upload_threat_doc(file: UploadFile = File(...)):
    global _threat_doc_entries
    content = (await file.read()).decode("utf-8", errors="ignore")
    _threat_doc_entries = parse_threat_doc(content, file.filename)
    return {"entries_parsed": len(_threat_doc_entries), "entries": _threat_doc_entries}


@app.post("/api/clear-threat-doc")
def clear_threat_doc():
    global _threat_doc_entries
    _threat_doc_entries = []
    return {"status": "cleared"}


# ---------------------------------------------------------------------------
# Feature 2: Code / package scan
# ---------------------------------------------------------------------------

@app.post("/api/scan-code")
async def scan_code(user_id: str = Form(...), file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8", errors="ignore")

    try:
        imports = extract_python_imports(content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    imports = filter_third_party(imports)

    results = []
    for idx, imp in enumerate(imports):
        if idx > 0:
            time.sleep(1.5)  # small gap between packages to stay under free-tier rate limits

        verdict_data = verify_package(
            package_name=imp.package,
            ecosystem="pypi",
            threat_doc_entries=_threat_doc_entries,
        )
        verdict = verdict_data.get("verdict", "unverified")
        reason = verdict_data.get("reason", "")
        source = verdict_data.get("source", "")

        result = {
            "package": imp.package,
            "line_number": imp.line_number,
            "full_statement": imp.full_statement,
            "verdict": verdict,
            "reason": reason,
            "source": source,
        }
        results.append(result)

        if verdict != "clean":
            db.log_event(
                user_id=user_id,
                scan_type="code",
                verdict=verdict,
                flagged_item=imp.package,
                reason=reason,
                severity=_severity_for(verdict),
            )

    return {"results": results}


# ---------------------------------------------------------------------------
# Feature 3: Admin audit log
# ---------------------------------------------------------------------------

@app.get("/api/admin/audit-log")
def audit_log(limit: int = 500):
    return db.get_all_events(limit=limit)


@app.get("/api/admin/user-summary")
def user_summary():
    return db.get_user_summary()