"""
The actual grounding tools the LLM agent calls. These are deterministic,
auditable functions - NOT LLM calls - which is the whole point: the model
orchestrates and explains, but every factual claim about a package traces
back to one of these.
"""

import re
from datetime import datetime, timezone

import requests
import Levenshtein

# ---------------------------------------------------------------------------
# 1. Registry lookup
# ---------------------------------------------------------------------------

PYPI_URL = "https://pypi.org/pypi/{package}/json"
NPM_URL = "https://registry.npmjs.org/{package}"


def registry_lookup(package_name: str, ecosystem: str = "pypi") -> dict:
    """Check whether a package exists on PyPI or npm, and pull basic metadata."""
    try:
        if ecosystem == "pypi":
            resp = requests.get(PYPI_URL.format(package=package_name), timeout=5)
            if resp.status_code != 200:
                return {"exists": False, "package": package_name, "ecosystem": ecosystem}
            data = resp.json()
            info = data.get("info", {})
            releases = data.get("releases", {})
            first_version_date = None
            if releases:
                all_dates = [
                    r[0]["upload_time_iso_8601"]
                    for r in releases.values()
                    if r
                ]
                if all_dates:
                    first_version_date = min(all_dates)
            return {
                "exists": True,
                "package": package_name,
                "ecosystem": ecosystem,
                "summary": info.get("summary"),
                "author": info.get("author"),
                "home_page": info.get("home_page"),
                "first_release_date": first_version_date,
                "latest_version": info.get("version"),
                "num_releases": len(releases),
            }

        elif ecosystem == "npm":
            resp = requests.get(NPM_URL.format(package=package_name), timeout=5)
            if resp.status_code != 200:
                return {"exists": False, "package": package_name, "ecosystem": ecosystem}
            data = resp.json()
            time_info = data.get("time", {})
            return {
                "exists": True,
                "package": package_name,
                "ecosystem": ecosystem,
                "description": data.get("description"),
                "maintainers": [m.get("name") for m in data.get("maintainers", [])],
                "first_release_date": time_info.get("created"),
                "latest_version": data.get("dist-tags", {}).get("latest"),
                "num_versions": len(data.get("versions", {})),
            }
        else:
            return {"error": f"Unknown ecosystem: {ecosystem}"}

    except requests.RequestException as e:
        return {"error": str(e), "package": package_name, "exists": None}


# ---------------------------------------------------------------------------
# 2. Metadata / trust-signal check (built on top of registry_lookup data)
# ---------------------------------------------------------------------------

def metadata_check(registry_data: dict) -> dict:
    """
    Given the dict returned by registry_lookup, derive simple trust signals.
    Kept heuristic and explainable on purpose - no black-box scoring.
    """
    if not registry_data.get("exists"):
        return {"trust_signals": [], "note": "Package does not exist - no metadata to evaluate."}

    signals = []
    first_release = registry_data.get("first_release_date")
    if first_release:
        try:
            release_dt = datetime.fromisoformat(first_release.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - release_dt).days
            if age_days < 30:
                signals.append(f"Package is very new (first released {age_days} days ago).")
        except ValueError:
            pass

    num_releases = registry_data.get("num_releases") or registry_data.get("num_versions")
    if num_releases is not None and num_releases <= 1:
        signals.append("Only one release ever published - low maturity signal.")

    if not registry_data.get("summary") and not registry_data.get("description"):
        signals.append("No description/summary provided - sparse metadata.")

    return {"trust_signals": signals}


# ---------------------------------------------------------------------------
# 3. Typosquat / slopsquat distance scoring
# ---------------------------------------------------------------------------

# Small seed list for the hackathon demo - expand as needed.
POPULAR_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "scipy", "matplotlib",
    "beautifulsoup4", "pillow", "pytest", "boto3", "sqlalchemy", "click",
    "pyyaml", "urllib3", "cryptography", "aiohttp", "fastapi", "uvicorn",
    "scikit-learn", "torch", "tensorflow", "transformers", "langchain",
    "pydantic", "jinja2", "redis", "celery", "gunicorn", "selenium",
]


def typosquat_score(package_name: str, threshold: int = 2) -> dict:
    """
    Compute edit-distance from package_name to each popular package.
    Also flags common LLM-hallucination suffix patterns (-utils, -toolkit, -sdk etc.)
    """
    closest = None
    closest_distance = None
    for popular in POPULAR_PACKAGES:
        dist = Levenshtein.distance(package_name.lower(), popular.lower())
        if closest_distance is None or dist < closest_distance:
            closest_distance = dist
            closest = popular

    is_suspicious_distance = (
        closest_distance is not None
        and 0 < closest_distance <= threshold
        and package_name.lower() != closest.lower()
    )

    hallucination_suffixes = ["-utils", "-toolkit", "-sdk", "-helper", "-wrapper", "-client", "-core"]
    matched_suffix = next((s for s in hallucination_suffixes if package_name.lower().endswith(s)), None)

    return {
        "closest_popular_package": closest,
        "edit_distance": closest_distance,
        "is_suspected_typosquat": is_suspicious_distance,
        "hallucination_suffix_pattern": matched_suffix,
    }


# ---------------------------------------------------------------------------
# 4. Threat intel lookup - public (OSV.dev) + user-uploaded doc
# ---------------------------------------------------------------------------

OSV_URL = "https://api.osv.dev/v1/query"


def public_threat_intel_lookup(package_name: str, ecosystem: str = "PyPI") -> dict:
    """Check OSV.dev for known vulnerabilities/malicious advisories."""
    try:
        resp = requests.post(
            OSV_URL,
            json={"package": {"name": package_name, "ecosystem": ecosystem}},
            timeout=5,
        )
        if resp.status_code != 200:
            return {"vulnerabilities": []}
        data = resp.json()
        vulns = data.get("vulns", [])
        return {
            "vulnerabilities": [
                {"id": v.get("id"), "summary": v.get("summary")} for v in vulns
            ]
        }
    except requests.RequestException as e:
        return {"error": str(e), "vulnerabilities": []}


def custom_threat_intel_lookup(package_name: str, uploaded_doc_entries: list[dict]) -> dict:
    """
    Check the package against a user-uploaded blocklist doc.
    uploaded_doc_entries: list of {"package": str, "reason": str} parsed from
    the uploaded CSV/markdown at upload time (see parse_threat_doc below).

    Simple exact-match on hackathon timeline; swap for embeddings/RAG later
    if you want fuzzier matching against free-text documentation.
    """
    package_lower = package_name.lower()
    for entry in uploaded_doc_entries:
        if entry["package"].lower() == package_lower:
            return {"flagged": True, "reason": entry["reason"], "source": "user_uploaded_doc"}
    return {"flagged": False}


def parse_threat_doc(file_content: str, filename: str) -> list[dict]:
    """
    Parse an uploaded threat-intel doc into {"package": ..., "reason": ...} entries.
    Supports simple CSV ('package,reason' per line) and loose markdown/text
    (lines like '- package_name: reason' or '* package_name - reason').
    """
    entries = []

    if filename.endswith(".csv"):
        lines = file_content.strip().splitlines()
        for line in lines[1:] if lines and "package" in lines[0].lower() else lines:
            parts = [p.strip() for p in line.split(",", 1)]
            if len(parts) == 2 and parts[0]:
                entries.append({"package": parts[0], "reason": parts[1]})
    else:
        # loose markdown/text parsing
        pattern = re.compile(r"^[-*]?\s*([A-Za-z0-9_.\-]+)\s*[:\-–]\s*(.+)$")
        for line in file_content.strip().splitlines():
            match = pattern.match(line.strip())
            if match:
                entries.append({"package": match.group(1), "reason": match.group(2)})

    return entries
