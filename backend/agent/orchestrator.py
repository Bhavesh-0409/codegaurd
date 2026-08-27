"""
Package-verification agent (Gemini).

Design principle: the LLM must NEVER assert whether a package exists, is
malicious, or is a typosquat from its own memory. Every claim has to be
grounded by calling one of the tools below. The LLM's job is orchestration
(deciding which tools to call) and explanation (turning tool output into a
one-line human-readable reason) - not being the source of truth.

Uses Gemini's automatic function calling: you hand it plain Python functions
and it inspects their signature/docstring to build the tool schema, decides
which to call, executes them, and loops until it has a final answer - no
manual tool-call loop needed on our side.
"""

import json
import os

from google import genai
from google.genai import types

from . import tools as t
from .gemini_utils import generate_with_retry

_client = None


def _get_client():
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not set. Add it to backend/.env")
        _client = genai.Client(api_key=api_key)
    return _client


MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")

SYSTEM_PROMPT = """You are Sentinel, a package-verification agent. You will be given \
ONE package name that was extracted deterministically from a user's uploaded code \
(you can trust that this package name was actually imported - that part is already verified).

Your job: call the available tools to gather ground-truth evidence about this \
package, then produce a final verdict. You must NEVER state whether a package \
exists, is malicious, or is a typosquat based on your own training knowledge - \
always ground every claim in a tool call result.

Call registry_lookup, typosquat_score, and public_threat_intel_lookup for every \
package. Call custom_threat_intel_lookup too if the user message says a threat-intel \
doc is available.

After calling tools, respond with ONLY valid JSON (no markdown fences, no other text) \
in this exact shape:
{
  "verdict": "clean" | "unverified" | "typosquat" | "hallucinated" | "malicious",
  "reason": "<one sentence, cite which check drove the verdict>",
  "source": "<which tool/check the verdict is primarily based on>"
}

Verdict guidance:
- "malicious": flagged by public or custom threat intel
- "hallucinated": registry_lookup says the package does not exist
- "typosquat": exists, but typosquat_score flags a suspiciously close match to a popular package, or a hallucination-suffix pattern
- "unverified": exists, but has weak trust signals (very new, single release, no description)
- "clean": exists, no red flags from any check
"""


def verify_package(package_name: str, ecosystem: str = "pypi", threat_doc_entries: list[dict] | None = None) -> dict:
    threat_doc_entries = threat_doc_entries or []
    client = _get_client()

    # Plain functions handed to Gemini as tools - it reads the docstring/type
    # hints to build the schema and calls them itself (automatic function calling).
    def registry_lookup(package_name: str, ecosystem: str) -> dict:
        """Check if a package exists on PyPI or npm and return basic metadata
        (author, release dates, version count). Always call this first.

        Args:
            package_name: the package name to check
            ecosystem: either "pypi" or "npm"
        """
        return t.registry_lookup(package_name, ecosystem)

    def typosquat_score(package_name: str) -> dict:
        """Compute edit-distance from the package name to a list of popular
        packages, and check for common LLM-hallucination naming patterns
        (e.g. '-utils', '-toolkit' suffixes). Call this for every package.

        Args:
            package_name: the package name to check
        """
        return t.typosquat_score(package_name)

    def public_threat_intel_lookup(package_name: str, ecosystem: str) -> dict:
        """Check the package against OSV.dev for known public
        vulnerability/malicious-package advisories.

        Args:
            package_name: the package name to check
            ecosystem: either "PyPI" or "npm"
        """
        return t.public_threat_intel_lookup(package_name, ecosystem)

    def custom_threat_intel_lookup(package_name: str) -> dict:
        """Check the package against the user's uploaded threat-intel
        document (org-specific blocklist), if one was uploaded this session.

        Args:
            package_name: the package name to check
        """
        return t.custom_threat_intel_lookup(package_name, threat_doc_entries)

    user_message = (
        f"Package to verify: '{package_name}' (ecosystem: {ecosystem}). "
        f"{'A custom threat-intel doc IS available - call custom_threat_intel_lookup too.' if threat_doc_entries else 'No custom threat-intel doc was uploaded this session.'}"
    )

    response = generate_with_retry(
        client,
        model=MODEL_NAME,
        contents=user_message,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            tools=[
                registry_lookup,
                typosquat_score,
                public_threat_intel_lookup,
                custom_threat_intel_lookup,
            ],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(
                maximum_remote_calls=8
            ),
        ),
    )

    text = (response.text or "").strip()
    text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "verdict": "unverified",
            "reason": "Agent response could not be parsed - flagged for manual review.",
            "source": "parser_fallback",
        }