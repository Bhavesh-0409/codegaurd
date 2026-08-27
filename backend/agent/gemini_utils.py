"""
Shared helper for calling the Gemini API with automatic retry on rate-limit
(429) errors. The free tier has tight per-minute quotas, and a single package
verification can trigger several internal round-trips (one per tool call), so
hitting 429 occasionally is expected - we just need to back off and retry
instead of crashing the request.
"""

import re
import time

from google.genai import errors


def generate_with_retry(client, max_retries: int = 4, **kwargs):
    """
    Wraps client.models.generate_content with retry-on-429 logic.
    Reads the server's suggested retryDelay when available, otherwise
    falls back to simple exponential backoff.
    """
    last_error = None
    for attempt in range(max_retries):
        try:
            return client.models.generate_content(**kwargs)
        except errors.APIError as e:
            last_error = e
            code = getattr(e, "code", None)
            if code not in (429, 503):
                raise

            wait_seconds = _extract_retry_delay(e) or (2 ** attempt) * 2
            print(f"[gemini_utils] Rate limited (429). Retrying in {wait_seconds:.1f}s "
                  f"(attempt {attempt + 1}/{max_retries})...")
            time.sleep(wait_seconds)

    raise last_error


def _extract_retry_delay(error) -> float | None:
    """Pull the server-suggested retry delay (in seconds) out of the error, if present."""
    try:
        message = str(error)
        match = re.search(r"retryDelay['\"]?:\s*['\"]?(\d+(?:\.\d+)?)s", message)
        if match:
            return float(match.group(1))
    except Exception:
        pass
    return None


def generate_security_patch(client, vulnerable_code: str, model: str = "gemini-3.5-flash-lite") -> str:
    """Uses the LLM to patch security vulnerabilities in the provided code snippet.
    Returns only the raw patched code."""
    from google.genai import types
    
    system_instruction = (
        "You are an expert security engineer and code patcher. "
        "You will be given a snippet of code that contains a security vulnerability (e.g. prompt injection, malicious imports). "
        "Your job is to rewrite the code to fix the vulnerability while preserving the intended functionality as much as possible. "
        "If an import is malicious, remove it or replace it with a safe standard library alternative if obvious. "
        "Return ONLY the raw patched code. Do not include markdown code fences (like ```python) and do not include any conversational text or explanations."
    )
    
    response = generate_with_retry(
        client,
        model=model,
        contents=vulnerable_code,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
        ),
    )
    
    patched_code = (response.text or "").strip()
    # Extra safety: if the model accidentally included fences despite instructions
    if patched_code.startswith("```"):
        patched_code = patched_code.split("\n", 1)[-1]
        if patched_code.endswith("```"):
            patched_code = patched_code.rsplit("\n", 1)[0]
    return patched_code.strip()