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
        except errors.ClientError as e:
            last_error = e
            if getattr(e, "code", None) != 429:
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