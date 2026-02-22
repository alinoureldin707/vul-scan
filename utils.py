"""
Shared utilities for the OWASP Security Scanner.
"""
import time
from typing import TypeVar, Callable, Any

from config import MAX_RETRIES
from printer import print_warning, print_error

T = TypeVar("T")


def invoke_with_retry(
    invoke_fn: Callable[[], Any],
    normalize_fn: Callable[[Any], T | None],
    context: str,
    max_retries: int = MAX_RETRIES,
) -> T | None:
    """
    Generic retry wrapper for agent invocations.
    
    Args:
        invoke_fn: Function that invokes the agent (no args, returns raw response)
        normalize_fn: Function to normalize/validate the response
        context: Description for logging (e.g., "finder:auth.js")
        max_retries: Maximum number of attempts
        
    Returns:
        Normalized response or None if all attempts fail
    """
    for attempt in range(1, max_retries + 1):
        try:
            raw = invoke_fn()
            result = normalize_fn(raw)
            if result is not None:
                return result
            if attempt < max_retries:
                print_warning(f"Attempt {attempt}/{max_retries}: Empty response for {context}, retrying...")
                time.sleep(0.5 * attempt)  # Exponential backoff
        except Exception as exc:
            if attempt < max_retries:
                print_warning(f"Attempt {attempt}/{max_retries} failed for {context}: {exc}")
                time.sleep(0.5 * attempt)
            else:
                print_error(f"All {max_retries} attempts failed for {context}: {exc}")
    return None
