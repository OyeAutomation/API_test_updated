"""Rate-limit / IP-block detection and interactive pause handling.

When the target API responds with 429 (Too Many Requests) or a 403 that
looks like a WAF/IP block, the suite should stop hammering the endpoint:
with an interactive handler (CLI/GUI) it pauses and asks the user to
unblock their IP, then resumes or cancels; without one (tests, scripts,
CI) it just warns and honors Retry-After so it never hangs.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Body markers that make a 403 count as a WAF / IP block rather than a
# plain authorization denial.
BLOCK_MARKERS = (
    "blocked",
    "rate limit",
    "rate_limit",
    "too many requests",
    "access denied",
    "captcha",
    "temporarily unavailable",
)

# Cap for the headless Retry-After wait so a run can never stall forever.
RETRY_AFTER_CAP_SECONDS = 30

# Callback contract: on_rate_limit(response, consecutive_blocks)
# -> ("resume", None | new_delay_ms) | ("cancel", None)
RateLimitCallback = Callable[[object, int], Tuple[str, Optional[int]]]


# Business-level block marker that counts on any HTTP status: some APIs
# return HTTP 401/200 with a message like "IP Already blocked" instead of
# a true 429/403.
ANY_STATUS_BLOCK_MARKERS = ("ip already blocked",)


def _response_body(resp) -> str:
    """Return the effective response body (decrypted when available)."""
    return getattr(resp, "_crypto_decrypted", None) or getattr(resp, "text", "") or ""


def is_block_response(resp) -> bool:
    """Return True when a response indicates rate limiting or an IP block."""
    if resp is None:
        return False
    if resp.status_code == 429:
        return True
    body = _response_body(resp).lower()
    if any(marker in body for marker in ANY_STATUS_BLOCK_MARKERS):
        return True
    if resp.status_code == 403:
        return any(marker in body for marker in BLOCK_MARKERS)
    return False


def decide_prompt_action(line: str, current_delay_ms: int) -> Tuple[str, Optional[int]]:
    """Map a user's CLI prompt input to (action, new_delay_ms).

    Actions:
        "" / "r" / "resume"  -> ("resume", None)         keep current delay
        "d" / "double"       -> ("resume", delay * 2)    double the delay
        "<number>"           -> ("resume", <number>)     set a delay in ms
        "c" / "cancel"       -> ("cancel", None)         abort the run
        anything else        -> ("invalid", None)        ask again
    """
    action = line.strip().lower()
    if action in ("", "r", "resume"):
        return "resume", None
    if action in ("c", "cancel"):
        return "cancel", None
    if action in ("d", "double"):
        return "resume", max(1, current_delay_ms * 2)
    try:
        value = int(action)
    except ValueError:
        return "invalid", None
    if value < 0:
        return "invalid", None
    return "resume", value


class RateLimitGuard:
    """Watches responses and pauses the run when the endpoint blocks us.

    The guard is shared by both request paths (engine and mandatory
    detection) so the consecutive-block counter spans the whole run.
    """

    def __init__(
        self,
        settings,
        cancel_event: Optional[threading.Event] = None,
        on_rate_limit: Optional[RateLimitCallback] = None,
    ):
        self.settings = settings
        self.cancel_event = cancel_event
        self.on_rate_limit = on_rate_limit
        self.consecutive_blocks = 0
        self.total_blocks = 0

    def check(self, resp) -> None:
        """Inspect a response; pause the run if a block is detected.

        With a callback: blocks until the user resumes or cancels.
        Without one (headless): warns, honors Retry-After (capped), and
        continues — the run never hangs.
        """
        if not is_block_response(resp):
            self.consecutive_blocks = 0
            return

        self.consecutive_blocks += 1
        self.total_blocks += 1

        if self.on_rate_limit is not None:
            logger.warning(
                "Rate limit / IP block detected (HTTP %s) — pausing for user...",
                resp.status_code,
            )
            action, new_delay = self.on_rate_limit(resp, self.consecutive_blocks)
            if action == "cancel":
                logger.warning("Rate-limit pause: run cancelled by user")
                if self.cancel_event:
                    self.cancel_event.set()
                return
            if new_delay is not None:
                self.settings.request_delay_ms = new_delay
                logger.warning("Delay between requests updated to %s ms", new_delay)
            return

        wait = self._headless_wait(resp)
        logger.warning(
            "Rate limit / IP block detected (HTTP %s) — waiting %ss "
            "(no pause handler; use the CLI/GUI to pause instead)",
            resp.status_code,
            wait,
        )
        time.sleep(wait)

    def _headless_wait(self, resp) -> int:
        retry_after = getattr(resp, "headers", {}) and resp.headers.get("Retry-After")
        if retry_after:
            try:
                return min(int(float(retry_after)), RETRY_AFTER_CAP_SECONDS)
            except (TypeError, ValueError):
                pass
        return min(2 ** (self.consecutive_blocks - 1), 8)
