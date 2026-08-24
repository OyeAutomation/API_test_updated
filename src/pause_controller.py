"""Cooperative pause between requests.

The worker thread calls wait_if_paused() before each request; when the GUI
pauses, it blocks until resumed. On resume the GUI may swap in a new
ParsedRequest / CryptoAdapter / ApiProfile via update(), and settings are
mutated in place, so edits take effect from the next request onward.
"""

from __future__ import annotations

import threading
from typing import Optional

_UNSET = object()


class PauseController:
    """Shared pause state between the GUI thread and the test-run worker.

    Attributes:
        parsed:   the ParsedRequest used for the next request (swap via update)
        settings: mutable Settings object (edit fields in place)
        adapter:  the CryptoAdapter used for the next request (swap via update)
        profile:  the ApiProfile used for test selection/eval (swap via update)
    """

    def __init__(self, parsed=None, settings=None, adapter=None, profile=None):
        self.parsed = parsed
        self.settings = settings
        self.adapter = adapter
        self.profile = profile
        self._lock = threading.Lock()
        self._resume_event = threading.Event()
        self._resume_event.set()  # not paused initially
        self._paused = False

    def pause(self) -> None:
        """Ask the worker to stop before the next request."""
        with self._lock:
            self._paused = True
            self._resume_event.clear()

    def update(self, parsed=_UNSET, settings=_UNSET, adapter=_UNSET,
               profile=_UNSET) -> None:
        """Swap in new state while paused (must be called before resume()).

        Only the fields explicitly passed are replaced, so passing None is a
        valid way to clear a field (e.g. dropping the API profile).
        """
        with self._lock:
            if parsed is not _UNSET:
                self.parsed = parsed
            if settings is not _UNSET:
                self.settings = settings
            if adapter is not _UNSET:
                self.adapter = adapter
            if profile is not _UNSET:
                self.profile = profile

    def resume(self) -> None:
        """Unblock the worker; it continues from the current point."""
        with self._lock:
            self._paused = False
        self._resume_event.set()

    def wait_if_paused(self, cancel_event: Optional[threading.Event] = None,
                       timeout: float = 0.2) -> None:
        """Block the calling (worker) thread while paused.

        Wakes periodically to re-check the cancel event so a cancel while
        paused aborts promptly instead of waiting for a resume.
        """
        while self._paused:
            if cancel_event is not None and cancel_event.is_set():
                return
            self._resume_event.wait(timeout)

    def is_paused(self) -> bool:
        return self._paused