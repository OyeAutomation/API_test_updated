"""Unit tests for the cooperative pause controller used by the GUI."""
import threading
import time

import pytest

from src.pause_controller import PauseController
from src.models import Settings


class _Obj:
    def __init__(self, label):
        self.label = label

    def __repr__(self):
        return f"_Obj({self.label})"


def test_not_paused_by_default():
    controller = PauseController()
    assert not controller.is_paused()
    controller.wait_if_paused(timeout=0.01)  # returns immediately


def test_pause_blocks_and_resume_unblocks():
    controller = PauseController(settings=Settings(request_delay_ms=10))
    controller.pause()
    assert controller.is_paused()

    unblocked = threading.Event()

    def worker():
        controller.wait_if_paused(timeout=0.05)
        unblocked.set()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    time.sleep(0.15)
    assert not unblocked.is_set(), "worker must stay blocked while paused"

    controller.resume()
    assert unblocked.wait(timeout=2), "worker must proceed after resume"
    assert not controller.is_paused()
    t.join(timeout=2)


def test_cancel_while_paused_wakes_worker():
    controller = PauseController()
    cancel_event = threading.Event()
    controller.pause()

    woke = threading.Event()

    def worker():
        controller.wait_if_paused(cancel_event, timeout=0.05)
        woke.set()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    time.sleep(0.1)
    assert not woke.is_set()

    cancel_event.set()
    assert woke.wait(timeout=2), "cancel must wake a paused worker"
    t.join(timeout=2)


def test_update_swaps_state():
    controller = PauseController(parsed=_Obj("old"), settings=Settings(),
                                 adapter=_Obj("old-adapter"), profile=_Obj("old-profile"))
    controller.update(parsed=_Obj("new"), adapter=_Obj("new-adapter"), profile=None)
    assert controller.parsed.label == "new"
    assert controller.adapter.label == "new-adapter"
    assert controller.profile is None
    # unspecified fields are left untouched
    assert controller.settings is not None


def test_multiple_pause_resume_cycles():
    controller = PauseController()
    for _ in range(3):
        controller.pause()
        assert controller.is_paused()
        controller.resume()
        assert not controller.is_paused()
    controller.pause()
    controller.pause()  # idempotent
    controller.resume()
    assert not controller.is_paused()