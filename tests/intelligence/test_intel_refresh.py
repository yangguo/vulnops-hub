"""Scheduling behavior for the dedicated intelligence refresh worker."""

from types import SimpleNamespace

from vulnops.workers.intel_refresh import IntelRefreshWorker


def test_bounded_refresh_does_not_sleep_after_final_iteration(monkeypatch):
    worker = IntelRefreshWorker(
        session_factory=lambda: None,
        settings=SimpleNamespace(kev_refresh_interval_seconds=86400.0),
    )
    monkeypatch.setattr(worker, "cycle", lambda: {"kev": 0})

    def unexpected_sleep(_seconds):
        raise AssertionError("bounded refresh slept after its final iteration")

    monkeypatch.setattr("vulnops.workers.intel_refresh.time.sleep", unexpected_sleep)

    worker.run_forever(max_iterations=1)
