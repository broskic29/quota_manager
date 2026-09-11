import quota_manager.usage_tracker as ut
import quota_manager.quota_management as qm


def test_usage_updater_sets_stop_event_on_exception(monkeypatch):
    import threading

    stop_event = threading.Event()

    # skip wipe checks (avoid hitting DB in this test)
    monkeypatch.setattr(qm, "system_daily_wipe_check", lambda *a, **k: True)
    monkeypatch.setattr(qm, "system_monthly_wipe_check", lambda *a, **k: True)

    # trigger the crash
    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(qm, "update_all_users_bytes", boom)

    # run fast (no waiting)
    monkeypatch.setattr(ut, "USAGE_UPDATE_INTERVAL", 0)

    ut.usage_updater(stop_event)

    assert stop_event.is_set()
