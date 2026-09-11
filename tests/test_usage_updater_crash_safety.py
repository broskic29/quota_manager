import threading
import sqlite3

import quota_manager.sql_management as sqlm
import quota_manager.usage_tracker as ut
import quota_manager.quota_management as qm


def test_usage_updater_stops_on_exception_and_keeps_partial_db_writes(
    db_paths, monkeypatch
):
    usage_db, _ = db_paths

    # Two logged-in users
    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.create_user_usage("u1", "alpha", db_path=usage_db)
    sqlm.create_user_usage("u2", "alpha", db_path=usage_db)
    with sqlite3.connect(usage_db) as con:
        con.execute(
            "UPDATE users SET logged_in=1, ip_address='10.0.0.2' WHERE username='u1'"
        )
        con.execute(
            "UPDATE users SET logged_in=1, ip_address='10.0.0.3' WHERE username='u2'"
        )

    # Avoid wipe logic; focus on update loop behavior
    monkeypatch.setattr(qm, "system_daily_wipe_check", lambda *a, **k: True)
    monkeypatch.setattr(qm, "system_monthly_wipe_check", lambda *a, **k: True)

    # First call updates u1, then crashes before u2
    def crashy_update_all_users_bytes():
        sqlm.update_user_bytes_usage(123, "u1", db_path=usage_db)
        raise RuntimeError("boom")

    monkeypatch.setattr(qm, "update_all_users_bytes", crashy_update_all_users_bytes)

    # Skip downstream stages
    monkeypatch.setattr(qm, "update_quota_information_all_users", lambda *a, **k: {})
    monkeypatch.setattr(qm, "enforce_quotas_all_users", lambda *a, **k: None)

    monkeypatch.setattr(ut, "USAGE_UPDATE_INTERVAL", 0)

    stop_event = threading.Event()
    ut.usage_updater(stop_event)

    assert stop_event.is_set(), "Stop event must be set on crash"

    # Partial write should remain committed
    assert sqlm.fetch_daily_bytes_usage("u1", db_path=usage_db) == 123
