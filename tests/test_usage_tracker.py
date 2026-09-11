import datetime as dt
import quota_manager.sql_management as sqlm


def test_daily_events_runs_expected_calls(db_paths, monkeypatch):
    usage_db, _ = db_paths

    # set up a logged in user
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)
    sqlm.login_user_usage("bob", "aa:bb", "10.0.0.2", db_path=usage_db)

    import quota_manager.usage_tracker as ut
    import quota_manager.quota_management as qm

    called = {
        "usage_dw": 0,
        "logout_all": 0,
        "wipe_ip": 0,
        "reset": 0,
        "calculate_hyp": 0,
        "applyq": 0,
    }
    monkeypatch.setattr(
        sqlm,
        "usage_daily_wipe",
        lambda *a, **k: called.__setitem__("usage_dw", called["usage_dw"] + 1),
    )
    monkeypatch.setattr(
        qm,
        "log_out_all_users",
        lambda *a, **k: called.__setitem__("logout_all", called["logout_all"] + 1),
    )
    monkeypatch.setattr(
        qm,
        "wipe_ip_neigh_db",
        lambda *a, **k: called.__setitem__("wipe_ip", called["wipe_ip"] + 1),
    )
    monkeypatch.setattr(
        qm,
        "reset_throttling_and_packet_dropping_all_users",
        lambda *a, **k: called.__setitem__("reset", called["reset"] + 1),
    )
    monkeypatch.setattr(
        qm,
        "calculate_hypothetical_group_quotas_for_today",
        lambda *a, **k: called.__setitem__(
            "calculate_hyp", called["calculate_hyp"] + 1
        ),
    )
    monkeypatch.setattr(
        qm,
        "apply_new_quotas",
        lambda *a, **k: called.__setitem__("applyq", called["applyq"] + 1),
    )

    tz = dt.timezone(dt.timedelta(hours=2))
    now = dt.datetime(2026, 2, 9, 0, 0, tzinfo=tz)

    ut.daily_events(now=now)

    assert called["usage_dw"] == 1
    assert called["logout_all"] == 1
    assert called["wipe_ip"] == 1
    assert called["reset"] == 1
    assert called["calculate_hyp"] == 1
    assert called["applyq"] == 1
