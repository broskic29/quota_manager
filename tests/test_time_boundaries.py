import sqlite3
import datetime as dt

import quota_manager.sql_management as sqlm
import quota_manager.usage_tracker as ut
import quota_manager.quota_management as qm


def test_day_rollover_resets_daily_not_monthly_and_quota_state_recovers(
    db_paths, monkeypatch
):
    usage_db, _ = db_paths

    # Patch out side effects from daily_events
    monkeypatch.setattr(qm, "log_out_all_users", lambda *a, **k: None)
    monkeypatch.setattr(qm, "wipe_ip_neigh_db", lambda *a, **k: None)
    monkeypatch.setattr(
        qm, "reset_throttling_and_packet_dropping_all_users", lambda *a, **k: None
    )
    monkeypatch.setattr(qm, "update_group_quotas", lambda *a, **k: None)

    # Setup: one user, one group with a quota
    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    sqlm.update_config_usage(
        name="default", total_bytes=500 * 1024**3, db_path=usage_db
    )

    with sqlite3.connect(usage_db) as con:
        con.execute(
            """
            UPDATE users
            SET logged_in=1, daily_usage_bytes=0, monthly_usage_bytes=0, exceeds_quota=0
            WHERE username=?
            """,
            ("bob",),
        )

    # "Traffic before midnight"
    sqlm.update_user_bytes_usage(700, "bob", db_path=usage_db)
    assert sqlm.fetch_daily_bytes_usage("bob", db_path=usage_db) == 700
    assert sqlm.fetch_monthly_bytes_usage("bob", db_path=usage_db) == 700

    group_quotas_dict = qm.calculate_hypothetical_group_quotas_for_today()
    qm.apply_new_quotas(group_quotas_dict)

    calculated_quota = group_quotas_dict["alpha"]

    assert (
        sqlm.fetch_high_speed_quota_for_user_usage("bob", db_path=usage_db)
        == calculated_quota
    )

    # Make user exceed quota before midnight
    with sqlite3.connect(usage_db) as con:
        con.execute(
            "UPDATE users SET daily_usage_bytes=?, exceeds_quota=1 WHERE username=?",
            (2000, "bob"),
        )

    # After midnight, daily wipe should reset daily_usage but not monthly_usage
    tz = dt.timezone(dt.timedelta(hours=2))
    now_after_midnight = dt.datetime(2026, 2, 10, 0, 1, tzinfo=tz)

    ut.daily_events(now=now_after_midnight)

    assert sqlm.fetch_daily_bytes_usage("bob", db_path=usage_db) == 0
    assert (
        sqlm.fetch_monthly_bytes_usage("bob", db_path=usage_db) == 700
    ), "monthly must not wipe on daily event"

    # Simulate user logs back in and quota info is recalculated
    with sqlite3.connect(usage_db) as con:
        con.execute("UPDATE users SET logged_in=1 WHERE username=?", ("bob",))

    exceeds, daily, quota = qm.update_quota_information_single_user(
        "bob", db_path=usage_db
    )

    assert daily == 0
    assert quota == calculated_quota
    if daily >= quota:
        assert exceeds is True
    else:
        assert exceeds is False

    # "Traffic after midnight" should increment daily AND monthly (monthly continues)
    sqlm.update_user_bytes_usage(300, "bob", db_path=usage_db)
    assert sqlm.fetch_daily_bytes_usage("bob", db_path=usage_db) == 300
    assert sqlm.fetch_monthly_bytes_usage("bob", db_path=usage_db) == 1000
