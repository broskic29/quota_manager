import sqlite3
import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm


def test_compute_remaining_weekdays_does_not_crash_before_reset_day(
    db_paths, monkeypatch
):
    usage_db, _ = db_paths

    tz = qm.dt.timezone(qm.dt.timedelta(hours=2))
    now = qm.dt.datetime(2026, 2, 5, 12, 0, tzinfo=tz)  # before day 7

    # ensure active days are weekdays
    cfg = sqlm.fetch_active_config(db_path=usage_db)
    sqlm.update_config_usage(
        name=cfg["name"],
        system_name=cfg["system_name"],
        total_bytes=cfg["total_monthly_bytes_purchased"],
        throttling_enabled=int(cfg["throttling_enabled"]),
        active_days="0,1,2,3,4",
        mac_set_limitation=0,
        allowed_macs="",
        active_config=1,
        db_path=usage_db,
    )

    n = qm.compute_remaining_weekdays(now, qm.ACCOUNT_BILLING_DAY)
    assert isinstance(n, int)
    assert n >= 1


def test_update_group_quotas_no_users_is_noop(db_paths, monkeypatch):
    usage_db, _ = db_paths

    tz = qm.dt.timezone(qm.dt.timedelta(hours=2))
    now = qm.dt.datetime(2026, 2, 9, 12, 0, tzinfo=tz)

    # no groups / no users created

    # optimizer must not be called in this case
    called = {"opt": 0}
    monkeypatch.setattr(
        qm.sqt,
        "quota_vector_generator",
        lambda *a, **k: called.__setitem__("opt", called["opt"] + 1),
    )

    group_quotas_dict = qm.calculate_hypothetical_group_quotas_for_today(
        now=now, reset_day=qm.ACCOUNT_BILLING_DAY
    )

    qm.apply_new_quotas(group_quotas_dict)

    assert called["opt"] == 0


def test_update_group_quotas_one_group_stable(db_paths, monkeypatch):
    usage_db, _ = db_paths

    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    # make math deterministic
    monkeypatch.setattr(sqlm, "fetch_daily_system_bytes", lambda: 0)
    monkeypatch.setattr(sqlm, "fetch_config_total_bytes", lambda *a, **k: 1024)

    tz = qm.dt.timezone(qm.dt.timedelta(hours=2))
    now = qm.dt.datetime(2026, 2, 9, 12, 0, tzinfo=tz)

    monkeypatch.setattr(qm, "compute_remaining_weekdays", lambda *a, **k: 1)

    # force optimizer output
    monkeypatch.setattr(
        qm.sqt,
        "gen_quota_config_dict",
        lambda total_daily_bytes, group_cfg: {"dummy": True},
    )
    monkeypatch.setattr(
        qm.sqt, "quota_vector_generator", lambda cfg: {"v_dict": {"alpha": 1024}}
    )

    group_quotas_dict = qm.calculate_hypothetical_group_quotas_for_today(
        now=now, reset_day=qm.ACCOUNT_BILLING_DAY
    )

    qm.apply_new_quotas(group_quotas_dict)

    # confirm group quota updated in DB
    con = sqlite3.connect(usage_db)
    q = con.execute(
        "SELECT high_speed_quota FROM groups WHERE group_name=?", ("alpha",)
    ).fetchone()[0]
    con.close()
    assert q == 1024
