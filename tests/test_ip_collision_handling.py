import sqlite3
import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm


def test_log_in_user_logs_out_other_user_on_same_ip(db_paths, monkeypatch):
    usage_db, _ = db_paths

    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.create_user_usage("alice", "alpha", db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    # Alice already logged in on IP
    with sqlite3.connect(usage_db) as con:
        con.execute(
            "UPDATE users SET logged_in=1, ip_address=?, mac_address=? WHERE username=?",
            ("10.0.0.50", "aa:aa:aa:aa:aa:aa", "alice"),
        )

    # Patch side effects to no-ops
    monkeypatch.setattr(qm, "nft_authorize_user", lambda *a, **k: None)
    monkeypatch.setattr(qm, "initialize_user_state_nftables", lambda *a, **k: None)
    monkeypatch.setattr(qm, "ip_timeout_updater", lambda *a, **k: None)
    monkeypatch.setattr(qm, "initialize_session_start_bytes", lambda *a, **k: 0)

    # Make log_out_user safe
    monkeypatch.setattr(qm, "remove_user_from_nftables", lambda *a, **k: None)
    monkeypatch.setattr(qm, "remove_user_from_ip_timeouts", lambda *a, **k: None)

    # Also bypass day/mac restrictions
    monkeypatch.setattr(
        sqlm,
        "fetch_active_config",
        lambda: {
            "active_days_list": [0, 1, 2, 3, 4, 5, 6],
            "mac_set_limitation": 0,
            "allowed_macs_list": [],
        },
    )

    # Bob logs in from same IP (collision)
    qm.log_in_user("bob", "10.0.0.50", "bb:bb:bb:bb:bb:bb")

    assert sqlm.check_if_user_logged_in("bob", db_path=usage_db) is True
    assert sqlm.check_if_user_logged_in("alice", db_path=usage_db) is False
