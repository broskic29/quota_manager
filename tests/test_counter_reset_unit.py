import sqlite3

import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm


def test_counter_reset_does_not_decrease_daily_usage_and_resets_baseline(
    db_paths, monkeypatch
):
    usage_db, _ = db_paths

    # Arrange: user exists, is logged in, has prior usage and baseline
    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    with sqlite3.connect(usage_db) as con:
        con.execute(
            """
            UPDATE users
            SET ip_address=?,
                mac_address=?,
                logged_in=1,
                daily_usage_bytes=2000,
                monthly_usage_bytes=5000,
                session_start_bytes=1000,
                session_total_bytes=300
            WHERE username=?
            """,
            ("10.0.0.2", "aa:bb:cc:dd:ee:ff", "bob"),
        )

    # Patch: nft now reports a LOWER counter than our baseline (reset/flush/reload case)
    monkeypatch.setattr(qm.nftm, "get_bytes_from_user", lambda ip: 500)

    # Act: update bytes
    qm.update_user_bytes("bob", usage_dict={}, db_path=usage_db)

    # Assert: daily usage does not decrease, and baseline/session_total reset, delta effectively 0
    with sqlite3.connect(usage_db) as con:
        row = con.execute(
            """
            SELECT daily_usage_bytes, session_start_bytes, session_total_bytes
            FROM users WHERE username=?
            """,
            ("bob",),
        ).fetchone()

    daily_usage, session_start, session_total = row
    assert daily_usage == 2000, "Daily usage must not decrease on counter reset"
    assert session_start == 500, "Baseline must reset to the new (lower) counter"
    assert session_total == 0, "Session total must wipe when baseline resets"
