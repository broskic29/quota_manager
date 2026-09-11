import sqlite3
import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm


def test_logged_out_user_does_not_accrue_bytes(db_paths, monkeypatch):
    usage_db, _ = db_paths

    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    with sqlite3.connect(usage_db) as con:
        con.execute(
            """
            UPDATE users
            SET ip_address=?, mac_address=?, logged_in=0,
                daily_usage_bytes=123, monthly_usage_bytes=456,
                session_start_bytes=1000, session_total_bytes=0
            WHERE username=?
            """,
            ("10.0.0.2", "aa:bb:cc:dd:ee:ff", "bob"),
        )

    monkeypatch.setattr(qm.nftm, "get_bytes_from_user", lambda ip: 999999)

    usage_dict = {}
    qm.update_user_bytes("bob", usage_dict=usage_dict, db_path=usage_db)

    assert sqlm.fetch_daily_bytes_usage("bob", db_path=usage_db) == 123
    assert sqlm.fetch_monthly_bytes_usage("bob", db_path=usage_db) == 456
