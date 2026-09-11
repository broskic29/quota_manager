import sqlite3
import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm


def test_update_user_bytes_multiple_ticks_does_not_double_count(db_paths, monkeypatch):
    usage_db, _ = db_paths

    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    with sqlite3.connect(usage_db) as con:
        con.execute(
            """
            UPDATE users
            SET ip_address=?, mac_address=?, logged_in=1,
                daily_usage_bytes=0, monthly_usage_bytes=0,
                session_start_bytes=1000, session_total_bytes=0
            WHERE username=?
            """,
            ("10.0.0.2", "aa:bb:cc:dd:ee:ff", "bob"),
        )

    # First tick: counter goes from 1000 -> 2500 => +1500
    monkeypatch.setattr(qm.nftm, "get_bytes_from_user", lambda ip: 2500)
    usage_dict = {}
    qm.update_user_bytes("bob", usage_dict=usage_dict, db_path=usage_db)

    assert sqlm.fetch_daily_bytes_usage("bob", db_path=usage_db) == 1500

    # Second tick: counter unchanged => +0
    monkeypatch.setattr(qm.nftm, "get_bytes_from_user", lambda ip: 2500)
    qm.update_user_bytes("bob", usage_dict=usage_dict, db_path=usage_db)

    assert sqlm.fetch_daily_bytes_usage("bob", db_path=usage_db) == 1500
