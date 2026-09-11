import sqlite3
import datetime as dt

import quota_manager.sql_management as sqlm
import quota_manager.usage_tracker as ut


def test_monthly_events_resets_monthly_and_clears_temporary_quota(db_paths):
    usage_db, _ = db_paths

    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    with sqlite3.connect(usage_db) as con:
        con.execute(
            """
            UPDATE users
            SET daily_usage_bytes = 111,
                monthly_usage_bytes = 222
            WHERE username = 'bob'
            """
        )

    tz = dt.timezone(dt.timedelta(hours=2))
    now = dt.datetime(2026, 3, 7, 0, 1, tzinfo=tz)  # billing day example
    ut.monthly_events()

    with sqlite3.connect(usage_db) as con:
        row = con.execute(
            "SELECT daily_usage_bytes, monthly_usage_bytes FROM users WHERE username='bob'"
        ).fetchone()

    daily, monthly = row
    assert daily == 111, "Monthly wipe should not touch daily usage"
    assert monthly == 0
