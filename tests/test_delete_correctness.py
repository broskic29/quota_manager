import sqlite3
import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm


def test_delete_user_removes_usage_radius_and_group_users(db_paths, monkeypatch):
    usage_db, radius_db = db_paths

    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.insert_user_radius("bob", "pw", db_path=radius_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    # prevent quota recompute doing heavy work
    monkeypatch.setattr(qm, "update_group_quotas", lambda *a, **k: None)
    monkeypatch.setattr(qm, "remove_user_from_nftables", lambda *a, **k: None)

    qm.delete_user_from_system("bob")

    # usage deleted
    assert not sqlm.check_if_user_exists("bob", db_path=usage_db)

    # radius deleted
    con = sqlite3.connect(radius_db)
    n = con.execute(
        "SELECT COUNT(*) FROM radcheck WHERE username=?", ("bob",)
    ).fetchone()[0]
    con.close()
    assert n == 0

    # group_users deleted (should be automatic via FK cascade)
    con = sqlite3.connect(usage_db)
    m = con.execute(
        """
        SELECT COUNT(*)
        FROM group_users gu
        JOIN users u ON u.id = gu.user_id
        WHERE u.username=?
        """,
        ("bob",),
    ).fetchone()[0]
    con.close()
    assert m == 0


def test_delete_group_empty_leaves_no_orphans(db_paths, monkeypatch):
    usage_db, _ = db_paths

    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)

    monkeypatch.setattr(qm, "update_group_quotas", lambda *a, **k: None)

    qm.delete_group_from_system("alpha")

    # group removed
    assert not sqlm.check_if_group_exists("alpha", db_path=usage_db)

    # group_users has no rows referencing deleted group
    con = sqlite3.connect(usage_db)
    k = con.execute(
        """
        SELECT COUNT(*)
        FROM group_users gu
        JOIN groups g ON g.id = gu.group_id
        WHERE g.group_name=?
        """,
        ("alpha",),
    ).fetchone()[0]
    con.close()
    assert k == 0
