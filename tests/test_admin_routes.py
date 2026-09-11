import quota_manager.sql_management as sqlm


def test_admin_requires_auth(admin_client):
    r = admin_client.get("/admin")
    assert r.status_code == 401


def test_admin_create_group_accepts_decimal(admin_client, admin_auth_header, db_paths):
    usage_db, _ = db_paths

    r = admin_client.post(
        "/admin/new_group",
        data={"group_name": "alpha", "desired_quota_ratio": "0.33"},
        headers=admin_auth_header,
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert sqlm.check_if_group_exists("alpha", db_path=usage_db)


def test_admin_update_group_ratio(
    admin_client, admin_auth_header, db_paths, monkeypatch
):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)

    # ensure recompute is attempted but doesn't run real optimizer
    import quota_manager.quota_management as qm

    called = {"ok": False}
    monkeypatch.setattr(
        sqlm,
        "update_group_desired_quota_ratio",
        lambda *a, **k: called.__setitem__("ok", True),
    )

    r = admin_client.post(
        "/admin/groups/alpha/ratio",
        data={"desired_quota_ratio": "0.25"},
        headers=admin_auth_header,
        follow_redirects=False,
    )
    assert r.status_code == 200

    row = sqlm.select_group_row("alpha", db_path=usage_db)
    assert float(row[4]) == 0.25  # desired_quota_ratio column in groups table
    assert called["ok"] is True


def test_admin_delete_group_blocked_if_has_users(
    admin_client, admin_auth_header, db_paths
):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    r = admin_client.post("/admin/groups/alpha/delete", headers=admin_auth_header)
    assert r.status_code == 200
    assert sqlm.check_if_group_exists("alpha", db_path=usage_db)


def test_admin_delete_group_succeeds_if_empty(
    admin_client, admin_auth_header, db_paths, monkeypatch
):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)

    import quota_manager.quota_management as qm

    monkeypatch.setattr(qm, "update_group_quotas", lambda *a, **k: None)

    r = admin_client.post("/admin/groups/alpha/delete", headers=admin_auth_header)
    assert r.status_code == 200
    assert not sqlm.check_if_group_exists("alpha", db_path=usage_db)
