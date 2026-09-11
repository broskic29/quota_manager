import quota_manager.sql_management as sqlm


def test_user_login_success_redirects_to_dashboard(
    user_client, db_paths, freeze_weekday, monkeypatch
):
    usage_db, _ = db_paths

    # setup group + user
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.insert_user_radius(
        "bob", "pw", db_path=None
    )  # uses patched sqlh.RADIUS_DB_PATH
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    # patch qm.log_in_user to avoid nft/iptime stuff; just mark logged in
    import quota_manager.quota_management as qm

    def fake_login(username, user_ip, user_mac):
        sqlm.login_user_usage(username, user_mac, user_ip, db_path=usage_db)
        return True

    monkeypatch.setattr(qm, "log_in_user", fake_login)

    r = user_client.post(
        "/login",
        data={"username": "bob", "password": "pw"},
        environ_base={"REMOTE_ADDR": "192.168.1.50"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    assert "/user/bob/dashboard" in r.headers["Location"]


def test_dashboard_requires_session(user_client, db_paths):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    r = user_client.get("/user/bob/dashboard", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/login" in r.headers["Location"]


def test_login_blocked_on_restricted_day(
    user_client, db_paths, freeze_sunday, monkeypatch
):
    usage_db, _ = db_paths

    # set active days to Mon-Fri only (already default, but be explicit)
    cfg = sqlm.fetch_active_config(db_path=usage_db)
    sqlm.update_config_usage(
        name=cfg["name"],
        system_name=cfg["system_name"],
        total_bytes=cfg["total_monthly_bytes_purchased"],
        throttling_enabled=0,
        active_days="0,1,2,3,4",
        mac_set_limitation=0,
        allowed_macs="",
        active_config=1,
        db_path=usage_db,
    )

    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    # real qm.log_in_user will throw RestrictedDayError
    import quota_manager.flask_tools.flask_utils as flu

    monkeypatch.setattr(flu, "authenticate_radius", lambda *a, **k: True)

    r = user_client.post(
        "/login",
        data={"username": "bob", "password": "pw"},
        environ_base={"REMOTE_ADDR": "192.168.1.50"},
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert b"restricted" in r.data.lower() or b"not allowed" in r.data.lower()
