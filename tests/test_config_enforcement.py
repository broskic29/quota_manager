import quota_manager.sql_management as sqlm


def test_mac_set_limitation_blocks_login_when_mac_not_allowed(
    user_client, db_paths, freeze_weekday, monkeypatch
):
    usage_db, _ = db_paths

    # config: mac limitation ON, only one MAC allowed
    cfg = sqlm.fetch_active_config(db_path=usage_db)
    sqlm.update_config_usage(
        name=cfg["name"],
        system_name=cfg["system_name"],
        total_bytes=cfg["total_monthly_bytes_purchased"],
        throttling_enabled=int(cfg["throttling_enabled"]),
        active_days="0,1,2,3,4",
        mac_set_limitation=1,
        allowed_macs="11:22:33:44:55:66",
        active_config=1,
        db_path=usage_db,
    )

    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.insert_user_radius("bob", "pw")  # uses patched RADIUS_DB_PATH via fixture
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    # device MAC returned by ip->mac is NOT allowed
    import quota_manager.quota_management as qm

    monkeypatch.setattr(qm, "mac_from_ip", lambda ip: "aa:bb:cc:dd:ee:ff")

    r = user_client.post(
        "/login",
        data={"username": "bob", "password": "pw"},
        environ_base={"REMOTE_ADDR": "192.168.1.50"},
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert b"device" in r.data.lower() or b"not allowed" in r.data.lower()


def test_active_days_blocks_login_on_weekend(
    user_client, db_paths, freeze_sunday, monkeypatch
):
    usage_db, _ = db_paths

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

    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)
    sqlm.insert_user_radius("bob", "pw")
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    import quota_manager.quota_management as qm

    monkeypatch.setattr(qm, "mac_from_ip", lambda ip: "aa:bb:cc:dd:ee:ff")

    r = user_client.post(
        "/login",
        data={"username": "bob", "password": "pw"},
        environ_base={"REMOTE_ADDR": "192.168.1.50"},
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert b"restricted" in r.data.lower() or b"not allowed" in r.data.lower()
