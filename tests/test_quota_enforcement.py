import quota_manager.sql_management as sqlm


def test_update_user_bytes_applies_delta(db_paths, monkeypatch):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    # mark logged in and set counters
    sqlm.login_user_usage("bob", "aa:bb", "10.0.0.2", db_path=usage_db)
    sqlm.update_session_start_bytes(1000, username="bob", db_path=usage_db)

    # patch fetch_user_bytes to return 2500 -> delta = (2500-1000)-0 = 1500
    import quota_manager.quota_management as qm

    monkeypatch.setattr(qm, "fetch_user_bytes", lambda username: 2500)

    qm.update_user_bytes("bob", usage_dict={}, db_path=usage_db)

    assert sqlm.fetch_daily_bytes_usage("bob", db_path=usage_db) == 1500


def test_enforce_quota_throttle_when_enabled(db_paths, monkeypatch):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)
    sqlm.login_user_usage("bob", "aa:bb", "10.0.0.2", db_path=usage_db)

    # user exceeds quota flag in DB
    sqlm.update_user_quota_information("bob", True, db_path=usage_db)

    import quota_manager.quota_management as qm

    monkeypatch.setattr(qm.nftm, "check_if_user_throttled", lambda ip: False)
    monkeypatch.setattr(qm.nftm, "check_if_user_dropped", lambda ip: False)

    called = {"throttle": 0}
    monkeypatch.setattr(
        qm,
        "throttle_single_user",
        lambda *a, **k: called.__setitem__("throttle", called["throttle"] + 1),
    )

    qm.enforce_quota_single_user("bob", throttling=True, db_path=usage_db)
    assert called["throttle"] == 1


def test_enforce_quota_drop_when_throttling_disabled(db_paths, monkeypatch):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)
    sqlm.login_user_usage("bob", "aa:bb", "10.0.0.2", db_path=usage_db)
    sqlm.update_user_quota_information("bob", True, db_path=usage_db)

    import quota_manager.quota_management as qm

    monkeypatch.setattr(qm.nftm, "check_if_user_throttled", lambda ip: False)
    monkeypatch.setattr(qm.nftm, "check_if_user_dropped", lambda ip: False)

    called = {"drop": 0}
    monkeypatch.setattr(
        qm,
        "drop_single_user",
        lambda *a, **k: called.__setitem__("drop", called["drop"] + 1),
    )

    qm.enforce_quota_single_user("bob", throttling=False, db_path=usage_db)
    assert called["drop"] == 1


def test_enforce_quota_resets_when_under_quota(db_paths, monkeypatch):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)
    sqlm.login_user_usage("bob", "aa:bb", "10.0.0.2", db_path=usage_db)
    sqlm.update_user_quota_information("bob", False, db_path=usage_db)

    import quota_manager.quota_management as qm

    monkeypatch.setattr(qm.nftm, "check_if_user_throttled", lambda ip: True)
    monkeypatch.setattr(qm.nftm, "check_if_user_dropped", lambda ip: False)

    called = {"reset": 0}
    monkeypatch.setattr(
        qm,
        "reset_throttling_single_user",
        lambda *a, **k: called.__setitem__("reset", called["reset"] + 1),
    )

    qm.enforce_quota_single_user("bob", throttling=True, db_path=usage_db)
    assert called["reset"] == 1
