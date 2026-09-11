import sqlite3
import quota_manager.sql_management as sqlm
import quota_manager.sqlite_helper_functions as sqlh


def test_init_usage_db_creates_default_config_and_system_state(db_paths):
    usage_db, _ = db_paths

    # config exists
    cfg = sqlm.fetch_active_config(db_path=usage_db)
    assert cfg["name"] == "default"
    assert "active_days_list" in cfg

    # system_state exists
    row = sqlm.fetch_system_state_row(db_path=usage_db)
    assert row is not None
    assert row[0] == cfg["system_name"]


def test_group_create_user_create_membership(db_paths):
    usage_db, _ = db_paths

    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    assert sqlm.check_if_user_exists("bob", db_path=usage_db)
    assert sqlm.check_if_group_exists("alpha", db_path=usage_db)

    grp = sqlm.check_which_group_user_is_in("bob", db_path=usage_db)
    assert grp == "alpha"


def test_delete_user_cascades_group_users(db_paths):
    usage_db, _ = db_paths

    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    sqlm.delete_user_usage("bob", db_path=usage_db)
    assert not sqlm.check_if_user_exists("bob", db_path=usage_db)
    assert sqlm.count_users_in_group("alpha", db_path=usage_db) == 0


def test_delete_group_fails_if_members_exist(db_paths):
    usage_db, _ = db_paths

    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)
    sqlm.create_user_usage("bob", "alpha", db_path=usage_db)

    assert sqlm.count_users_in_group("alpha", db_path=usage_db) == 1


def test_fetch_active_config_parses_days_and_macs(db_paths):
    usage_db, _ = db_paths

    cfg = sqlm.fetch_active_config(db_path=usage_db)
    assert isinstance(cfg["active_days_list"], list)
    assert isinstance(cfg["allowed_macs_list"], list)
