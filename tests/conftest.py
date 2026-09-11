import base64
import sqlite3
import datetime as dt
import pytest

import quota_manager.sqlite_helper_functions as sqlh
import quota_manager.sql_management as sqlm


@pytest.fixture()
def db_paths(tmp_path, monkeypatch):
    usage_db = tmp_path / "usage_tracking.db"
    radius_db = tmp_path / "freeradius.db"

    # Patch runtime constants
    monkeypatch.setattr(sqlh, "USAGE_TRACKING_DB_PATH", str(usage_db))
    monkeypatch.setattr(sqlh, "RADIUS_DB_PATH", str(radius_db))

    # Init usage DB using your normal initializer
    sqlm.init_usage_db()

    # Minimal RADIUS schema for tests (so delete_user_radius etc won't crash)
    con = sqlite3.connect(str(radius_db))
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS radcheck (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            attribute TEXT,
            op TEXT,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS radreply (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            attribute TEXT,
            op TEXT,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS radusergroup (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            groupname TEXT,
            priority INTEGER
        );
        CREATE TABLE IF NOT EXISTS radacct (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT
        );
        """
    )
    con.commit()
    con.close()

    return str(usage_db), str(radius_db)


@pytest.fixture()
def admin_auth_header():
    token = base64.b64encode(b"admin:donbosco1815").decode("ascii")
    return {"Authorization": f"Basic {token}"}


@pytest.fixture()
def patch_external_side_effects(monkeypatch):
    """
    Make quota_management safe: no real nftables, no ip-neigh, no quota optimizer.
    """
    import quota_manager.quota_management as qm

    # nftables side-effects
    monkeypatch.setattr(qm, "nft_authorize_user", lambda *a, **k: None)
    monkeypatch.setattr(qm, "initialize_user_state_nftables", lambda *a, **k: None)
    monkeypatch.setattr(qm, "remove_user_from_nftables", lambda *a, **k: None)
    monkeypatch.setattr(qm, "remove_user_from_ip_timeouts", lambda *a, **k: None)
    monkeypatch.setattr(qm, "ip_timeout_updater", lambda *a, **k: None)

    monkeypatch.setattr(qm, "nft_authorize_user", lambda *a, **k: None)
    monkeypatch.setattr(qm, "initialize_session_start_bytes", lambda *a, **k: 0)

    # avoid running the optimizer in tests unless explicitly testing it
    monkeypatch.setattr(qm, "update_group_quotas", lambda *a, **k: None)
    monkeypatch.setattr(qm, "apply_new_quotas", lambda *a, **k: None)

    # Prevent update_user_bytes/login from touching real nft counters/sets
    monkeypatch.setattr(qm.nftm, "get_bytes_from_user", lambda *a, **k: 0)

    return True


@pytest.fixture()
def admin_client(db_paths, patch_external_side_effects):
    from quota_manager.flask_tools.admin_management_flask_server import (
        admin_management_app,
    )

    admin_management_app.config.update(TESTING=True)
    return admin_management_app.test_client()


@pytest.fixture()
def user_client(db_paths, patch_external_side_effects, monkeypatch):
    from quota_manager.flask_tools.user_login_flask_server import user_app
    import quota_manager.flask_tools.flask_utils as flu
    import quota_manager.quota_management as qm

    user_app.config.update(TESTING=True)

    # bypass radius auth + mac lookup
    monkeypatch.setattr(flu, "authenticate_radius", lambda *a, **k: True)
    monkeypatch.setattr(qm, "mac_from_ip", lambda ip: "aa:bb:cc:dd:ee:ff")

    return user_app.test_client()


@pytest.fixture()
def freeze_weekday(monkeypatch):
    """
    Force quota_management.dt.datetime.now(...) to a Monday.
    """
    import quota_manager.quota_management as qm

    class FakeDateTime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            # 2026-02-09 is a Monday
            base = dt.datetime(2026, 2, 9, 12, 0, 0)
            return base.replace(tzinfo=tz) if tz else base

    monkeypatch.setattr(qm.dt, "datetime", FakeDateTime)
    return True


@pytest.fixture()
def freeze_sunday(monkeypatch):
    """
    Force quota_management.dt.datetime.now(...) to a Sunday.
    """
    import quota_manager.quota_management as qm

    class FakeDateTime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            # 2026-02-08 is a Sunday
            base = dt.datetime(2026, 2, 8, 12, 0, 0)
            return base.replace(tzinfo=tz) if tz else base

    monkeypatch.setattr(qm.dt, "datetime", FakeDateTime)
    return True
