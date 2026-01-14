import sqlite3
import logging

RADIUS_DB_PATH = "/overlay/freeradius3/freeradius.db"
USAGE_TRACKING_DB_PATH = "/overlay/freeradius3/usage_tracking.db"
DEFAULT_SCHEMA_PATH = "/etc/freeradius3/mods-config/sql/main/sqlite/schema.sql"

UTC_OFFSET = 2

log = logging.getLogger(__name__)


class MACAddressError(Exception):
    """Raised when a user does not exist."""

    pass


def check_if_table_exists(table_name, db_path=RADIUS_DB_PATH):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,)
    )
    return bool(cur.fetchone())


def delete_table(table_name, db_path):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()

    cur.execute(f"DROP TABLE IF EXISTS {table_name};")

    con.commit()
    con.close()


def wipe_table(table_name, db_path):

    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()

    cur.execute(f"DELETE FROM {table_name};")
    cur.execute(f"DELETE FROM sqlite_sequence WHERE name='{table_name}';")

    con.commit()
    con.close()


def fetch_all_tables(db_path):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    res = cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    return res.fetchall()


def fetch_all_columns(table, db_path):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    res = cur.execute(f"PRAGMA table_info({table});")
    columns = res.fetchall()
    columns = [column[1] for column in columns]
    return columns


def update_field(username, password, table, field, value, db_path):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cursor = con.cursor()

    query = f"""
        UPDATE {table}
        SET {field} = ?
        WHERE username = ? AND password = ?;
    """

    cursor.execute(query, (value, username, password))
    con.commit()
    con.close()


def check_if_table_empty(table, db_path):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(f"SELECT * FROM {table};")
    res = cur.fetchall()
    con.close()
    if len(res) < 1:
        return True
    return False


def log_all_table_information(table, db_path=USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    res = cur.execute(f"SELECT * FROM {table};")
    rows = res.fetchall()
    for row in rows:
        log.debug(row)


def log_all_radius_user_information(db_path=RADIUS_DB_PATH):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    res = cur.execute("SELECT username, attribute, value FROM radcheck;")
    rows = res.fetchall()
    for row in rows:
        log.debug(row)


def print_all_radius_user_information(db_path=RADIUS_DB_PATH):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    res = cur.execute("SELECT username, attribute, value FROM radcheck;")
    rows = res.fetchall()
    for row in rows:
        print(row)


def print_all_table_information(table, db_path=USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    res = cur.execute(f"SELECT * FROM {table};")
    rows = res.fetchall()
    for row in rows:
        print(row)
