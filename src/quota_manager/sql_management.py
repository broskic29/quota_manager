import sqlite3
from datetime import datetime, timezone, timedelta

from pathlib import Path
import subprocess

import quota_manager.sqlite_helper_functions as sqlh
import quota_manager.nftables_management as nftm


DEFAULT_DB_PATH = "/var/lib/radius/freeradius.db"
USAGE_DB_PATH = "/var/lib/radius/usage.db"
DEFAULT_SCHEMA_PATH = "/etc/freeradius3/mods-config/sql/main/sqlite/schema.sql"


# --- Database setup ---
def init_freeradius_db():
    p = Path(DEFAULT_DB_PATH)

    if not p.exists():
        with open(DEFAULT_DB_PATH, "a") as f:
            pass

    if not sqlh.check_if_table_exists("radcheck"):
        with open(DEFAULT_SCHEMA_PATH, "r") as f:
            subprocess.run(["sqlite3", DEFAULT_DB_PATH], stdin=f, check=True)


# --- Database setup ---
def init_usage_db():
    con = sqlite3.connect(USAGE_DB_PATH)
    cur = con.cursor()

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        mac_address TEXT NOT NULL,
        ip_address TEXT,
        daily_usage_bytes INTEGER NOT NULL DEFAULT 0,
        monthly_usage_bytes INTEGER NOT NULL DEFAULT 0,
        session_total_bytes INTEGER NOT NULL DEFAULT 0,
        UNIQUE(username)
    );
    """
    )

    con.commit()
    con.close()


def insert_user_radius(
    username,
    password,
    db_path="/var/lib/radius/freeradius.db",
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO radcheck (username, attribute, op, value)
    VALUES (?, ?, ?, ?)
    """,
        (f"{username}", "Cleartext-Password", ":=", f"{password}"),
    )

    user_id = cur.lastrowid
    try:
        return (
            flask.jsonify(
                {
                    "status": "success",
                    "message": f"User {username} with user_id {user_id} created.",
                }
            ),
            201,
        )
    finally:
        con.commit()
        con.close()


def modify_username_radius(
    old_username,
    new_username,
    db_path="/var/lib/radius/freeradius.db",
):
    con = sqlite3.connect(db_path)
    cursor = con.cursor()

    query = f"""
        UPDATE radcheck
        SET username = ?
        WHERE username = ?;
    """

    cursor.execute(query, (new_username, old_username))

    try:
        return (
            flask.jsonify(
                {
                    "status": "success",
                    "message": f"User {old_username} changed name to {new_username}.",
                }
            ),
            200,
        )
    finally:
        con.commit()
        con.close()


def modify_user_password_radius(
    username,
    password,
    db_path="/var/lib/radius/freeradius.db",
):
    con = sqlite3.connect(db_path)
    cursor = con.cursor()

    query = f"""
        UPDATE radcheck
        SET value = ?
        WHERE username = ?;
    """

    cursor.execute(query, (password, username))

    try:
        return (
            flask.jsonify(
                {
                    "status": "success",
                    "message": f"User {username} password updated.",
                }
            ),
            200,
        )
    finally:
        con.commit()
        con.close()


def delete_user_radius(
    username,
    db_path="/var/lib/radius/freeradius.db",
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    # Delete from authentication table
    cur.execute("DELETE FROM radcheck WHERE username = ?", (username,))
    # Delete from reply table
    cur.execute("DELETE FROM radreply WHERE username = ?", (username,))
    # Delete from user groups
    cur.execute("DELETE FROM radusergroup WHERE username = ?", (username,))
    # Optional: delete accounting records
    cur.execute("DELETE FROM radacct WHERE username = ?", (username,))
    con.commit()
    con.close()
    print(f"User '{username}' deleted successfully.")


def update_radius_field(
    username, password, table, field, value, db_path="/var/lib/radius/freeradius.db"
):
    con = sqlite3.connect(db_path)
    cursor = con.cursor()

    query = f"""
        UPDATE {table}
        SET  = ?
        WHERE username = ? AND password = ?;
    """

    cursor.execute(query, (value, username, password))
    con.commit()
    con.close()


def insert_user_usage(
    username,
    mac_address,
    ip_address,
    db_path="/var/lib/radius/usage.db",
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO usage (username, mac_address, ip_address, daily_usage_bytes, monthly_usage_bytes, session_total_bytes)
    VALUES (?, ?, ?, ?, ?, ?)
    """,
        (f"{username}", f"{mac_address}", f"{ip_address}", 0, 0, 0),
    )

    user_id = cur.lastrowid

    try:
        return (
            flask.jsonify(
                {
                    "status": "success",
                    "message": f"User {username} with user_id {user_id} created.",
                }
            ),
            201,
        )
    finally:
        con.commit()
        con.close()


def login_user_usage(
    username,
    mac_address,
    ip_address,
    db_path="/var/lib/radius/usage.db",
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        SELECT *
        FROM usage
        WHERE username = ?
        """,
        (username,),
    )
    row = cur.fetchone()

    if row:
        columns = [
            column
            for column in sqlh.fetch_all_columns(db_path, "usage")
            if column != "username"
        ]
        set_clause = ", ".join(f"{col} = ?" for col in columns)
        values = [mac_address, ip_address, 0, 0, 0]

        cur.execute(
            f"""
            UPDATE usage
            SET {set_clause}
            WHERE username = ?
            """,
            values + [username],
        )

        try:
            return (
                flask.jsonify(
                    {
                        "status": "success",
                        "message": f"User {username} updated.",
                    }
                ),
                200,
            )
        finally:
            con.commit()
            con.close()

    con.close()

    insert_user_usage(username, mac_address, ip_address, db_path)


def delete_user_usage(
    username,
    db_path="/var/lib/radius/usage.db",
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    # Delete from authentication table
    cur.execute("DELETE FROM usage WHERE username = ?", (username,))
    con.commit()
    con.close()
    print(f"User '{username}' deleted successfully.")


def update_usage_field(username, field, value, db_path="/var/lib/radius/usage.db"):
    con = sqlite3.connect(db_path)
    cursor = con.cursor()

    query = f"""
        UPDATE usage
        SET {field} = ?
        WHERE username = ?;
    """

    cursor.execute(query, (value, username))
    con.commit()
    con.close()


def fetch_usage_user_mac_address(username, db_path="/var/lib/radius/usage.db"):
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    cur.execute(
        """
        SELECT mac_address
        FROM usage
        WHERE username = ?
        """,
        (username,),
    )
    return cur.fetchone()[0]


def fetch_radius_usage_for_user(username, db_path="/var/lib/radius/usage.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE username = ?
        GROUP BY username
        """,
        (username,),
    )
    rows = cur.fetchall()
    usage_dict = {username: total_bytes / 1024 / 1024 for username, total_bytes in rows}
    con.commit()
    con.close()
    return usage_dict


def fetch_radius_usage_all_users(db_path="/var/lib/radius/freeradius.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        GROUP BY username
        """,
    )
    rows = cur.fetchall()
    usage_dict = {username: total_bytes / 1024 / 1024 for username, total_bytes in rows}
    con.commit()
    con.close()
    return usage_dict


def usage_update(db_path="/var/lib/radius/usage.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    usage_dict = fetch_radius_usage_all_users()

    for username, byte_count in usage_dict.items():

        cur.execute(
            """
            UPDATE usage
            SET daily_total_bytes = daily_total_bytes + (? - session_total_bytes),
                monthly_total_bytes = monthly_total_bytes + (? - session_total_bytes),
                session_total_bytes = ?
            WHERE username = ?
            """,
            (
                byte_count,
                byte_count,
                byte_count,
                username,
            ),
        )

    con.commit()
    con.close()


def usage_daily_wipe(db_path="/var/lib/radius/usage.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        UPDATE usage
        SET daily_total_bytes = 0
        """,
    )
    con.commit()
    con.close()


def usage_monthly_wipe(db_path="/var/lib/radius/usage.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        UPDATE usage
        SET monthly_total_bytes = 0
        """,
    )
    con.commit()
    con.close()


def fetch_daily_usage(username, db_path="/var/lib/radius/usage.db"):
    con = sqlite3.connect(db_path)  # Connects to database

    # Need to add try blocks and error catching for all of these things at some point.
    try:
        cur = con.cursor()

        cur.execute(
            """
            SELECT daily_total_bytes
            FROM radacct
            WHERE username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return row[0]
    finally:
        con.close()


def check_if_daily_usage_exceeds_quota_for_user(
    username, quota, db_path="/var/lib/radius/usage.db"
):
    usage_bytes = fetch_daily_usage(username, db_path)

    if usage_bytes >= quota:
        return True
    else:
        return False


def print_all_radius_user_information(db_path="/var/lib/radius/freeradius.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    res = cur.execute("SELECT username, attribute, value FROM radcheck;")
    rows = res.fetchall()
    for row in rows:
        print(row)


def print_all_radius_accounting_information(db_path="/var/lib/radius/freeradius.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    res = cur.execute("SELECT username, attribute, value FROM radacct;")
    rows = res.fetchall()
    for row in rows:
        print(row)


def print_all_usage_user_information(db_path="/var/lib/radius/usage.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    res = cur.execute("SELECT * FROM usage;")
    rows = res.fetchall()
    for row in rows:
        print(row)
