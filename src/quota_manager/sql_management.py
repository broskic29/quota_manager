import sqlite3

from pathlib import Path
import subprocess

import flask

import quota_manager.sqlite_helper_functions as sqlh


# --- Database setup ---
def init_freeradius_db():
    p = Path(sqlh.RADIUS_DB_PATH)

    if not p.exists():
        print("Path doesn't exist!")
        with open(sqlh.RADIUS_DB_PATH, "a") as f:
            pass

    if not sqlh.check_if_table_exists("radcheck"):
        print("Table doesn't exist!")
        with open(sqlh.DEFAULT_SCHEMA_PATH, "r") as f:
            subprocess.run(["sqlite3", sqlh.RADIUS_DB_PATH], stdin=f, check=True)


# --- Database setup ---
def init_usage_db():
    con = sqlite3.connect(sqlh.USAGE_TRACKING_DB_PATH)
    cur = con.cursor()

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        mac_address TEXT NOT NULL,
        ip_address TEXT,
        daily_usage_bytes INTEGER NOT NULL DEFAULT 0,
        monthly_usage_bytes INTEGER NOT NULL DEFAULT 0,
        session_total_bytes INTEGER NOT NULL DEFAULT 0,
        all_time_bytes INTEGER NOT NULL DEFAULT 0,
        UNIQUE(username)
    );
    """
    )

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_name TEXT NOT NULL,
        high_speed_quota INTEGER NOT NULL DEFAULT 0,
        throttled_quota INTEGER NOT NULL DEFAULT 0,
        UNIQUE(group_name)
    );
    """
    )

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS group_users (
        group_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,

        PRIMARY KEY (group_id, user_id),

        FOREIGN KEY (group_id) REFERENCES groups(id)
            ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE,

        UNIQUE(user_id)
    );
    """
    )

    con.commit()
    con.close()


def insert_user_radius(
    username,
    password,
    db_path=sqlh.RADIUS_DB_PATH,
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO radcheck (username, attribute, op, value)
    VALUES (?, ?, ?, ?)
    """,
        (
            f"{username}",
            "Cleartext-Password",
            ":=",
            f"{password}",
        ),
    )
    user_id = cur.lastrowid
    con.commit()
    con.close()

    # The below is not working outside of a flask context.
    # This function should be usable outside of flask.
    # try:
    #     return (
    #         flask.jsonify(
    #             {
    #                 "status": "success",
    #                 "message": f"User {username} with user_id {user_id} created.",
    #             }
    #         ),
    #         201,
    #     )
    # finally:
    #     con.commit()
    #     con.close()


def modify_username_radius(
    old_username,
    new_username,
    db_path=sqlh.RADIUS_DB_PATH,
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
    db_path=sqlh.RADIUS_DB_PATH,
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
    db_path=sqlh.RADIUS_DB_PATH,
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


def insert_user_usage(
    username,
    mac_address,
    ip_address,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO users (username, mac_address, ip_address, daily_usage_bytes, monthly_usage_bytes, session_total_bytes)
    VALUES (?, ?, ?, ?, ?, ?)
    """,
        (f"{username}", f"{mac_address}", f"{ip_address}", 0, 0, 0),
    )
    user_id = cur.lastrowid
    # try:
    #     return (
    #         flask.jsonify(
    #             {
    #                 "status": "success",
    #                 "message": f"User {username} with user_id {user_id} created.",
    #             }
    #         ),
    #         201,
    #     )
    # finally:
    con.commit()
    con.close()


def create_group_usage(
    group_name,
    high_speed_quota,
    throttled_quota,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO groups (group_name, high_speed_quota, throttled_quota)
    VALUES (?, ?, ?)
    """,
        (group_name, high_speed_quota, throttled_quota),
    )
    group_id = cur.lastrowid
    # try:
    #     return (
    #         flask.jsonify(
    #             {
    #                 "status": "success",
    #                 "message": f"User {username} with user_id {user_id} created.",
    #             }
    #         ),
    #         201,
    #     )
    # finally:
    #     con.commit()
    #     con.close()
    con.commit()
    con.close()


def insert_user_into_group_usage(
    group_name,
    username,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")
    cur.execute(
        """
    DELETE FROM group_users
    WHERE user_id = (
        SELECT id FROM users WHERE username = ?
        )
    """,
        (username,),
    )
    cur.execute(
        """
    INSERT OR IGNORE INTO group_users (group_id, user_id)
    SELECT g.id, u.id
    FROM groups g
    JOIN users u ON u.username = ?
    WHERE g.group_name = ?
    """,
        (username, group_name),
    )
    con.commit()
    con.close()


def login_user_usage(
    username,
    mac_address,
    ip_address,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    con = sqlite3.connect(db_path)  # Connects to database

    cur = con.cursor()
    cur.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,),
    )
    row = cur.fetchone()

    # This should update the user if it already exists,
    # otherwise, create new user.

    # Need to make daily bytes and whatnot carry over...
    if row:
        columns = [column for column in sqlh.fetch_all_columns(db_path, "users")]
        set_clause = ", ".join(f"{col} = ?" for col in columns)
        values = list(row)
        values[2] = mac_address
        values[3] = ip_address

        cur.execute(
            f"""
            UPDATE users
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
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    # Delete from authentication table
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    con.commit()
    con.close()
    print(f"User '{username}' deleted successfully.")


def fetch_user_mac_address_usage(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    cur.execute(
        """
        SELECT mac_address
        FROM users
        WHERE username = ?
        """,
        (username,),
    )
    res = cur.fetchone()
    if res is None:
        print(f"No mac_address can be found for user: {username}")
        return res
    return cur.fetchone()[0]


def fetch_all_usernames_usage(db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        """
        SELECT username
        FROM users
        """,
    )
    return [entry[0] for entry in cur.fetchall()]


def update_user_bytes_usage(
    user_bytes, username, mac_reset=False, db_path=sqlh.USAGE_TRACKING_DB_PATH
):

    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    session_bytes = user_bytes if not mac_reset else 0

    cur.execute(
        """
        UPDATE users
        SET daily_usage_bytes = daily_usage_bytes + (? - session_total_bytes),
            monthly_usage_bytes = monthly_usage_bytes + (? - session_total_bytes),
            session_total_bytes = ?
        WHERE username = ?
        """,
        (
            user_bytes,
            user_bytes,
            session_bytes,
            username,
        ),
    )

    con.commit()
    con.close()


def usage_daily_wipe(db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        UPDATE users
        SET daily_usage_bytes = 0
        """,
    )
    con.commit()
    con.close()


def usage_monthly_wipe(db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        UPDATE users
        SET monthly_total_bytes = 0
        """,
    )
    con.commit()
    con.close()


def fetch_daily_bytes_usage(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(db_path)  # Connects to database
    # Need to add try blocks and error catching for all of these things at some point.
    try:
        cur = con.cursor()
        cur.execute(
            """
            SELECT daily_usage_bytes
            FROM users
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


def fetch_high_speed_quota_for_user_usage(
    username, db_path=sqlh.USAGE_TRACKING_DB_PATH
):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()

    cur.execute("PRAGMA foreign_keys = ON;")

    cur.execute("BEGIN;")

    cur.execute(
        """
    SELECT g.high_speed_quota
    FROM users u
    JOIN group_users gu ON u.id = gu.user_id
    JOIN groups g ON g.id = gu.group_id
    WHERE u.username = ?
    """,
        (username,),
    )

    quota_bytes = cur.fetchone()

    con.commit()
    con.close()

    if quota_bytes is not None:
        return quota_bytes[0]
    else:
        return None


def check_if_daily_bytes_exceeds_high_speed_quota_for_user_usage(
    username, db_path=sqlh.USAGE_TRACKING_DB_PATH
):
    quota_bytes = fetch_high_speed_quota_for_user_usage(username, db_path)

    usage_bytes = fetch_daily_bytes_usage(username, db_path)

    if usage_bytes >= quota_bytes:
        return True
    else:
        return False
