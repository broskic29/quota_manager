import sqlite3
import logging

from pathlib import Path
import subprocess

import quota_manager.sqlite_helper_functions as sqlh

log = logging.getLogger(__name__)

LOGGED_OUT = 0
LOGGED_IN = 1


class UserNameError(Exception):
    """Raised when a username query returns nothing."""

    pass


class GroupNameError(Exception):
    """Raised when a group_name query returns nothing."""

    pass


class GroupMissingError(Exception):
    """Raised when a group does not exist."""

    pass


class GroupMemberError(Exception):
    """Raised when a user is not a member of any group."""

    pass


# --- Database setup ---
def init_freeradius_db():
    p = Path(sqlh.RADIUS_DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)

    if not p.exists() or not sqlh.check_if_table_exists(
        "radcheck", sqlh.RADIUS_DB_PATH
    ):
        log.debug("RADIUS database doesn't exist!")
        try:
            with open(sqlh.DEFAULT_SCHEMA_PATH, "r") as f:
                subprocess.run(["sqlite3", sqlh.RADIUS_DB_PATH], stdin=f, check=True)
        except Exception as e:
            log.error(f"Exception: {e}. Failed to create RADIUS database!")


# --- Database setup ---
def init_usage_db():
    p = Path(sqlh.USAGE_TRACKING_DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)

    if not p.exists():

        log.debug("Usage tracking database doesn't exist!")

        with open(sqlh.USAGE_TRACKING_DB_PATH, "a") as f:
            pass

    try:
        con = sqlite3.connect(sqlh.USAGE_TRACKING_DB_PATH)
        cur = con.cursor()

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            mac_address TEXT,
            ip_address TEXT,
            daily_usage_bytes INTEGER NOT NULL DEFAULT 0,
            monthly_usage_bytes INTEGER NOT NULL DEFAULT 0,
            session_total_bytes INTEGER NOT NULL DEFAULT 0,
            all_time_bytes INTEGER NOT NULL DEFAULT 0,
            session_start_bytes NOT NULL DEFAULT 0,
            logged_in INTEGER NOT NULL DEFAULT 0,
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

    except Exception as e:
        log.error(f"Exception: {e}. Failed to create usage_tracking database!")


def insert_user_radius(
    username,
    password,
    db_path=sqlh.RADIUS_DB_PATH,
):
    table_exists = sqlh.check_if_table_exists(
        table_name="radcheck", db_path=sqlh.RADIUS_DB_PATH
    )

    if not table_exists:
        log.warning("RADIUS: Table 'radcheck' doesn't exist. Reinitializing...")
        init_freeradius_db()

    user_exists = check_if_user_exists(
        username, table_name="radcheck", db_path=sqlh.RADIUS_DB_PATH
    )

    if not user_exists:
        con = sqlite3.connect(
            db_path, timeout=30, isolation_level=None
        )  # Connects to database
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
        log.info(f"Successfully created RADIUS user {username} with id {user_id}.")
        con.commit()
        con.close()
    else:
        log.warning(f"RADIUS user {username} already exists.")


def modify_username_radius(
    old_username,
    new_username,
    db_path=sqlh.RADIUS_DB_PATH,
):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cursor = con.cursor()

    query = f"""
        UPDATE radcheck
        SET username = ?
        WHERE username = ?;
    """

    cursor.execute(query, (new_username, old_username))

    con.commit()
    con.close()


def modify_user_password_radius(
    username,
    password,
    db_path=sqlh.RADIUS_DB_PATH,
):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cursor = con.cursor()

    query = f"""
        UPDATE radcheck
        SET value = ?
        WHERE username = ?;
    """

    cursor.execute(query, (password, username))

    con.commit()
    con.close()


def delete_user_radius(
    username,
    db_path=sqlh.RADIUS_DB_PATH,
):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
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
    log.info(f"User '{username}' deleted successfully.")


def insert_user_usage(
    username,
    mac_address,
    ip_address,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO users (username, mac_address, ip_address, daily_usage_bytes, monthly_usage_bytes, session_total_bytes, session_start_bytes, logged_in)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (f"{username}", f"{mac_address}", f"{ip_address}", 0, 0, 0, 0, LOGGED_OUT),
    )

    con.commit()
    con.close()


def create_group_usage(
    group_name,
    high_speed_quota,
    throttled_quota,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO groups (group_name, high_speed_quota, throttled_quota)
    VALUES (?, ?, ?)
    """,
        (group_name, high_speed_quota, throttled_quota),
    )

    con.commit()
    con.close()


def remove_user_from_group_usage(
    username,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
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
    con.commit()
    con.close()


def insert_user_into_group_usage(
    group_name,
    username,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    remove_user_from_group_usage(username)

    # Raise error if user doesn't exist or if group doesn't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed to insert user {username} into group {group_name}: user not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    group_exists = check_if_group_exists(group_name)

    if not group_exists:
        log.error(
            f"Failed to insert user {username} into group {group_name}: group not found in groups table."
        )
        raise GroupNameError(f"Group {group_name} does not exist.")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")

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


def create_user_usage(
    username,
    group_name,
    mac_address="00:00:00:00:00",
    ip_address="0.0.0.0",
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):

    # Raise error if user exists or if group doesn't exist
    user_exists = check_if_user_exists(username)

    if user_exists:
        log.error(f"Failed to create user {username}: user already exists.")
        raise UserNameError(f"User {username} already exists.")

    group_exists = check_if_group_exists(group_name)

    if not group_exists:
        log.error(
            f"Failed to insert user {username} into group {group_name}: group not found in groups table."
        )
        raise GroupNameError(f"Group {group_name} does not exist.")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")

    cur.execute(
        """
    INSERT INTO users (username, mac_address, ip_address, daily_usage_bytes, monthly_usage_bytes, session_total_bytes, session_start_bytes, logged_in)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (f"{username}", f"{mac_address}", f"{ip_address}", 0, 0, 0, 0, LOGGED_OUT),
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


def select_user_row(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
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
    con.close()
    return row


def login_user_usage(
    username,
    mac_address,
    ip_address,
    session_start_bytes,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    row = select_user_row(username)

    # This updates the user if it already exists,
    # otherwise, creates new user.

    # Carries over daily bytes and whatnot. Need to test...
    if row:
        columns = [column for column in sqlh.fetch_all_columns("users", db_path)]
        set_clause = ", ".join(f"{col} = ?" for col in columns)
        values = list(row)
        log.debug(f"Values for user {username}: {values}")
        values[2] = mac_address
        values[3] = ip_address
        values[8] = session_start_bytes
        values[9] = LOGGED_IN

        con = sqlite3.connect(
            db_path, timeout=30, isolation_level=None
        )  # Connects to database
        cur = con.cursor()

        cur.execute(
            f"""
            UPDATE users
            SET {set_clause}
            WHERE username = ?
            """,
            values + [username],
        )

        log.info(f"User {username} successfully updated.")
        sqlh.print_all_table_information("users", db_path=sqlh.USAGE_TRACKING_DB_PATH)

        con.commit()
        con.close()
    else:
        raise UserNameError(
            f"Failed attempting to log in user {username}: User does not exist."
        )


def logout_user_usage(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    row = select_user_row(username)

    # This updates the user if it already exists,
    # otherwise, creates new user.

    # Carries over daily bytes and whatnot. Need to test...
    if row:
        columns = [column for column in sqlh.fetch_all_columns("users", db_path)]
        set_clause = ", ".join(f"{col} = ?" for col in columns)
        values = list(row)
        values[9] = LOGGED_OUT

        con = sqlite3.connect(
            db_path, timeout=30, isolation_level=None
        )  # Connects to database
        cur = con.cursor()

        cur.execute(
            f"""
            UPDATE users
            SET {set_clause}
            WHERE username = ?
            """,
            values + [username],
        )

        log.info(f"User {username} successfully logged out.")

        con.commit()
        con.close()
    else:
        raise UserNameError(
            f"Failed attempting to log out user {username}: User does not exist."
        )


def delete_user_usage(
    username,
    db_path=sqlh.USAGE_TRACKING_DB_PATH,
):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    # Delete from authentication table
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    con.commit()
    con.close()
    log.info(f"User '{username}' deleted successfully.")


def fetch_user_mac_address_usage(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):

    # Raise error if user doesn't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed fetching MAC address for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
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
        log.debug(f"No MAC address can be found for user: {username}")
        return res
    return res[0]


def get_usernames_from_mac_address_usage(
    mac_address, db_path=sqlh.USAGE_TRACKING_DB_PATH
):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()

    cur.execute(
        """
        SELECT username
        FROM users
        WHERE mac_address = ?
        """,
        (mac_address,),
    )
    res = cur.fetchall()
    if len(res) < 1:
        log.debug(f"No usernames can be found for MAC address: {mac_address}")
        return None
    return [entry[0] for entry in res]


def fetch_all_usernames_usage(db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        """
        SELECT username
        FROM users
        """,
    )
    return [entry[0] for entry in cur.fetchall()]


def fetch_session_total_bytes(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    # Raise error if user doesn't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed fetching quota_bytes for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    # Need to add try blocks and error catching for all of these things at some point.
    try:
        cur = con.cursor()

        cur.execute(
            """
            SELECT session_total_bytes
            FROM users
            WHERE username = ?
            """,
            (username,),
        )

        res = cur.fetchone()

        if res is None:
            log.error(
                f"ERROR: Operation to fetch byte information failed for user {username}."
            )
            return res

        session_total_bytes = res[0]

        log.debug(f"Session_total_bytes: {session_total_bytes}")

        return session_total_bytes

    finally:
        con.close()


def update_user_bytes_usage(byte_delta, username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    # Raise error if user doens't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed fetching quota_bytes for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    log.debug("Printing table info before update")
    sqlh.print_all_table_information("users")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    # cur.execute(
    #     """
    # CREATE TABLE IF NOT EXISTS users (
    #     id INTEGER PRIMARY KEY AUTOINCREMENT,
    #     username TEXT NOT NULL,
    #     mac_address TEXT,
    #     ip_address TEXT,
    #     daily_usage_bytes INTEGER NOT NULL DEFAULT 0,
    #     monthly_usage_bytes INTEGER NOT NULL DEFAULT 0,
    #     session_total_bytes INTEGER NOT NULL DEFAULT 0,
    #     all_time_bytes INTEGER NOT NULL DEFAULT 0,
    #     session_start_bytes NOT NULL DEFAULT 0,
    #     logged_in INTEGER NOT NULL DEFAULT 0,
    #     UNIQUE(username)
    # );
    # """
    # )

    cur.execute(
        """
        UPDATE users
        SET daily_usage_bytes = daily_usage_bytes + ?,
            monthly_usage_bytes = monthly_usage_bytes + ?,
            all_time_bytes = all_time_bytes + ?,
            session_total_bytes = session_total_bytes + ?
        WHERE username = ?
        """,
        (
            byte_delta,
            byte_delta,
            byte_delta,
            byte_delta,
            username,
        ),
    )

    # Should really add error checking here...

    con.commit()
    con.close()

    log.debug("Printing table info after update")
    sqlh.print_all_table_information("users")


def update_session_start_bytes(
    username, user_bytes, db_path=sqlh.USAGE_TRACKING_DB_PATH
):
    # Raise error if user doens't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed updating session_start_bytes for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        UPDATE users
        SET session_start_bytes = ?
        WHERE username = ?
        """,
        (
            user_bytes,
            username,
        ),
    )

    # Should really add error checking here...

    con.commit()
    con.close()


def wipe_session_total_bytes(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    log.debug(f"Wiping session total bytes for {username}...")

    # Raise error if user doens't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed wiping session_total_bytes for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        UPDATE users
        SET session_total_bytes = ?
        WHERE username = ?
        """,
        (
            0,
            username,
        ),
    )

    # Should really add error checking here...

    con.commit()
    con.close()


def usage_daily_wipe(db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
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
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
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
    # Raise error if user doesn't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed fetching quota_bytes for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
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
            log.error(
                f"ERROR: Operation to fetch daily usage failed for user {username}."
            )
            return None
        return row[0]
    finally:
        con.close()


def fetch_high_speed_quota_for_user_usage(
    username, db_path=sqlh.USAGE_TRACKING_DB_PATH
):
    # Raise error if user doesn't exist, isn't in group, or if group doesn't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed fetching quota_bytes for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    user_in_group = check_if_user_in_any_group(username)

    if not user_in_group:
        log.error(
            f"Failed fetching quota_bytes for user {username}: not assigned to a group."
        )
        raise GroupMemberError(f"User {username} not assigned to a group.")

    table_empty = sqlh.check_if_table_empty("groups", db_path)

    if table_empty:
        log.error(f"Failed fetching quota_bytes for user {username}: no groups exist.")
        raise GroupMissingError(f"No groups exist.")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    cur.execute("PRAGMA foreign_keys = ON;")

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

    if quota_bytes is None:
        log.error(
            f"ERROR: Operation to fetch high speed data quota failed for user {username}."
        )
        raise GroupMemberError(
            f"Quota bytes undefined for user {username}: group membership indeterminate."
        )

    return quota_bytes[0]


def fetch_session_start_bytes(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    # Raise error if user doesn't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed fetching quota_bytes for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    # Need to add try blocks and error catching for all of these things at some point.
    try:
        cur = con.cursor()

        cur.execute(
            """
            SELECT session_start_bytes
            FROM users
            WHERE username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        if row is None:
            log.error(
                f"ERROR: Operation to fetch session_start_bytes failed for user {username}."
            )
            raise RuntimeError(
                f"Failed to fetch session_start_bytes for user {username}."
            )
        session_start_bytes = row[0]
        log.debug(f"Session_start_bytes: {session_start_bytes}")
        return row[0]
    finally:
        con.close()


def check_if_daily_bytes_exceeds_high_speed_quota_for_user_usage(
    username, db_path=sqlh.USAGE_TRACKING_DB_PATH
):
    quota_bytes = fetch_high_speed_quota_for_user_usage(username, db_path)

    usage_bytes = fetch_daily_bytes_usage(username, db_path)

    if usage_bytes >= quota_bytes:
        return True
    else:
        return False


def check_if_user_in_any_group(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
        SELECT username
        FROM users u
        JOIN group_users gu ON u.id = gu.user_id
        WHERE username = ?
        """,
        (username,),
    )
    res = cur.fetchall()
    con.close()
    if len(res) < 1:
        return False
    return True


def check_if_user_exists(
    username, table_name="users", db_path=sqlh.USAGE_TRACKING_DB_PATH
):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT username
        FROM {table_name}
        WHERE username = ?
        """,
        (username,),
    )
    res = cur.fetchall()
    con.close()
    if len(res) < 1:
        return False
    return True


def check_if_group_exists(group_name, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
        SELECT group_name
        FROM groups
        WHERE group_name = ?
        """,
        (group_name,),
    )
    res = cur.fetchall()
    con.close()
    if len(res) < 1:
        return False
    return True


def check_if_user_logged_in(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
        SELECT logged_in
        FROM users
        WHERE username = ?
        """,
        (username,),
    )
    res = cur.fetchone()
    con.close()
    if res is None:
        raise UserNameError(f"User {username} does not exist.")

    logged_in = res[0]
    return bool(logged_in)
