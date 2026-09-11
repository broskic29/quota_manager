import sqlite3
import logging

from pathlib import Path
import subprocess
import datetime as dt

import quota_manager.sqlite_helper_functions as sqlh

log = logging.getLogger(__name__)

IP_TIMEOUT_TABLE_NAME = "ip_timeouts"
USAGE_TRACKING_TABLE_NAME = "users"
GROUP_TABLE_NAME = "groups"
GROUP_USERS_TABLE_NAME = "group_users"
RADIUS_TABLE_NAME = "radcheck"
CONFIGS_TABLE_NAME = "configs"
SYSTEM_STATE_TABLE_NAME = "system_state"

LOGGED_OUT = 0
LOGGED_IN = 1

NOT_OVER_QUOTA = 0
OVER_QUOTA = 1

IP_POLLING = 30
IP_TIMEOUT = int(4 * IP_POLLING)


class UserNameError(Exception):
    """Raised when a username query returns nothing."""

    pass


class ConfigNameError(Exception):
    """Raised when a config name query returns nothing."""

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


class DBInitializationError(Exception):
    """Raised when databases fail to initialize."""

    pass


class SystemStateError(Exception):
    """System state database left in corrputed state."""

    pass


# --- Database setup ---
def init_freeradius_db():
    p = Path(sqlh.RADIUS_DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)

    if not p.exists() or not sqlh.check_if_table_exists(
        RADIUS_TABLE_NAME, sqlh.RADIUS_DB_PATH
    ):
        log.debug("RADIUS database doesn't exist!")
        try:
            log.debug("Initializing RADIUS database...")
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

        log.info("Initializing usage database...")

        with open(sqlh.USAGE_TRACKING_DB_PATH, "a") as f:
            pass

    try:
        con = sqlite3.connect(sqlh.USAGE_TRACKING_DB_PATH)
        cur = con.cursor()

        if not sqlh.check_if_table_exists(
            USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.info(f"sql_management: Creating table '{USAGE_TRACKING_TABLE_NAME}'.")

        cur.execute(
            f"""
        CREATE TABLE IF NOT EXISTS {USAGE_TRACKING_TABLE_NAME} (
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
            exceeds_quota INTEGER NOT NULL DEFAULT 0,
            UNIQUE(username)
        );
        """
        )

        if not sqlh.check_if_table_exists(
            GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.info(f"sql_management: Creating table '{GROUP_TABLE_NAME}'.")

        cur.execute(
            f"""
        CREATE TABLE IF NOT EXISTS {GROUP_TABLE_NAME} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT NOT NULL,
            high_speed_quota INTEGER NOT NULL DEFAULT 0,
            throttled_quota INTEGER NOT NULL DEFAULT 0,
            desired_quota_ratio REAL NOT NULL DEFAULT 0.0,
            min_quota_ratio REAL NOT NULL DEFAULT 0.0,
            max_num_bytes INTEGER,
            min_num_bytes INTEGER NOT NULL DEFAULT 0.0,
            mse_weights REAL,
            UNIQUE(group_name)
        );
        """
        )

        if not sqlh.check_if_table_exists(
            GROUP_USERS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.info(f"sql_management: Creating table '{GROUP_USERS_TABLE_NAME}'.")

        cur.execute(
            f"""
        CREATE TABLE IF NOT EXISTS {GROUP_USERS_TABLE_NAME} (
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,

            PRIMARY KEY (user_id, group_id),

            FOREIGN KEY (group_id) REFERENCES groups(id)
                ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id)
                ON DELETE CASCADE,

            UNIQUE(user_id)
        );
        """
        )

        if not sqlh.check_if_table_exists(
            IP_TIMEOUT_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.info(f"sql_management: Creating table '{IP_TIMEOUT_TABLE_NAME}'.")

        cur.execute(
            f"""
        CREATE TABLE IF NOT EXISTS {IP_TIMEOUT_TABLE_NAME} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_addr TEXT NOT NULL,
            mac_addr TEXT NOT NULL,
            last_timestamp INTEGER,
            timeout INTEGER DEFAULT 0,
            UNIQUE(ip_addr)
        );
        """
        )

        if not sqlh.check_if_table_exists(
            CONFIGS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.info(f"sql_management: Creating table '{CONFIGS_TABLE_NAME}'.")

        cur.execute(
            f"""
        CREATE TABLE IF NOT EXISTS {CONFIGS_TABLE_NAME} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            system_name TEXT NOT NULL,
            total_monthly_bytes_purchased INTEGER NOT NULL,
            throttling_enabled INTEGER NOT NULL,
            active_days TEXT NOT NULL,
            mac_set_limitation INTEGER NOT NULL,
            allowed_macs TEXT,
            active_config INTEGER
        );
        """
        )

        if not sqlh.check_if_table_exists(
            SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.info(f"sql_management: Creating table '{SYSTEM_STATE_TABLE_NAME}'.")

        cur.execute(
            f"""
        CREATE TABLE IF NOT EXISTS {SYSTEM_STATE_TABLE_NAME} (
            system_name TEXT PRIMARY KEY,
            system_date TEXT NOT NULL,
            wiped_this_month INTEGER NOT NULL,
            total_daily_bytes INTEGER,
            total_monthly_bytes INTEGER,
            all_time_bytes INTEGER,
            num_users INTEGER,
            num_groups INTEGER,
            total_system_monthly_bytes INTEGER,
            session_start_bytes INTEGER,
            session_total_bytes INTEGER,
            daily_budget_bytes INTEGER,
            UNIQUE(system_name)
        );
        """
        )

        con.commit()
        con.close()

        if sqlh.check_if_table_empty(CONFIGS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
            # Default: Mon-Fri active (0-4), throttling off, mac limitation off
            create_config_usage(
                name="default",
                system_name="dbtti",
                total_bytes=0,  # YOU should set this in admin page
                throttling_enabled=False,
                active_days=[0, 1, 2, 3, 4],
                mac_set_limitation=False,
                allowed_macs=None,
                active_config=1,
            )

            log.debug(f"init_usage_db: Initialized config:")
            sqlh.log_all_table_information(CONFIGS_TABLE_NAME)

        if sqlh.check_if_table_empty(
            SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):

            tz = dt.timezone(dt.timedelta(hours=sqlh.UTC_OFFSET))
            now = dt.datetime.now(tz)
            date_str = now.date().isoformat()

            try:
                config = fetch_active_config()
            except ConfigNameError as e:
                raise DBInitializationError(f"Databases failed to iniitalize: {e}")

            # Default: Mon-Fri active (0-4), throttling off, mac limitation off
            initialize_system_state_usage(
                system_name=config["system_name"],
                system_date=date_str,
                wiped_this_month=False,
                total_daily_bytes=0,
                total_monthly_bytes=0,
                all_time_bytes=0,
                num_users=0,
                num_groups=0,
                total_system_monthly_bytes=0,
                session_start_bytes=0,
                session_total_bytes=0,
                daily_budget_bytes=0,
                db_path=sqlh.USAGE_TRACKING_DB_PATH,
            )

            log.debug(f"init_usage_db: Initialized system state:")
            sqlh.log_all_table_information(SYSTEM_STATE_TABLE_NAME)

    except Exception as e:
        log.error(f"Exception: {e}. Failed to create usage_tracking database!")
        raise Exception(e)


def insert_user_radius(
    username,
    password,
    db_path=None,
):
    db_path = db_path or sqlh.RADIUS_DB_PATH
    table_exists = sqlh.check_if_table_exists(
        table_name=RADIUS_TABLE_NAME, db_path=sqlh.RADIUS_DB_PATH
    )

    if not table_exists:
        log.warning("RADIUS: Table 'radcheck' doesn't exist. Reinitializing...")
        init_freeradius_db()

    user_exists = check_if_user_exists(
        username, table_name=RADIUS_TABLE_NAME, db_path=sqlh.RADIUS_DB_PATH
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
    db_path=None,
):
    db_path = db_path or sqlh.RADIUS_DB_PATH
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


def get_user_password_radius(
    username,
    db_path=None,
):
    db_path = db_path or sqlh.RADIUS_DB_PATH
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cursor = con.cursor()

    query = f"""
        SELECT value
        FROM radcheck
        WHERE username = ? AND attribute = ?;
    """

    cursor.execute(query, (username, "Cleartext-Password"))

    res = cursor.fetchone()

    con.commit()
    con.close()

    return res[0]


def modify_user_password_radius(
    username,
    password,
    db_path=None,
):
    db_path = db_path or sqlh.RADIUS_DB_PATH
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
    db_path=None,
):
    db_path = db_path or sqlh.RADIUS_DB_PATH
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
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO users (username, mac_address, ip_address, daily_usage_bytes, monthly_usage_bytes, session_total_bytes, session_start_bytes, logged_in, over_quota)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            f"{username}",
            f"{mac_address}",
            f"{ip_address}",
            0,
            0,
            0,
            0,
            LOGGED_OUT,
            NOT_OVER_QUOTA,
        ),
    )

    con.commit()
    con.close()


def create_group_usage(
    group_name,
    desired_quota_ratio,
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO groups (group_name, desired_quota_ratio)
    VALUES (?, ?)
    """,
        (group_name, desired_quota_ratio),
    )

    con.commit()
    con.close()


def remove_user_from_group_usage(
    username,
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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
    INSERT OR IGNORE INTO group_users (user_id, group_id)
    SELECT u.id, g.id
    FROM users u
    JOIN groups g ON g.group_name = ?
    WHERE u.username = ?
    """,
        (group_name, username),
    )
    con.commit()
    con.close()


def get_groups_usage(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        return

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
        SELECT group_name
        FROM groups
        """,
    )
    res = cur.fetchall()
    if len(res) < 1:
        log.debug(f"No usage groups exist.")
        return None
    return [entry[0] for entry in res]


def update_group_quota(group_name, quota_byte_value, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    cur.execute(
        f"""
            UPDATE {GROUP_TABLE_NAME}
            SET high_speed_quota = ?
            WHERE group_name = ?
            """,
        (quota_byte_value, group_name),
    )

    con.commit()
    con.close()


def update_min_quota_ratio(group_name, min_quota_ratio, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        f"""
            UPDATE {GROUP_TABLE_NAME}
            SET min_quota_ratio = ?
            WHERE group_name = ?
            """,
        (min_quota_ratio, group_name),
    )
    con.commit()
    con.close()


def create_user_usage(
    username,
    group_name,
    mac_address="00:00:00:00:00",
    ip_address="0.0.0.0",
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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
    INSERT INTO users (username, mac_address, ip_address)
    VALUES (?, ?, ?)
    """,
        (username, mac_address, ip_address),
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


def delete_group_usage(group_name, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")
    cur.execute("DELETE FROM groups WHERE group_name = ?", (group_name,))
    con.commit()
    con.close()
    log.info(f"Group '{group_name}' deleted successfully.")


def update_group_desired_quota_ratio(group_name, desired_quota_ratio, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        UPDATE {GROUP_TABLE_NAME}
        SET desired_quota_ratio = ?
        WHERE group_name = ?
        """,
        (desired_quota_ratio, group_name),
    )
    con.commit()
    con.close()
    log.info(
        f"Group '{group_name}' desired_quota_ratio updated to {desired_quota_ratio}."
    )


def count_users_in_group(group_name, db_path=None) -> int:
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        """
        SELECT COUNT(*)
        FROM users u
        JOIN group_users gu ON gu.user_id = u.id
        JOIN groups g ON g.id = gu.group_id
        WHERE g.group_name = ?
        """,
        (group_name,),
    )
    res = cur.fetchone()
    con.close()
    return int(res[0] if res else 0)


def select_user_row(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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


def select_group_row(group_name, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
        SELECT *
        FROM groups
        WHERE group_name = ?
        """,
        (group_name,),
    )
    row = cur.fetchone()
    con.close()
    return row


def login_user_usage(
    username,
    ip_address,
    mac_address,
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    row = select_user_row(username)

    # This updates the user if it already exists,
    # otherwise, creates new user.

    # Carries over daily bytes and whatnot. Need to test...
    if row:
        columns = [
            column
            for column in sqlh.fetch_all_columns(USAGE_TRACKING_TABLE_NAME, db_path)
        ]
        set_clause = ", ".join(f"{col} = ?" for col in columns)
        values = list(row)
        log.debug(f"Values for user {username}: {values}")
        values[2] = ip_address
        values[3] = mac_address
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
        sqlh.log_all_table_information(
            USAGE_TRACKING_TABLE_NAME, db_path=sqlh.USAGE_TRACKING_DB_PATH
        )

        con.commit()
        con.close()
    else:
        raise UserNameError(
            f"Failed attempting to log in user {username}: User does not exist."
        )


def logout_user_usage(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if check_if_user_exists(username):

        con = sqlite3.connect(
            db_path, timeout=30, isolation_level=None
        )  # Connects to database
        cur = con.cursor()

        cur.execute(
            f"""
            UPDATE users
            SET logged_in = ?
            WHERE username = ?
            """,
            (LOGGED_OUT, username),
        )

        log.debug(f"User {username} successfully logged out.")

        con.commit()
        con.close()
    else:
        raise UserNameError(
            f"Failed attempting to log out user {username}: User does not exist."
        )


def delete_user_usage(
    username,
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    # Delete from authentication table
    con.execute("PRAGMA foreign_keys = ON;")
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    con.commit()
    con.close()
    log.info(f"User '{username}' deleted successfully.")


def create_config_usage(
    name: str,
    system_name: str,
    total_bytes: int,
    throttling_enabled: bool,
    active_days: list[int],
    mac_set_limitation: bool,
    allowed_macs: list[str] | None = None,
    active_config: int | None = None,
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    active_days = ",".join(str(day) for day in active_days)

    if allowed_macs:
        allowed_macs = ",".join(mac for mac in allowed_macs)

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    cur.execute(
        f"""
    INSERT INTO {CONFIGS_TABLE_NAME} (name, system_name, total_monthly_bytes_purchased, throttling_enabled, active_days, mac_set_limitation, allowed_macs, active_config)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            name,
            system_name,
            total_bytes,
            throttling_enabled,
            active_days,
            mac_set_limitation,
            allowed_macs,
            active_config,
        ),
    )

    con.commit()
    con.close()


def initialize_system_state_usage(
    system_name: str,
    system_date: str,
    wiped_this_month: bool,
    total_daily_bytes: int | None = None,
    total_monthly_bytes: int | None = None,
    all_time_bytes: int | None = None,
    num_users: int | None = None,
    num_groups: int | None = None,
    total_system_monthly_bytes: int | None = None,
    session_start_bytes: int | None = None,
    session_total_bytes: int | None = None,
    daily_budget_bytes: int | None = None,
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    cur.execute(
        f"""
    INSERT INTO {SYSTEM_STATE_TABLE_NAME} (system_name, system_date, wiped_this_month, total_daily_bytes, total_monthly_bytes, all_time_bytes, num_users, num_groups, total_system_monthly_bytes, session_start_bytes, session_total_bytes, daily_budget_bytes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            system_name,
            system_date,
            wiped_this_month,
            total_daily_bytes,
            total_monthly_bytes,
            all_time_bytes,
            num_users,
            num_groups,
            total_system_monthly_bytes,
            session_start_bytes,
            session_total_bytes,
            daily_budget_bytes,
        ),
    )

    con.commit()
    con.close()


def update_system_state_usage(
    system_name: str | None = None,
    system_date: str | None = None,
    wiped_this_month: bool | None = None,
    total_daily_bytes: int | None = None,
    total_monthly_bytes: int | None = None,
    all_time_bytes: int | None = None,
    num_users: int | None = None,
    num_groups: int | None = None,
    total_system_monthly_bytes: int | None = None,
    session_start_bytes: int | None = None,
    session_total_bytes: int | None = None,
    daily_budget_bytes: int | None = None,
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    row = fetch_system_state_row()

    if row:
        columns = [
            column
            for column in sqlh.fetch_all_columns(SYSTEM_STATE_TABLE_NAME, db_path)
        ]
        set_clause = ", ".join(f"{col} = ?" for col in columns)
        values = list(row)
        log.debug(f"Values for system {values[0]}: {values}")
        values[0] = system_name if system_name is not None else values[0]
        values[1] = system_date if system_date is not None else values[1]
        values[2] = wiped_this_month if wiped_this_month is not None else values[2]
        values[3] = total_daily_bytes if total_daily_bytes is not None else values[3]
        values[4] = (
            total_monthly_bytes if total_monthly_bytes is not None else values[4]
        )
        values[5] = all_time_bytes if all_time_bytes is not None else values[5]
        values[6] = num_users if num_users is not None else values[6]
        values[7] = num_groups if num_groups is not None else values[7]
        values[8] = (
            total_system_monthly_bytes
            if total_system_monthly_bytes is not None
            else values[8]
        )
        values[9] = (
            session_start_bytes if session_start_bytes is not None else values[9]
        )
        values[10] = (
            session_total_bytes if session_total_bytes is not None else values[10]
        )
        values[11] = (
            daily_budget_bytes if daily_budget_bytes is not None else values[11]
        )

        con = sqlite3.connect(
            db_path, timeout=30, isolation_level=None
        )  # Connects to database
        cur = con.cursor()

        cur.execute(
            f"""
            UPDATE {SYSTEM_STATE_TABLE_NAME}
            SET {set_clause}
            WHERE system_name = ?
            """,
            values + [values[0]],
        )

        log.info(f"System {values[0]} state successfully updated.")
        sqlh.log_all_table_information(
            SYSTEM_STATE_TABLE_NAME, db_path=sqlh.USAGE_TRACKING_DB_PATH
        )

        con.commit()
        con.close()
    else:
        raise RuntimeError(f"System state information does not exist.")


def select_config_row(name, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT *
        FROM {CONFIGS_TABLE_NAME}
        WHERE name = ?
        """,
        (name,),
    )
    row = cur.fetchone()
    con.close()
    return row


def update_config_usage(
    name: str | None = None,
    system_name: str | None = None,
    total_bytes: int | None = None,
    throttling_enabled: bool | None = None,
    active_days: list[int] | None = None,
    mac_set_limitation: bool | None = None,
    allowed_macs: list[str] | None = None,
    active_config: int | None = None,
    db_path=None,
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    row = select_config_row(name)

    if isinstance(active_days, list):
        active_days = ",".join(str(d) for d in active_days)
    elif active_days is None:
        active_days = ""

    if isinstance(allowed_macs, list):
        allowed_macs = ",".join(str(d) for d in allowed_macs)
    elif allowed_macs is None:
        allowed_macs = ""

    # This updates the user if it already exists,
    # otherwise, creates new user.

    # Carries over daily bytes and whatnot. Need to test...
    if row:
        columns = [
            column for column in sqlh.fetch_all_columns(CONFIGS_TABLE_NAME, db_path)
        ]
        set_clause = ", ".join(f"{col} = ?" for col in columns)
        values = list(row)
        log.debug(f"Values for config {name}: {values}")
        values[1] = name if name is not None else values[1]
        values[2] = system_name if system_name is not None else values[2]
        values[3] = total_bytes if total_bytes is not None else values[3]
        values[4] = throttling_enabled if throttling_enabled is not None else values[4]
        values[5] = active_days if active_days is not None else values[5]
        values[6] = mac_set_limitation if mac_set_limitation is not None else values[6]
        values[7] = allowed_macs if allowed_macs is not None else values[7]
        values[8] = active_config if active_config is not None else values[8]

        con = sqlite3.connect(
            db_path, timeout=30, isolation_level=None
        )  # Connects to database
        cur = con.cursor()

        cur.execute(
            f"""
            UPDATE {CONFIGS_TABLE_NAME}
            SET {set_clause}
            WHERE name = ?
            """,
            values + [name],
        )

        con.commit()
        con.close()
    else:
        raise ConfigNameError(
            f"Failed attempting to update system config: config {name} does not exist."
        )


def fetch_active_config_row(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        CONFIGS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(CONFIGS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_active_config_row: Table {CONFIGS_TABLE_NAME} empty or does not exist."
        )
        return

    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT id, name, system_name, total_monthly_bytes_purchased, throttling_enabled, active_days,
               mac_set_limitation, allowed_macs, active_config
        FROM {CONFIGS_TABLE_NAME}
        WHERE active_config = 1
        LIMIT 1
        """
    )
    row = cur.fetchone()
    con.close()
    return row


def fetch_active_config(db_path=None) -> dict:
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        CONFIGS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(CONFIGS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_active_config: Table {CONFIGS_TABLE_NAME} empty or does not exist."
        )
        raise ConfigNameError("Config table empty or does not exist.")

    row = fetch_active_config_row(db_path)
    if not row:
        # fallback to name="default" if present
        default = select_config_row("default", db_path=db_path)
        if not default:
            raise ConfigNameError("No active config and no default config found.")
        row = default

    # row layout depends on select_config_row vs fetch_active_config_row:
    # select_config_row returns "*", so safest is to re-query by name using columns:
    # We'll standardize: if row came from select_config_row, its indexes match table definition.
    # Table is: id, name, total_monthly_bytes_purchased, throttling_enabled, active_days,
    #           mac_set_limitation, allowed_macs, active_config
    cfg = {
        "id": row[0],
        "name": row[1],
        "system_name": row[2],
        "total_monthly_bytes_purchased": int(row[3]),
        "throttling_enabled": bool(row[4]),
        "active_days": row[5] or "",
        "mac_set_limitation": bool(row[6]),
        "allowed_macs": row[7] or "",
        "active_config": row[8],
    }

    # parse active_days -> list[int]
    days = []
    for part in cfg["active_days"].split(",") if cfg["active_days"] else []:
        part = part.strip()
        if part != "":
            days.append(int(part))
    cfg["active_days_list"] = days

    # parse allowed_macs -> list[str]
    macs = []
    for m in cfg["allowed_macs"].split(",") if cfg["allowed_macs"] else []:
        m = m.strip()
        if m:
            macs.append(m)
    cfg["allowed_macs_list"] = macs

    return cfg


def fetch_system_state_row(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_system_state_row: Table {SYSTEM_STATE_TABLE_NAME} empty or does not exist."
        )
        return

    config = fetch_active_config()

    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT system_name, system_date, wiped_this_month, total_daily_bytes, total_monthly_bytes, all_time_bytes, num_users, num_groups, total_system_monthly_bytes, session_start_bytes, session_total_bytes, daily_budget_bytes
        FROM {SYSTEM_STATE_TABLE_NAME}
        WHERE system_name = ?
        LIMIT 1
        """,
        (config["system_name"],),
    )
    row = cur.fetchone()
    con.close()
    return row


def fetch_system_state(db_path=None) -> dict:
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_system_state: Table {SYSTEM_STATE_TABLE_NAME} empty or does not exist."
        )
        return

    row = fetch_system_state_row(db_path)

    # row layout depends on select_config_row vs fetch_active_config_row:
    # select_config_row returns "*", so safest is to re-query by name using columns:
    # We'll standardize: if row came from select_config_row, its indexes match table definition.
    # Table is: id, name, total_monthly_bytes_purchased, throttling_enabled, active_days,
    #           mac_set_limitation, allowed_macs, active_config
    cfg = {
        "system_name": row[0],
        "system_date": row[1],
        "wiped_this_month": bool(row[2]),
        "total_daily_bytes": row[3],
        "total_monthly_bytes": row[4],
        "all_time_bytes": row[5],
        "num_users": row[6],
        "num_groups": row[7],
        "total_system_monthly_bytes": row[8],
        "session_start_bytes": row[9],
        "session_total_bytes": row[10],
    }

    return cfg


def fetch_user_mac_address_usage(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_user_mac_address_usage: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
        )
        return
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


def fetch_user_ip_address_usage(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_user_ip_address_usage: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
        )
        return
    # Raise error if user doesn't exist
    user_exists = check_if_user_exists(username)

    if not user_exists:
        log.error(
            f"Failed fetching IP address for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()

    cur.execute(
        """
        SELECT ip_address
        FROM users
        WHERE username = ?
        """,
        (username,),
    )
    res = cur.fetchone()
    if res is None:
        log.debug(f"No IP address can be found for user: {username}")
        return res
    return res[0]


def get_usernames_from_mac_address_usage(mac_address, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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


def get_usernames_from_ip_address_usage(ip_address, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()

    cur.execute(
        """
        SELECT username
        FROM users
        WHERE ip_address = ?
        """,
        (ip_address,),
    )
    res = cur.fetchall()
    if len(res) < 1:
        return None
    return [entry[0] for entry in res]


def get_usernames_from_ip_and_mac_usage(ip_addr, mac_addr, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()

    cur.execute(
        """
        SELECT username
        FROM users
        WHERE ip_address = ? AND mac_address = ?

        """,
        (
            ip_addr,
            mac_addr,
        ),
    )
    res = cur.fetchall()
    if len(res) < 1:
        log.debug(
            f"No usernames can be found for IP address: {ip_addr}, MAC address {mac_addr}"
        )
        return None
    return [entry[0] for entry in res]


def fetch_all_usernames_usage(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        return
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT username
        FROM {USAGE_TRACKING_TABLE_NAME}
        """,
    )
    return [entry[0] for entry in cur.fetchall()]


def fetch_group_quota_info_usage(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_group_quota_info_usage: Table {GROUP_TABLE_NAME} empty or does not exist."
        )
        return

    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()

    if sqlh.check_if_table_empty(
        GROUP_USERS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or not sqlh.check_if_table_exists(
        GROUP_USERS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_group_quota_info_usage: Table {GROUP_USERS_TABLE_NAME} empty or does not exist. Setting num_members for each group to zero."
        )
        cur.execute(
            f"""
            SELECT
                g.group_name,
                g.desired_quota_ratio, g.min_quota_ratio,
                g.max_num_bytes,
                g.min_num_bytes,
                g.mse_weights
            FROM {GROUP_TABLE_NAME} g
            ORDER BY g.group_name;
            """,
        )

        res = cur.fetchall()
        # Insert value 0 at position 1, thereby setting num_member = 0
        new_res = [list(interior_tuple) for interior_tuple in res]
        for interior_list in new_res:
            interior_list.insert(1, 0)
        res = [tuple(interior_list) for interior_list in new_res]

    else:
        cur.execute(
            f"""
            SELECT
                g.group_name,
                COUNT(gu.user_id) AS num_members,
                g.desired_quota_ratio, g.min_quota_ratio,
                g.max_num_bytes,
                g.min_num_bytes,
                g.mse_weights
            FROM {GROUP_TABLE_NAME} g
            LEFT JOIN group_users gu ON gu.group_id = g.id
            GROUP BY
                g.id,
                g.group_name,
                g.desired_quota_ratio,
                g.min_quota_ratio,
                g.max_num_bytes,
                g.min_num_bytes,
                g.mse_weights
            ORDER BY g.group_name;
            """,
        )
        res = cur.fetchall()
    return res


def fetch_all_users_with_groups_usage(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_all_users_with_groups_usage: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
        )
        return
    if not sqlh.check_if_table_exists(
        GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_all_users_with_groups_usage: Table {GROUP_TABLE_NAME} empty or does not exist."
        )
        return
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        """
        SELECT u.username, g.group_name
        FROM users u
        LEFT JOIN group_users gu ON gu.user_id = u.id
        LEFT JOIN groups g ON g.id = gu.group_id
        ORDER BY u.username
        """
    )
    rows = cur.fetchall()
    con.close()
    return rows


def fetch_users_usage_rows(db_path=None) -> list[dict]:
    """Return a list of user usage dicts sorted by daily usage desc."""
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_desired_quota_ratios: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
        )
        return

    if not sqlh.check_if_table_exists(
        GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_desired_quota_ratios: Table {GROUP_TABLE_NAME} empty or does not exist."
        )
        return

    if not sqlh.check_if_table_exists(
        GROUP_USERS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_USERS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_desired_quota_ratios: Table {GROUP_USERS_TABLE_NAME} empty or does not exist."
        )
        return

    with sqlite3.connect(db_path, timeout=30) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            """
            SELECT
                u.username,
                u.daily_usage_bytes,
                u.monthly_usage_bytes,
                u.ip_address,
                u.mac_address,
                u.logged_in,
                g.group_name
            FROM users u
            LEFT JOIN group_users gu ON gu.user_id = u.id
            LEFT JOIN groups g ON g.id = gu.group_id
            ORDER BY u.daily_usage_bytes DESC, u.username ASC
            """
        ).fetchall()

    users: list[dict] = []
    for r in rows:
        users.append(
            {
                "username": r["username"],
                "group_name": r["group_name"],
                "daily_mib": (r["daily_usage_bytes"] or 0) / float(1024**2),
                "monthly_gib": (r["monthly_usage_bytes"] or 0) / float(1024**3),
                "ip_address": r["ip_address"],
                "mac_address": r["mac_address"],
                "logged_in": bool(r["logged_in"]),
            }
        )
    return users


def fetch_desired_quota_ratios(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_desired_quota_ratios: Table {GROUP_TABLE_NAME} empty or does not exist."
        )
        return
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT group_name, desired_quota_ratio
        FROM {GROUP_TABLE_NAME}
        """,
    )
    res = cur.fetchall()
    return res


def fetch_config_total_bytes(config_name="default", db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        CONFIGS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(CONFIGS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_config_total_bytes: Table {CONFIGS_TABLE_NAME} empty or does not exist."
        )
        return 0
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT total_monthly_bytes_purchased
        FROM {CONFIGS_TABLE_NAME}
        WHERE name = ?
        """,
        (config_name,),
    )

    res = cur.fetchone()

    con.close()

    return res[0]


def fetch_daily_usage_bytes(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    config = fetch_active_config()
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT total_daily_bytes
        FROM {SYSTEM_STATE_TABLE_NAME}
        WHERE system_name = ?
        """,
        (config["system_name"],),
    )
    res = cur.fetchone()
    return res[0]


def fetch_monthly_usage_bytes(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    config = fetch_active_config()
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT total_monthly_bytes
        FROM {SYSTEM_STATE_TABLE_NAME}
        WHERE system_name = ?
        """,
        (config["system_name"],),
    )
    res = cur.fetchone()
    return res[0]


def fetch_total_system_monthly_usage_bytes(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    config = fetch_active_config()
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT total_system_monthly_bytes
        FROM {SYSTEM_STATE_TABLE_NAME}
        WHERE system_name = ?
        """,
        (config["system_name"],),
    )
    res = cur.fetchone()
    return res[0]


def fetch_max_daily_usage(db_path=None):
    """
    Should iterate across each user in the system, summing (user_quota - daily_usage).
    """
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_max_daily_usage: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
        )
        return 0
    if not sqlh.check_if_table_exists(
        GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_max_daily_usage: Table {GROUP_TABLE_NAME} empty or does not exist."
        )
        return 0
    if not sqlh.check_if_table_exists(
        GROUP_USERS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_USERS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_max_daily_usage: Table {GROUP_USERS_TABLE_NAME} empty or does not exist."
        )
        return 0

    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()

    cur.execute("PRAGMA foreign_keys = ON;")

    cur.execute(
        """
        SELECT COALESCE(SUM(MAX(COALESCE(g.high_speed_quota, 0) - COALESCE(u.daily_usage_bytes, 0), 0)), 0)
        FROM users u
        JOIN group_users gu ON u.id = gu.user_id
        JOIN groups g ON g.id = gu.group_id
        """
    )

    res = cur.fetchone()

    con.close()

    return res[0]


def fetch_all_monthly_usage_bytes(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_max_daily_usage: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
        )
        return 0

    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT monthly_usage_bytes
        FROM {USAGE_TRACKING_TABLE_NAME}
        """,
    )
    return [entry[0] for entry in cur.fetchall()]


def fetch_all_ip_addr_ip_timeouts(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        return
    con = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT ip_addr, mac_addr
        FROM {IP_TIMEOUT_TABLE_NAME}
        """,
    )
    return cur.fetchall()


def fetch_session_bytes(username=None, system_name=None, byte_type=None, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if (username is None and system_name is None) or (username and system_name):
        log.error("fetch_session_bytes: Must specify either username or system name.")
        raise ValueError("Must specify either username or system name.")

    byte_type_dict = {"start": "session_start_bytes", "total": "session_total_bytes"}

    if byte_type is None or byte_type not in byte_type_dict:
        log.error("fetch_session_bytes: Must specify a proper byte type.")
        raise ValueError("Must specify a proper byte type.")

    byte_type = byte_type_dict[byte_type]

    if username:
        if not sqlh.check_if_table_exists(
            USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ) or sqlh.check_if_table_empty(
            USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.debug(
                f"fetch_max_daily_usage: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
            )
            return 0

        # Raise error if user doesn't exist
        user_exists = check_if_user_exists(username)

        if not user_exists:
            log.error(
                f"Failed fetching quota_bytes for user {username}: not found in users table."
            )
            raise UserNameError(f"User {username} does not exist.")

    elif system_name:
        if not sqlh.check_if_table_exists(
            SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ) or sqlh.check_if_table_empty(
            SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.debug(
                f"fetch_session_start_bytes: Table {SYSTEM_STATE_TABLE_NAME} empty or does not exist."
            )
            return 0

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    # Need to add try blocks and error catching for all of these things at some point.
    try:
        cur = con.cursor()

        if username:
            cur.execute(
                f"""
                SELECT {byte_type}
                FROM users
                WHERE username = ?
                """,
                (username,),
            )
        elif system_name:
            cur.execute(
                f"""
                SELECT {byte_type}
                FROM system_state
                WHERE system_name = ?
                """,
                (system_name,),
            )

        row = cur.fetchone()
        if row is None:
            if username:
                log.error(
                    f"ERROR: Operation to fetch {byte_type} failed for user {username}."
                )
                raise RuntimeError(f"Failed to fetch {byte_type} for user {username}.")
            elif system_name:
                log.error(
                    f"ERROR: Operation to fetch {byte_type} failed for system '{system_name}'."
                )
                raise RuntimeError(
                    f"Failed to fetch {byte_type} for system '{system_name}'."
                )
        session_bytes = row[0]

        name = username if username else system_name
        log.debug(f"{byte_type}: {session_bytes} for {name}")

        return session_bytes
    finally:
        con.close()


def update_user_bytes_usage(byte_delta, username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    # Raise error if user doens't exist
    user_exists = check_if_user_exists(username)

    cfg = fetch_active_config()
    system_name = cfg.get("system_name")
    if not system_name:
        log.error(
            "update_user_bytes_usage: Error, no active config. Unable to update system bytes."
        )
        raise ConfigNameError(
            "update_user_bytes_usage: Error, no active config. Unable to update system bytes."
        )

    if not user_exists:
        log.error(
            f"Failed fetching quota_bytes for user {username}: not found in users table."
        )
        raise UserNameError(f"User {username} does not exist.")

    # log.debug("Printing table info before update")
    # sqlh.log_all_table_information(USAGE_TRACKING_TABLE_NAME)

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

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

    cur.execute(
        """
        UPDATE system_state
        SET total_daily_bytes = total_daily_bytes + ?,
            total_monthly_bytes = total_monthly_bytes + ?,
            all_time_bytes = all_time_bytes + ?
        WHERE system_name = ?
        """,
        (
            byte_delta,
            byte_delta,
            byte_delta,
            system_name,
        ),
    )

    # Should really add error checking here...

    con.commit()
    con.close()

    # log.debug("Printing table info after update")
    # sqlh.log_all_table_information(USAGE_TRACKING_TABLE_NAME)


def update_system_bytes_usage(byte_delta, system_name, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not system_name:
        log.error(
            "update_system_bytes_usage: Error, no active config. Unable to update system bytes."
        )
        raise ConfigNameError(
            "update_system_bytes_usage: Error, no active config. Unable to update system bytes."
        )

    if not sqlh.check_if_table_exists(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_session_start_bytes: Table {SYSTEM_STATE_TABLE_NAME} empty or does not exist."
        )
        return 0

    # log.debug("Printing table info before update")
    # sqlh.log_all_table_information(SYSTEM_STATE_TABLE_NAME)

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        UPDATE system_state
        SET total_system_monthly_bytes = total_system_monthly_bytes + ?,
            session_total_bytes = session_total_bytes + ?
        WHERE system_name = ?
        """,
        (
            byte_delta,
            byte_delta,
            system_name,
        ),
    )

    # Should really add error checking here...

    con.commit()
    con.close()

    # log.debug("Printing table info after update")
    # sqlh.log_all_table_information(USAGE_TRACKING_TABLE_NAME)


def update_session_start_bytes(
    user_bytes, username=None, system_name=None, db_path=None
):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if (username is None and system_name is None) or (username and system_name):
        log.error(
            "update_session_start_bytes: Must specify either username or system name."
        )
        raise ValueError("Must specify either username or system name.")

    if username:
        if not sqlh.check_if_table_exists(
            USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ) or sqlh.check_if_table_empty(
            USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.debug(
                f"update_session_start_bytes: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
            )
            return 0
        # Raise error if user doens't exist
        user_exists = check_if_user_exists(username)

        if not user_exists:
            log.error(
                f"Failed updating session_start_bytes for user {username}: not found in users table."
            )
            raise UserNameError(f"User {username} does not exist.")

    elif system_name:
        if not sqlh.check_if_table_exists(
            SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ) or sqlh.check_if_table_empty(
            SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.debug(
                f"update_session_start_bytes: Table {SYSTEM_STATE_TABLE_NAME} empty or does not exist."
            )
            return 0

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    if username:
        cur.execute(
            f"""
            UPDATE {USAGE_TRACKING_TABLE_NAME}
            SET session_start_bytes = ?
            WHERE username = ?
            """,
            (
                user_bytes,
                username,
            ),
        )
    elif system_name:
        cur.execute(
            f"""
            UPDATE {SYSTEM_STATE_TABLE_NAME}
            SET session_start_bytes = ?
            WHERE system_name = ?
            """,
            (
                user_bytes,
                system_name,
            ),
        )

    # Should really add error checking here...

    con.commit()
    con.close()


def wipe_session_total_bytes(username=None, system_name=None, db_path=None):

    if (username is None and system_name is None) or (username and system_name):
        log.error("fetch_session_bytes: Must specify either username or system name.")
        raise ValueError("Must specify either username or system name.")

    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if username:
        if not sqlh.check_if_table_exists(
            USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ) or sqlh.check_if_table_empty(
            USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.debug(
                f"wipe_session_total_bytes: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
            )
            return 0
        # Raise error if user doens't exist
        user_exists = check_if_user_exists(username)

        if not user_exists:
            log.error(
                f"Failed wiping session_total_bytes for user {username}: not found in users table."
            )
            raise UserNameError(f"User {username} does not exist.")

        log.debug(f"Wiping session total bytes for {username}...")

    elif system_name:
        if not sqlh.check_if_table_exists(
            SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ) or sqlh.check_if_table_empty(
            SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
        ):
            log.debug(
                f"wipe_session_total_bytes: Table {SYSTEM_STATE_TABLE_NAME} empty or does not exist."
            )
            return 0

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    if username:
        cur.execute(
            f"""
            UPDATE {USAGE_TRACKING_TABLE_NAME}
            SET session_total_bytes = ?
            WHERE username = ?
            """,
            (
                0,
                username,
            ),
        )
        log.debug(
            f"wipe_session_total_bytes: Wiped session_total_bytes for user {username}"
        )
    elif system_name:
        cur.execute(
            f"""
            UPDATE {SYSTEM_STATE_TABLE_NAME}
            SET session_total_bytes = ?
            WHERE system_name = ?
            """,
            (
                0,
                system_name,
            ),
        )
        log.debug(
            f"wipe_session_total_bytes: Wiped session_total_bytes for system {system_name}"
        )

    # Should really add error checking here...

    con.commit()
    con.close()


def usage_daily_wipe(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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

    cur.execute(
        """
        UPDATE system_state
        SET total_daily_bytes = 0
        """,
    )
    con.commit()
    con.close()

    log.info("Daily wipe complete.")


def usage_monthly_wipe(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
        UPDATE users
        SET monthly_usage_bytes = 0
        """,
    )

    cur.execute(
        """
        UPDATE system_state
        SET total_monthly_bytes = ?, total_system_monthly_bytes = ?
        """,
        (0, 0),
    )
    con.commit()
    con.close()

    log.info("Monthly wipe complete.")


def fetch_daily_system_bytes(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_daily_bytes_usage: Table {SYSTEM_STATE_TABLE_NAME} empty or does not exist."
        )
        return 0

    try:
        config = fetch_active_config()
    except ConfigNameError as e:
        raise DBInitializationError(f"Databases failed to iniitalize: {e}")

    system_name = config.get("system_name")

    if config.get("system_name") is None:
        raise SystemStateError(
            "fetch_daily_system_bytes: System state database left in corrputed state."
        )

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    # Need to add try blocks and error catching for all of these things at some point.
    try:
        cur = con.cursor()

        cur.execute(
            f"""
            SELECT total_daily_bytes
            FROM {SYSTEM_STATE_TABLE_NAME}
            WHERE system_name = ?
            """,
            (system_name,),
        )
        row = cur.fetchone()
        if row is None:
            log.error(f"ERROR: Operation to fetch daily system bytes failed.")
            return None
        return row[0]
    finally:
        con.close()


def fetch_daily_budget_bytes(db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        SYSTEM_STATE_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_daily_budget_bytes: Table {SYSTEM_STATE_TABLE_NAME} empty or does not exist."
        )
        return 0

    try:
        config = fetch_active_config()
    except ConfigNameError as e:
        log.error(f"fetch_daily_budget_bytes: Failed to update budget bytes: {e}")
        raise

    system_name = config.get("system_name")

    if config.get("system_name") is None:
        raise SystemStateError(
            "fetch_daily_budget_bytes: System state database left in corrputed state."
        )

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    # Need to add try blocks and error catching for all of these things at some point.
    try:
        cur = con.cursor()

        cur.execute(
            f"""
            SELECT daily_budget_bytes
            FROM {SYSTEM_STATE_TABLE_NAME}
            WHERE system_name = ?
            """,
            (system_name,),
        )
        row = cur.fetchone()
        if row is None:
            log.error(
                f"ERROR: Operation to fetch daily budget failed for system {system_name}."
            )
            return None
        return row[0]
    finally:
        con.close()


def fetch_daily_bytes_usage(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_max_daily_usage: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
        )
        return 0

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


def fetch_monthly_bytes_usage(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_monthly_bytes_usage: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
        )
        return 0

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
            SELECT monthly_usage_bytes
            FROM users
            WHERE username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        if row is None:
            log.error(
                f"ERROR: Operation to fetch monthly usage failed for user {username}."
            )
            return None
        return row[0]
    finally:
        con.close()


def fetch_high_speed_quota_for_group_usage(group_name, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    if not sqlh.check_if_table_exists(
        GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_max_daily_usage: Table {GROUP_TABLE_NAME} empty or does not exist."
        )
        return 0

    table_empty = sqlh.check_if_table_empty(GROUP_TABLE_NAME, db_path)

    if table_empty:
        log.error(
            f"Failed fetching quota_bytes for group {group_name}: no groups exist."
        )
        raise GroupMissingError(f"No groups exist.")

    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()

    cur.execute(
        """
    SELECT high_speed_quota
    FROM groups
    WHERE group_name = ?
    """,
        (group_name,),
    )

    quota_bytes = cur.fetchone()

    con.commit()
    con.close()

    if quota_bytes is None:
        log.error(
            f"ERROR: Operation to fetch high speed data quota failed for group {group_name}."
        )
        raise GroupNameError(
            f"Quota bytes undefined for group {group_name}: group quota status indeterminate."
        )

    return quota_bytes[0]


def fetch_high_speed_quota_for_user_usage(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    if not sqlh.check_if_table_exists(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(
        USAGE_TRACKING_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ):
        log.debug(
            f"fetch_max_daily_usage: Table {USAGE_TRACKING_TABLE_NAME} empty or does not exist."
        )
        return 0
    if not sqlh.check_if_table_exists(
        GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_max_daily_usage: Table {GROUP_TABLE_NAME} empty or does not exist."
        )
        return 0
    if not sqlh.check_if_table_exists(
        GROUP_USERS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH
    ) or sqlh.check_if_table_empty(GROUP_USERS_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH):
        log.debug(
            f"fetch_max_daily_usage: Table {GROUP_USERS_TABLE_NAME} empty or does not exist."
        )
        return 0

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

    table_empty = sqlh.check_if_table_empty(GROUP_TABLE_NAME, db_path)

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


def check_if_user_in_any_group(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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


def check_which_group_user_is_in(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
        SELECT group_name
        FROM users u
        JOIN group_users gu ON u.id = gu.user_id
        JOIN groups g ON g.id = gu.group_id
        WHERE u.username = ?
        """,
        (username,),
    )
    res = cur.fetchone()
    con.close()
    if len(res) < 1:
        return None
    return res[0]


def check_if_user_exists(username, table_name=USAGE_TRACKING_TABLE_NAME, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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
    # log.debug(f"check_if_user_exists: {res}")
    con.close()
    if len(res) < 1:
        return False
    return True


def check_if_value_in_table(value, value_type, table_name, db_path):
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        f"""
        SELECT {value_type}
        FROM {table_name}
        WHERE {value_type} = ?
        """,
        (value,),
    )
    res = cur.fetchall()
    con.close()
    if len(res) < 1:
        return False
    return True


def check_if_group_exists(group_name, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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


def check_if_user_logged_in(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
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


def check_if_user_exceeds_quota(username, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
        SELECT exceeds_quota
        FROM users
        WHERE username = ?
        """,
        (username,),
    )
    res = cur.fetchone()
    con.close()
    if res is None:
        raise UserNameError(f"User {username} does not exist.")

    exceeds_quota = res[0]
    return bool(exceeds_quota)


def insert_ip_addr_ip_db(user_ip, user_mac, now, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO ip_timeouts (ip_addr, mac_addr, last_timestamp)
    VALUES (?, ?, ?)
    """,
        (
            user_ip,
            user_mac,
            now,
        ),
    )
    con.commit()
    con.close()

    log.debug(f"Inserted user at {user_ip} into ip_timeouts table.")


def select_ip_row(ip_addr, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute(
        """
        SELECT *
        FROM ip_timeouts
        WHERE ip_addr = ?
        """,
        (ip_addr,),
    )
    row = cur.fetchone()
    con.close()
    return row


def update_ip_db(ip_addr, now, timeout, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    row = select_ip_row(ip_addr)

    if row:
        columns = [column for column in sqlh.fetch_all_columns("ip_timeouts", db_path)]
        set_clause = ", ".join(f"{col} = ?" for col in columns)
        values = list(row)
        values[3] = now
        values[4] = timeout

        con = sqlite3.connect(
            db_path, timeout=30, isolation_level=None
        )  # Connects to database
        cur = con.cursor()
        cur.execute(
            f"""
            UPDATE ip_timeouts
            SET {set_clause}
            WHERE ip_addr = ?
            """,
            values + [ip_addr],
        )
        con.commit()
        con.close()
        log.debug(f"Updated ip_timeouts table for user at {ip_addr}.")
    else:
        raise sqlh.IPAddressError(
            f"Failed attempting to update ip timeouts table for IP address {ip_addr}: Device does not exist."
        )


def delete_ip_neigh(ip_addr, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    con = sqlite3.connect(
        db_path, timeout=30, isolation_level=None
    )  # Connects to database
    cur = con.cursor()
    cur.execute("DELETE FROM ip_timeouts WHERE ip_addr = ?", (ip_addr,))
    con.commit()
    con.close()
    log.debug(f"Deleted {ip_addr} from ip_timeouts table.")


def update_user_quota_information(username, exceeds_quota, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    if check_if_user_exists(username):

        quota_bool = OVER_QUOTA if exceeds_quota else NOT_OVER_QUOTA

        con = sqlite3.connect(
            db_path, timeout=30, isolation_level=None
        )  # Connects to database
        cur = con.cursor()

        cur.execute(
            f"""
            UPDATE users
            SET exceeds_quota = ?
            WHERE username = ?
            """,
            (quota_bool, username),
        )

        if exceeds_quota:
            log.info(f"User {username} quota information updated: user exceeds quota.")
        else:
            log.info(f"User {username} quota information updated: user under quota.")

        con.commit()
        con.close()
    else:
        raise UserNameError(
            f"Failed attempting to log out user {username}: User does not exist."
        )
