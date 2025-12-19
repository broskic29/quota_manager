import sqlite3
from datetime import datetime, timezone, timedelta


def connect_to_db(db_path="/var/lib/radius/freeradius.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    return con  # Creates cursor object


def print_all_tables(db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    res = cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = res.fetchall()
    print(tables)


def print_all_columns(db_path="/var/lib/radius/freeradius.db", table="radcheck"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    res = cur.execute(f"PRAGMA table_info({table});")
    columns = res.fetchall()
    for col in columns:
        print(col)


def print_user_information(db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    res = cur.execute("SELECT username, attribute, value FROM radcheck;")
    rows = res.fetchall()
    for row in rows:
        print(row)


def print_table_rows(
    db_path="/var/lib/radius/freeradius.db",
    table="radcheck",
    row_list=["username", "attribute", "value"],
):
    con = connect_to_db(db_path)
    cur = con.cursor()
    row_query = ", ".join(row_list)
    res = cur.execute(f"SELECT {row_query} FROM {table};")
    rows = res.fetchall()
    for row in rows:
        print(row)


def insert_user(
    username,
    password,
    db_path="/var/lib/radius/freeradius.db",
):
    con = connect_to_db(db_path)
    cur = con.cursor()
    cur.execute(
        """
    INSERT INTO radcheck (username, attribute, op, value)
    VALUES (?, ?, ?, ?)
    """,
        (f"{username}", "Cleartext-Password", ":=", f"{password}"),
    )
    con.commit()
    con.close()


def delete_user(
    username,
    db_path="/var/lib/radius/freeradius.db",
):
    con = connect_to_db(db_path)
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


# def modify_user(username, field, value):


def print_daily_usage(db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    # Get the first day of the current month at midnight UTC
    now = datetime.now(timezone.utc)
    start_of_day = datetime(now.year, now.month, now.day, 1, tzinfo=timezone.utc)
    ts_start = int(start_of_day.timestamp())  # convert to Unix timestamp
    cur = con.cursor()
    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE acctstarttime >= ?
        GROUP BY username
        """,
        (ts_start,),
    )
    rows = cur.fetchall()
    for username, total_bytes in rows:
        print(f"{username}: {total_bytes / 1024 / 1024:.2f} MB")
    con.commit()
    con.close()


def print_daily_usage_for_user(username, db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    # Get the first day of the current month at midnight UTC
    now = datetime.now(timezone.utc)
    start_of_day = datetime(now.year, now.month, now.day, 1, tzinfo=timezone.utc)
    ts_start = int(start_of_day.timestamp())  # convert to Unix timestamp
    cur = con.cursor()
    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE username = ?
          AND acctstarttime >= ?
        GROUP BY username
        """,
        (username, ts_start),
    )
    rows = cur.fetchall()
    for username, total_bytes in rows:
        print(f"{username}: {total_bytes / 1024 / 1024:.2f} MB")
    con.commit()
    con.close()


def check_daily_usage(db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    # Note: will have to modify this to calculate from billing date
    # Return a json object
    # Get the first day of the current month at midnight UTC
    now = datetime.now(timezone.utc)
    start_of_day = datetime(now.year, now.month, now.day, 1, tzinfo=timezone.utc)
    ts_start = int(start_of_day.timestamp())  # convert to Unix timestamp
    cur = con.cursor()
    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE acctstarttime >= ?
        GROUP BY username
        """,
        (ts_start,),
    )
    rows = cur.fetchall()
    usage_dict = {username: total_bytes / 1024 / 1024 for username, total_bytes in rows}
    con.commit()
    con.close()
    return usage_dict


def check_daily_usage_for_user(username, db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    # Get the first day of the current month at midnight UTC
    now = datetime.now(timezone.utc)
    start_of_day = datetime(now.year, now.month, now.day, 1, tzinfo=timezone.utc)
    ts_start = int(start_of_day.timestamp())  # convert to Unix timestamp
    cur = con.cursor()
    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE username = ?
          AND acctstarttime >= ?
        GROUP BY username
        """,
        (username, ts_start),
    )
    rows = cur.fetchall()
    usage_dict = {username: total_bytes / 1024 / 1024 for username, total_bytes in rows}
    con.commit()
    con.close()
    return usage_dict


def check_if_daily_usage_exceeds_quota_for_user(
    username, quota, db_path="/var/lib/radius/freeradius.db"
):
    con = connect_to_db(db_path)
    cur = con.cursor()
    # Get the first day of the current month at midnight UTC
    now = datetime.now(timezone.utc)
    start_of_day = datetime(now.year, now.month, now.day, 1, tzinfo=timezone.utc)
    ts_start = int(start_of_day.timestamp())  # convert to Unix timestamp
    cur = con.cursor()
    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE username = ?
            AND acctstarttime >= ?
        GROUP BY username
        """,
        (username, ts_start),
    )
    rows = cur.fetchall()
    total_bytes = rows[0][1]
    con.commit()
    con.close()
    if total_bytes >= quota:
        return True
    else:
        return False


def print_monthly_usage(db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    # Note: will have to modify this to calculate from billing date
    # Get the first day of the current month at midnight UTC
    now = datetime.now(timezone.utc)
    first_of_month = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    ts_start = int(first_of_month.timestamp())  # convert to Unix timestamp
    cur = con.cursor()
    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE acctstarttime >= ?
        GROUP BY username
        """,
        (ts_start,),
    )
    rows = cur.fetchall()
    for username, total_bytes in rows:
        print(f"{username}: {total_bytes / 1024 / 1024:.2f} MB")
    con.commit()
    con.close()


def print_monthly_usage_for_user(username, db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    # Get the first day of the current month at midnight UTC
    now = datetime.now(timezone.utc)
    first_of_month = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    ts_start = int(first_of_month.timestamp())  # convert to Unix timestamp
    cur = con.cursor()
    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE username = ?
          AND acctstarttime >= ?
        GROUP BY username
        """,
        (username, ts_start),
    )
    rows = cur.fetchall()
    for username, total_bytes in rows:
        print(f"{username}: {total_bytes / 1024 / 1024:.2f} MB")
    con.commit()
    con.close()


def check_monthly_usage(db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    # Note: will have to modify this to calculate from billing date
    # Return a json object
    # Get the first day of the current month at midnight UTC
    now = datetime.now(timezone.utc)
    first_of_month = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    ts_start = int(first_of_month.timestamp())  # convert to Unix timestamp
    cur = con.cursor()
    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE acctstarttime >= ?
        GROUP BY username
        """,
        (ts_start,),
    )
    rows = cur.fetchall()
    usage_dict = {username: total_bytes / 1024 / 1024 for username, total_bytes in rows}
    con.commit()
    con.close()
    return usage_dict


def check_monthly_usage_for_user(username, db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    # Get the first day of the current month at midnight UTC
    now = datetime.now(timezone.utc)
    first_of_month = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    ts_start = int(first_of_month.timestamp())  # convert to Unix timestamp
    cur = con.cursor()
    cur.execute(
        """
        SELECT username, SUM(acctinputoctets + acctoutputoctets) as total_bytes
        FROM radacct
        WHERE username = ?
          AND acctstarttime >= ?
        GROUP BY username
        """,
        (username, ts_start),
    )
    rows = cur.fetchall()
    usage_dict = {username: total_bytes / 1024 / 1024 for username, total_bytes in rows}
    con.commit()
    con.close()
    return usage_dict
