import sqlite3


def connect_to_db(db_path="/var/lib/radius/freeradius.db"):
    con = sqlite3.connect(db_path)  # Connects to database
    return con  # Creates cursor object


def check_if_table_exists(table_name, db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,)
    )
    return cur.fetchone()


def fetch_all_tables(db_path="/var/lib/radius/freeradius.db"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    res = cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    return res.fetchall()


def fetch_all_columns(db_path="/var/lib/radius/freeradius.db", table="radcheck"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    res = cur.execute(f"PRAGMA table_info({table});")
    columns = res.fetchall()
    columns = [column[1] for column in columns]
    return columns


def update_field(username, password, table, field, value, db_path):
    con = sqlite3.connect(db_path)
    cursor = con.cursor()

    query = f"""
        UPDATE {table}
        SET {field} = ?
        WHERE username = ? AND password = ?;
    """

    cursor.execute(query, (value, username, password))
    con.commit()
    con.close()


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
