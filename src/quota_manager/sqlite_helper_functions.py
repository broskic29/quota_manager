import sqlite3

RADIUS_DB_PATH = "/var/lib/radius/freeradius.db"
USAGE_TRACKING_DB_PATH = "/var/lib/radius/usage_tracking.db"
DEFAULT_SCHEMA_PATH = "/etc/freeradius3/mods-config/sql/main/sqlite/schema.sql"


def check_if_table_exists(table_name, db_path=RADIUS_DB_PATH):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,)
    )
    return cur.fetchone()


def delete_table(table_name, db_path):
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    cur.execute(f"DROP TABLE IF EXISTS {table_name};")

    con.commit()
    con.close()


def fetch_all_tables(db_path):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    res = cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    return res.fetchall()


def fetch_all_columns(db_path, table):
    con = sqlite3.connect(db_path)
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


def print_all_radius_user_information(db_path=RADIUS_DB_PATH):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    res = cur.execute("SELECT username, attribute, value FROM radcheck;")
    rows = res.fetchall()
    for row in rows:
        print(row)


def print_all_radius_accounting_information(db_path=RADIUS_DB_PATH):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    res = cur.execute("SELECT username, attribute, value FROM radacct;")
    rows = res.fetchall()
    for row in rows:
        print(row)


def print_all_table_information(table, db_path=USAGE_TRACKING_DB_PATH):
    con = sqlite3.connect(db_path)  # Connects to database
    cur = con.cursor()
    res = cur.execute(f"SELECT * FROM {table};")
    rows = res.fetchall()
    for row in rows:
        print(row)
