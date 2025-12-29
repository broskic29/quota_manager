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
    tables = res.fetchall()
    tables = [table[1] for table in tables]
    return tables


def fetch_all_columns(db_path="/var/lib/radius/freeradius.db", table="radcheck"):
    con = connect_to_db(db_path)
    cur = con.cursor()
    res = cur.execute(f"PRAGMA table_info({table});")
    columns = res.fetchall()
    columns = [column[1] for column in columns]
    return columns
