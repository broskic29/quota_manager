import sqlite3

con = sqlite3.connect("clients.db")  # Creates database

cur = con.cursor()  # Creates cursor object

# Creates a table called "clients" with columns as listed
cur.execute("CREATE TABLE clients(mac_address, ip_address, mac_group)")

# Database resolution, grabs the first name from the sqlite_master
# table
res = cur.execute("SELECT name FROM sqlite_master")

# Fetches the first entry's name
res.fetchone()

# Execute a more complicated SQL statement. This one inserts the given
# tuple into clients.db as a row.
cur.execute(
    """ INSERT INTO clients VALUES
            ('8A:DC:3A:5B:6C', '192.168.2.156', 'admin')
"""
)

# After every "transaction"
con.commit()

# Creates a resolution object to pull out all mac addresses
# as a tuple
res = cur.execute("SELECT mac_address FROM clients")

# Pulls out all mac addresses as a tuple
res.fetchall()

# Used to contain many tuples that can then be inserted en masse.
# always use the "?" symbol to represent python data that will
# be inserted, corresponds to however many columns there are.
data = [
    ("82:D5:31:34:AC", "192.168.2.157", "admin"),
    ("AB:AC:3A:5C:69", "192.168.2.159", "computer_lab"),
    ("AB:AC:B1:AA:91", "192.168.2.160", "computer_lab"),
]
cur.executemany("INSERT INTO clients VALUES(?, ?, ?)", data)
con.commit()

# Can be iterated over, this command pulls out a tuple containing
# the mac_address column and the mac_group for each row.
for row in cur.execute("SELECT mac_address, mac_group FROM clients ORDER BY mac_group"):
    print(row)

# Calls con.commit() automatically
with con:
    con.execute("INSERT INTO clients(mac_address) VALUES(?)", ("82:D5:31:37:AD",))

# Calls con.commit() automatically if finishes correctly.
# With an exception, con.rollback() called to restore block to
# beginning of transaction.
try:
    with con:
        con.execute("INSERT INTO clients(mac_address) VALUES(?)", ("82:D5:31:37:AD",))
except sqlite3.IntegrityError:
    print("Couldn't add value twice")

# Ensures that changes were written to disk.
con.close()
