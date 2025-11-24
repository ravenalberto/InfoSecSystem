# database_setup.py
import sqlite3

# Connect to (or create) the database file
conn = sqlite3.connect('CryptoPad.db')
cursor = conn.cursor()

# --- TABLE 1: User_Registration ---
# Formerly "Users". This stores WHO the users are.
cursor.execute('''
CREATE TABLE IF NOT EXISTS User_Registration (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt          BLOB NOT NULL,
    date_registered TEXT
);
''')

# --- TABLE 2: User_Logins (NEW) ---
# This tracks WHEN users access the system.
cursor.execute('''
CREATE TABLE IF NOT EXISTS User_Logins (
    login_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    login_timestamp TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES User_Registration (user_id)
);
''')

# --- TABLE 3: Entries ---
# Stores the diary data. Now links to User_Registration.
cursor.execute('''
CREATE TABLE IF NOT EXISTS Entries (
    entry_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    title         TEXT NOT NULL,
    content       BLOB,
    is_encrypted  INTEGER NOT NULL DEFAULT 0,
    date_modified TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES User_Registration (user_id)
);
''')

conn.commit()
conn.close()

print("Database 'CryptoPad.db' with 3 tables created successfully.")