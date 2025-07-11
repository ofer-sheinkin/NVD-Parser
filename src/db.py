import sqlite3
import os

def get_db_connection():
    db_path = os.getenv("SQLITE_DB_PATH", os.path.join("data", "cves.db"))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn 