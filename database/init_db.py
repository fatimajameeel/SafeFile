import sqlite3
import os

# Get the absolute path of this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# safefile.db should be created in the PROJECT ROOT
DB_PATH = os.path.join(BASE_DIR, "..", "safefile.db")

# schema.sql is inside this folder
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")


def init_db():
    # 1. Read schema.sql
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    # 2. Connect to (create) safefile.db
    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.cursor()
        cursor.executescript(schema_sql)
        conn.commit()
        print("Database initialized successfully at:", DB_PATH)
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
