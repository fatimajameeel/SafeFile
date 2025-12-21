import sqlite3

DB_PATH = "safefile.db"  # change if yours is in a folder


def column_exists(conn, table_name: str, column_name: str) -> bool:
    cols = conn.execute(f"PRAGMA table_info({table_name});").fetchall()
    return any(col[1] == column_name for col in cols)  # col[1] = name


def main():
    conn = sqlite3.connect(DB_PATH)

    if column_exists(conn, "file", "analysis_json"):
        print("✅ Column 'analysis_json' already exists. Nothing to do.")
        return

    conn.execute("ALTER TABLE file ADD COLUMN analysis_json TEXT;")
    conn.commit()
    conn.close()
    print("✅ Added column 'analysis_json' successfully.")


if __name__ == "__main__":
    main()
