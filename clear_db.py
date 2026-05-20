import sqlite3
import pathlib
import sys
import os

# Ensure project root is in the Python path
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from database.db import get_connection, DEFAULT_DB_PATH, init_db

def clear_database():
    print(f"Connecting to database at: {DEFAULT_DB_PATH}")
    if not DEFAULT_DB_PATH.exists():
        print("Database file does not exist. Initializing a new one...")
        init_db(DEFAULT_DB_PATH)
        print("Done.")
        return

    conn = get_connection(DEFAULT_DB_PATH)
    cursor = conn.cursor()

    try:
        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = [row[0] for row in cursor.fetchall()]

        print(f"Found tables: {', '.join(tables)}")

        with conn:
            # Disable foreign keys temporarily
            conn.execute("PRAGMA foreign_keys=OFF;")
            
            for table in tables:
                print(f"Clearing table: {table}...")
                conn.execute(f"DELETE FROM {table};")
            
            # Reset autoincrement sequences
            print("Resetting autoincrement sequences...")
            conn.execute("DELETE FROM sqlite_sequence;")
            
            # Re-enable foreign keys
            conn.execute("PRAGMA foreign_keys=ON;")

        print("Database cleared successfully.")
        
        # Re-initialize to ensure essential metadata (like install_time) is present
        print("Re-initializing essential metadata...")
        init_db(DEFAULT_DB_PATH)
        print("Initialization complete.")

    except Exception as e:
        print(f"Error clearing database: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    clear_database()
