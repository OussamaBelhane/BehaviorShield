import sqlite3
import os
import sys

# Add project root to path to use project configs
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from agent.config import DB_PATH
except ImportError:
    # Fallback if pathing is weird
    DB_PATH = "C:/BehaviorShield/behaviorshield.db"

def dedup_alerts():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    print(f"Connecting to database: {DB_PATH}")
    
    # We want to find duplicates based on (pid, message, timestamp down to the second)
    # SQLite strftime('%Y-%m-%d %H:%M:%S', timestamp) gives us second-level granularity
    
    find_dups_q = """
    SELECT pid, message, strftime('%Y-%m-%d %H:%M:%S', timestamp) as ts_sec, COUNT(*) as cnt
    FROM alerts
    GROUP BY pid, message, ts_sec
    HAVING cnt > 1
    """
    
    try:
        dups = conn.execute(find_dups_q).fetchall()
        total_removed = 0
        
        for row in dups:
            # Find all ids for this group
            # We filter by the same ts_sec
            ids_q = """
            SELECT id FROM alerts 
            WHERE pid = ? AND message = ? AND strftime('%Y-%m-%d %H:%M:%S', timestamp) = ?
            ORDER BY id ASC
            """
            ids_rows = conn.execute(ids_q, (row['pid'], row['message'], row['ts_sec'])).fetchall()
            ids = [r['id'] for r in ids_rows]
            
            # Keep the first (lowest ID), delete the rest
            to_delete = ids[1:]
            if to_delete:
                placeholders = ','.join(['?'] * len(to_delete))
                conn.execute(f"DELETE FROM alerts WHERE id IN ({placeholders})", to_delete)
                total_removed += len(to_delete)
        
        conn.commit()
        print(f"Done. Removed {total_removed} duplicate alerts.")
        
    except Exception as e:
        print(f"Error during deduplication: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    dedup_alerts()
