r"""
run_backend.py
--------------
Convenience script to start the Flask backend from the project root.
Run from: c:\Users\Invictus\Desktop\project\pfa
"""
import sys
import pathlib

# Ensure project root is in the Python path
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from database.db import init_db
from agent.config import DB_PATH
from backend.app import create_app

if __name__ == "__main__":
    # Init DB if not done already
    init_db(DB_PATH)

    import threading
    import os
    import time

    app = create_app(str(DB_PATH))
    
    def start_flask():
        # Disable the reloader as it spawns child processes that are harder to kill from here
        app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)

    print("\n[EDR]  BehaviorShield Backend - http://localhost:5000")
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    
    import msvcrt
    print("[INFO] Press 'q' to stop the backend immediately.\n")

    try:
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch in (b'\x00', b'\xe0'):
                    msvcrt.getch()
                    continue
                try:
                    char = ch.decode('utf-8').lower()
                except UnicodeDecodeError:
                    continue
                    
                if char == 'q':
                    print("[INFO] Stopping backend...")
                    os._exit(0)
            time.sleep(0.1)
    except (KeyboardInterrupt, EOFError):
        print("\n[INFO] Exiting...")
        os._exit(0)
