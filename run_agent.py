"""
run_agent.py
------------
Top-level launcher for the BehaviorShield detection agent.
Must be run as Administrator.

Usage:
    python run_agent.py
"""

import sys
import pathlib

# Make sure the project root is on sys.path regardless of where
# the script is invoked from.
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.main import main

if __name__ == "__main__":
    while True:
        should_restart = main()
        if not should_restart:
            break
        print("\n" + "="*60)
        print("  RESTARTING BEHAVIORSHIELD...")
        print("="*60 + "\n")
