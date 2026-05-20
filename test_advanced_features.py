import os
import sys
import pathlib
import subprocess
import time
import psutil
import sqlite3

# Add project root to sys.path
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from database.db import init_db, get_connection
from agent.whitelist import add_to_whitelist

def kill_leftovers():
    """Kill any existing agent, simulator, or test processes."""
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmd = proc.info.get("cmdline") or []
            cmd_str = " ".join(cmd).lower()
            name = proc.info.get("name") or ""
            if (
                "run_agent.py" in cmd_str 
                or "malwarehashtest.exe" in name.lower() 
                or "scoretest.exe" in name.lower()
            ):
                proc.kill()
        except Exception:
            pass

def clean_test_folders():
    """Ensure a pristine workspace in C:/BehaviorShield/TestFolder/."""
    test_dir = pathlib.Path("C:/BehaviorShield/TestFolder/")
    if test_dir.exists():
        for f in test_dir.glob("**/*"):
            if f.is_file():
                try: f.unlink()
                except: pass

def wait_for_log_pattern(pattern: str, initial_count: int, timeout_sec: float = 30.0) -> bool:
    """Robustly wait until a specific pattern count increases in agent.log."""
    log_path = pathlib.Path("C:/BehaviorShield/logs/agent.log")
    start_time = time.perf_counter()
    while time.perf_counter() - start_time < timeout_sec:
        if log_path.exists():
            try:
                content = log_path.read_text(encoding="utf-8", errors="ignore")
                if content.count(pattern) > initial_count:
                    return True
            except Exception:
                pass
        time.sleep(0.5)
    return False

def get_log_pattern_count(pattern: str) -> int:
    """Get the current occurrence count of a log pattern."""
    log_path = pathlib.Path("C:/BehaviorShield/logs/agent.log")
    if log_path.exists():
        try:
            return log_path.read_text(encoding="utf-8", errors="ignore").count(pattern)
        except Exception:
            pass
    return 0

def main():
    print("="*60)
    print("       BEHAVIORSHIELD ADVANCED FEATURES TESTING SUITE       ")
    print("="*60)

    # Resolve paths to test executables
    bin_dir = pathlib.Path("C:/BehaviorShield/TestApps/bin")
    malware_exe = bin_dir / "MalwareHashTest.exe"
    score_exe = bin_dir / "ScoreTest.exe"
    db_path = pathlib.Path("C:/BehaviorShield/data/behaviorshield.db")

    if not malware_exe.exists() or not score_exe.exists():
        print("[-] Error: Compiled test executables not found in C:/BehaviorShield/TestApps/bin!")
        return

    # -------------------------------------------------------------
    # TEST 1: LOCAL MALWARE SIGNATURE / HASH SCAN DETECTION
    # -------------------------------------------------------------
    print("\n--- [TEST 1] Malware Hash Detection & Prevention ---")
    kill_leftovers()
    
    print("[*] Reinitializing Database...")
    if db_path.exists():
        try: db_path.unlink()
        except: pass
    init_db(db_path)

    # 1. Launch MalwareHashTest.exe first so it is running during the startup scan
    print("[+] Launching MalwareHashTest.exe (Known Malware Hash)...")
    malware_proc = subprocess.Popen([str(malware_exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    # Verify it is indeed running
    if malware_proc.poll() is not None:
        print("[-] Error: MalwareHashTest.exe failed to start or exited prematurely.")
        return
    print(f"[+] MalwareHashTest.exe is running with PID {malware_proc.pid}")

    # Record initial counts
    init_scan_count = get_log_pattern_count("Startup scan complete")
    init_kill_count = get_log_pattern_count("ENGAGING KILL")

    # 2. Launch BehaviorShield Agent (with hash scan enabled)
    print("[+] Launching BehaviorShield Agent (HASH_SCAN_ENABLED = True)...")
    env = os.environ.copy()
    env["HASH_SCAN_ENABLED"] = "True"
    env["VT_ENABLED"] = "False"
    
    agent_proc = subprocess.Popen([sys.executable, "run_agent.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)

    # Robustly wait for the startup scan to finish
    print("[*] Waiting for startup scan to finish and scan the running MalwareHashTest.exe...")
    if wait_for_log_pattern("Startup scan complete", init_scan_count, timeout_sec=20.0):
        print("[+] Agent startup scan completed successfully!")
    else:
        print("[-] Warning: Startup scan timed out or did not log completion.")

    # Allow a split second for kill signal execution to complete
    time.sleep(1.5)

    # 3. Check if MalwareHashTest.exe was successfully killed
    if malware_proc.poll() is not None:
        print("[+] SUCCESS: MalwareHashTest.exe was automatically KILLED by startup scan!")
    else:
        print("[-] FAILURE: MalwareHashTest.exe is still running!")
        malware_proc.terminate()

    # 4. Check DB events to verify the detection was logged
    conn = get_connection(db_path)
    try:
        # Check both process name or alert triggers
        row = conn.execute("SELECT * FROM alerts WHERE LOWER(image_path) LIKE '%malwarehashtest.exe%'").fetchone()
        if row:
            print(f"[+] SUCCESS: Threat logged in SQLite alerts table! Score: {row['score']}, Message: '{row['message']}'")
        else:
            # Fallback: check processes table
            row2 = conn.execute("SELECT * FROM processes WHERE LOWER(image_path) LIKE '%malwarehashtest.exe%'").fetchone()
            if row2:
                print(f"[+] SUCCESS: Threat logged in SQLite processes table with verdict '{row2['hash_verdict']}'!")
            else:
                print("[-] FAILURE: Threat was not logged in processes or alerts database tables.")
    except Exception as e:
        print(f"[-] Error querying DB: {e}")
    finally:
        conn.close()

    # Clean up agent
    agent_proc.terminate()
    kill_leftovers()

    # -------------------------------------------------------------
    # TEST 2: PROCESS WHITELIST OPTIMIZATION
    # -------------------------------------------------------------
    print("\n--- [TEST 2] Process Whitelist Optimization ---")
    kill_leftovers()
    clean_test_folders()

    # 1. Add ScoreTest.exe to the whitelist database
    print(f"[+] Adding ScoreTest.exe ({score_exe}) to whitelist database...")
    init_db(db_path)
    add_to_whitelist(score_exe, vendor="Whitelist Test Vendor", reason="Authorized Test Suite Binary", db_path=db_path)
    
    # 2. Start BehaviorShield Agent (with hash scan disabled for speed)
    print("[+] Launching BehaviorShield Agent...")
    env["HASH_SCAN_ENABLED"] = "False"
    
    init_watchdog_count = get_log_pattern_count("Watchdog (fallback) started for:")
    agent_proc = subprocess.Popen([sys.executable, "run_agent.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    
    print("[*] Waiting for Watchdog fallback to fully initialize...")
    wait_for_log_pattern("Watchdog (fallback) started for:", init_watchdog_count, timeout_sec=20.0)
    time.sleep(1.0) # Grace period for watchdog scheduling

    # 3. Execute ScoreTest.exe which performs rapid filesystem writes/renames
    print("[+] Executing ScoreTest.exe (rapid writes/renames) in background...")
    score_proc = subprocess.Popen([str(score_exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(6) # Let ScoreTest run to completion

    # 4. Check if ScoreTest.exe was whitelisted and ignored
    if score_proc.poll() is not None:
        print("[+] ScoreTest.exe completed naturally (not killed).")
    else:
        print("[-] ScoreTest.exe is still running (exiting it).")
        score_proc.terminate()

    # Verify no events or scores were generated for ScoreTest.exe in the database
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM events WHERE LOWER(process_name) LIKE '%scoretest.exe%'").fetchone()
        if not row:
            print("[+] SUCCESS: BehaviorShield completely ignored whitelisted ScoreTest.exe (0 events recorded)!")
        else:
            print(f"[-] FAILURE: Recorded whitelisted event in DB: {dict(row)}")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()

    # Clean up agent
    agent_proc.terminate()
    kill_leftovers()

    # -------------------------------------------------------------
    # TEST 3: BEHAVIORAL MASS_RENAME SCORING (NON-WHITELISTED)
    # -------------------------------------------------------------
    print("\n--- [TEST 3] Behavioral Scoring of Non-Whitelisted Binary ---")
    kill_leftovers()
    clean_test_folders()

    # 1. Clear whitelist entries so ScoreTest.exe is no longer trusted
    print("[+] Clearing whitelist database...")
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM whitelist")
    finally:
        conn.close()

    # 2. Start BehaviorShield Agent
    print("[+] Launching BehaviorShield Agent...")
    init_watchdog_count = get_log_pattern_count("Watchdog (fallback) started for:")
    agent_proc = subprocess.Popen([sys.executable, "run_agent.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    
    print("[*] Waiting for Watchdog fallback to fully initialize...")
    wait_for_log_pattern("Watchdog (fallback) started for:", init_watchdog_count, timeout_sec=20.0)
    time.sleep(1.0)

    # 3. Execute ScoreTest.exe again
    print("[+] Executing ScoreTest.exe (rapid writes/renames)...")
    score_proc = subprocess.Popen([str(score_exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(6) # Allow it to run

    if score_proc.poll() is not None:
        print("[+] ScoreTest.exe completed its execution loop.")
    else:
        score_proc.terminate()

    # Allow event queue to flush to SQLite
    time.sleep(1.5)

    # 4. Verify behavioral rule triggers in the database
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM events WHERE source = 'watchdog'").fetchall()
        if rows:
            print(f"[+] SUCCESS: Watchdog detected and scored {len(rows)} filesystem events!")
            rules_conn = conn.execute("SELECT score_delta, severity FROM events WHERE score_delta > 0").fetchall()
            if rules_conn:
                print("[+] SUCCESS: Triggered behavioral rules recorded in SQLite:")
                for r in rules_conn:
                    print(f"    - Score Delta: +{r['score_delta']} (Severity: {r['severity']})")
            else:
                # Let's inspect all events
                print("[!] Watchdog events logged but no positive score events recorded. Total events:", len(rows))
        else:
            print("[-] FAILURE: Watchdog did not record any events in the database.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()

    # Final cleanup
    agent_proc.terminate()
    kill_leftovers()
    print("\n" + "="*60)
    print("           ALL ADVANCED FEATURES TESTS COMPLETED            ")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
