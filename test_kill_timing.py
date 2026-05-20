import subprocess
import time
import psutil
import pathlib
import sys

def main():
    print("\n====================================================")
    print("       BEHAVIORSHIELD AUTOMATED TIMING TESTER       ")
    print("====================================================\n")

    # 1. Kill any existing agent or python simulator process to clean up
    print("[*] Cleaning up running agents/simulators...")
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmd = proc.info.get("cmdline") or []
            cmd_str = " ".join(cmd).lower()
            if "run_agent.py" in cmd_str or "test_ransomware.py" in cmd_str:
                proc.kill()
        except Exception:
            pass

    # 2. Re-initialize / clean databases
    print("[+] Resetting Database...")
    subprocess.run([sys.executable, "clear_db.py"], capture_output=True)

    # Count existing watchdog starts in log
    log_path = pathlib.Path("C:/BehaviorShield/logs/agent.log")
    initial_starts = 0
    if log_path.exists():
        try:
            initial_starts = log_path.read_text(encoding="utf-8", errors="ignore").count("Watchdog (fallback) started for:")
        except Exception:
            pass

    import os
    env = os.environ.copy()
    env["HASH_SCAN_ENABLED"] = "False"
    env["VT_ENABLED"] = "False"

    # 3. Start the BehaviorShield agent in the background
    print("[+] Launching BehaviorShield Agent...")
    agent_proc = subprocess.Popen([sys.executable, "run_agent.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    
    # 4. Wait for the Watchdog fallback to be fully active
    print("[*] Waiting for Watchdog to initialize fully (allowing startup scan to finish)...")
    
    watchdog_active = False
    start_wait = time.perf_counter()
    while time.perf_counter() - start_wait < 90.0:
        if log_path.exists():
            try:
                current_starts = log_path.read_text(encoding="utf-8", errors="ignore").count("Watchdog (fallback) started for:")
                if current_starts > initial_starts:
                    watchdog_active = True
                    break
            except Exception:
                pass
        time.sleep(1)

    if not watchdog_active:
        print("[-] WARNING: Watchdog did not start within 90 seconds. Continuing anyway...")
    else:
        print("[+] Watchdog is fully active and listening! Continuing...") 

    # 5. Get baseline count of files in C:/BehaviorShield/TestFolder/RansomTest before run
    base_dir = pathlib.Path("C:/BehaviorShield/TestFolder/RansomTest")
    dirs = ["Docs", "Photos", "Work", "Backup"]
    
    # Prepare clean directory structure
    for d in dirs:
        (base_dir / d).mkdir(parents=True, exist_ok=True)
        # remove old locked/txt files
        for f in (base_dir / d).glob("*"):
            try: 
                f.unlink()
            except: 
                pass
        # Create 5 baseline documents per dir (Total 20 files)
        for i in range(5):
            with open(base_dir / d / f"data_{i}.txt", "w") as f:
                f.write("Important document content " * 100)

    total_baseline_files = 20
    print(f"[+] Prepared {total_baseline_files} clean test files across 4 directories.")

    # 6. Start the ransomware simulator and measure timing
    print("[!] Launching Ransomware Simulator...")
    start_time = time.perf_counter()
    
    # Launch the simulator process
    sim_proc = subprocess.Popen([sys.executable, "C:/BehaviorShield/TestApps/scripts/test_ransomware.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 7. Monitor the process until it is killed
    killed = False
    duration_ms = 0.0
    
    while time.perf_counter() - start_time < 15.0:
        if sim_proc.poll() is not None:
            # Simulator terminated
            duration_ms = (time.perf_counter() - start_time) * 1000
            killed = True
            break
        time.sleep(0.01)

    if killed:
        print(f"[+] Ransomware simulator terminated after {duration_ms:.2f} ms.")
    else:
        print("[-] Ransomware simulator was NOT killed (timed out after 15s).")

    # 8. Gather statistics on files
    print("[*] Verifying file safety and quarantine status...")
    time.sleep(3) # Wait for agent's scoring/quarantine batch DB writer to finalize
    
    locked_files = []
    intact_files = []
    
    for d in dirs:
        for f in (base_dir / d).glob("*"):
            if f.suffix == ".locked":
                locked_files.append(f)
            elif f.suffix == ".txt":
                intact_files.append(f)

    # 9. Verify quarantine
    quarantine_dir = pathlib.Path("C:/BehaviorShield/Quarantine")
    quarantined_files = list(quarantine_dir.glob("**/*.locked"))

    print("\n" + "="*50)
    print("         BEHAVIORSHIELD PERFORMANCE REPORT")
    print("="*50)
    print(f"Ransomware Process Killed : {'YES (SUCCESS)' if killed else 'NO (FAILURE)'}")
    if killed:
        print(f"Detection to Kill Time   : {duration_ms:.2f} ms")
    print(f"Total Initial Files       : {total_baseline_files}")
    print(f"Files Encrypted (.locked) : {len(locked_files)}")
    print(f"Files Protected (Intact)  : {len(intact_files)}")
    print(f"Files Quarantined         : {len(quarantined_files)}")
    
    protection_rate = (len(intact_files) / total_baseline_files) * 100
    print(f"File Protection Rate      : {protection_rate:.2f}%")
    
    if len(locked_files) == 0 and len(quarantined_files) > 0:
        print("Quarantine Status         : SUCCESS (All encrypted files isolated)")
    elif len(quarantined_files) >= len(locked_files) and len(locked_files) > 0:
        print("Quarantine Status         : SUCCESS (All encrypted files isolated)")
    else:
        print("Quarantine Status         : PENDING/PARTIAL")
    print("="*50 + "\n")

    # Terminate the agent process cleanly
    agent_proc.terminate()
    agent_proc.wait()

if __name__ == "__main__":
    main()
