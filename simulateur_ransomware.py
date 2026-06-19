import os
import time
import pathlib

print("====================================================")
# Keep process name recognizable
print("       BEHAVIORSHIELD RANSOMWARE SIMULATOR")
print("====================================================\n")

test_dir = pathlib.Path("C:/BehaviorShield/TestFolder/RansomTest")
test_dir.mkdir(parents=True, exist_ok=True)

# 1. Clean previous files
print("[*] Cleaning up test folder...")
for f in test_dir.glob("*"):
    try:
        f.unlink()
    except Exception as e:
        print(f"Failed to delete {f.name}: {e}")

# 2. Create 15 mock documents
print("[*] Creating 15 mock documents...")
files = []
for i in range(15):
    p = test_dir / f"user_document_{i}.txt"
    p.write_text("This is a confidential and highly important user file. Please do not modify this content. " * 100)
    files.append(p)

print("[+] Created 15 files successfully.")
print("[*] Waiting 2 seconds for stability...")
time.sleep(2)

# 3. Simulate encryption by renaming
print("\n[!] STARTING SIMULATED MASS ENCRYPTION (renaming to .locked)...")
for i, f in enumerate(files):
    new_path = f.with_suffix(".locked")
    try:
        os.rename(f, new_path)
        print(f"    -> [{i+1}/15] Encrypted: {f.name} -> {new_path.name}")
        time.sleep(0.1)  # 100ms delay to simulate processing time
    except Exception as e:
        print(f"\n[X] Action failed or blocked: {e}")
        print("[+] SUCCESS: The process was likely terminated/blocked by BehaviorShield!")
        break

time.sleep(1)
print("\n[-] Simulation finished. If you reached this line, check if BehaviorShield.exe is running as Admin.")
