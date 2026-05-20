import os
import time

print("[MALICIOUS-LIKE] Fake ransomware simulation started")

target_folder = "demo_files"
os.makedirs(target_folder, exist_ok=True)

# Create demo files
for i in range(5):
    with open(f"{target_folder}/file{i}.txt", "w") as f:
        f.write("Important data")

# Fake encryption rename only
for file in os.listdir(target_folder):
    old_path = os.path.join(target_folder, file)
    new_path = old_path + ".locked"

    os.rename(old_path, new_path)

    print(f"[LOCKED] {file}")

    time.sleep(1)

print("[NOTE] Files are NOT encrypted. Rename only.")