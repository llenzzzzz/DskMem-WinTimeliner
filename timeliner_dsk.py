import subprocess
import os
from datetime import datetime
import csv

bin_directory = input("TSK Bin Folder Path\n > ")
eo1_directory = input("\nDISK IMG File Path (.E01)\n > ")
csv_directory = input("\nWorking Directory\n > ")

args = [eo1_directory]
command = subprocess.Popen([f"{bin_directory}\mmls.exe"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')

print("\n[RUNNING] mmls.exe")

for line in command.stdout:
    line = line.strip()
    if 'NTFS' in line:
        offset = int(line.split()[2])
        break

print(f"[DONE] Obtained offset value for NTFS filesystem: {offset}")

args = ["-m", "C:/", "-r", "-l", "-i", "ewf", "-f", "ntfs", "-o", str(offset), eo1_directory]

with open(fr"{bin_directory}\bodyfile.txt", "w", encoding='utf-8') as file:
    command = subprocess.Popen([fr"{bin_directory}\fls.exe"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
    
    print("[RUNNING] fls.exe")

    for line in command.stdout:
        line.strip()
        file.write(line)
    
    print("[DONE] Finished scanning for files and directories within the filesystem.")

args = [f"{bin_directory}\mactime.pl", "-b", fr"{bin_directory}\bodyfile.txt"]

with open(fr"{bin_directory}\timeline.txt", "w", encoding='utf-8') as file:
    command = subprocess.Popen(["perl"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
    
    print("[RUNNING] mactime.pl")

    for line in command.stdout:
        line.strip()
        file.write(line)

    print("[DONE] Finished analysis and timeline generation.")

stdout, _ = command.communicate()

headers = ["Local Date", "Local Time", "Size (Bytes)", "Activity Type", "Unix Permissions", "User Id", "Group Id", "inode", "File Name"]

with open(fr"{bin_directory}\timeline.txt", 'r') as infile:
    lines = infile.readlines()

with open(f"{csv_directory}\dsk_output.csv", mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(headers)

    date = ""
    time = ""

    combined = []

    for line in lines:
        parts = line.split()
        if len(parts) >= 11 and parts[0][0].isalpha():
            date = datetime.strptime(' '.join(parts[1:4]), "%b %d %Y").strftime("%d/%m/%Y")
            time = datetime.strptime(parts[4], "%H:%M:%S").strftime("%H:%M:%S")
            combined.append([date] + [time] + parts[5:11] + [' '.join(parts[11:])])
        else:
            combined.append([date] + [time] + parts[0:6] + [' '.join(parts[6:])])

    sorted_combined = sorted(combined, key=lambda x: (x[0], x[1]), reverse=True)
    writer.writerows(sorted_combined)

os.remove(fr"{bin_directory}\bodyfile.txt")
os.remove(fr"{bin_directory}\timeline.txt")
print("[DONE] Removed temporary files.")

print(f"\nForensic Image Timeline (DISK) saved as dsk_output.csv at {csv_directory}")