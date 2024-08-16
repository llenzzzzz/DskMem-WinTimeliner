import subprocess
import os
import re
from datetime import datetime
import csv

os.environ["PYTHONIOENCODING"] = "utf-8"

vol3_directory = input("VOL3 File Path (vol.py)\n > ")
raw_directory = input("\nMEM IMG File Path (.raw)\n > ")
csv_directory = input("\nWorking Directory\n > ")

args = [vol3_directory, "-f", raw_directory, "windows.psscan.PsScan"]
command = subprocess.Popen(["python"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')

psscan = []
print("\n[RUNNING] windows.psscan.PsScan")

regex = re.compile(r'^\s*(\d{1,4})\s')
for line in command.stdout:
    line = line.strip()
    parts = line.split()
    if regex.match(line):
        if len(parts) == 12:
            parts[9] = datetime.strptime(parts[9], '%H:%M:%S.%f').strftime('%H:%M:%S')
            psscan.append(parts[8:10] + ["process_creation"] + [parts[2]] + parts[0:2] + ["-"] + parts[3:8] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"])
        else:
            parts[9] = datetime.strptime(parts[9], '%H:%M:%S.%f').strftime('%H:%M:%S')
            psscan.append(parts[8:10] + ["process_creation"] + [parts[2]] + parts[0:2] + ["-"] + parts[3:8] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"])
            parts[11] = datetime.strptime(parts[11], '%H:%M:%S.%f').strftime('%H:%M:%S')
            psscan.append(parts[10:12] + ["process_termination"] + [parts[2]] + parts[0:2] + ["-"] + parts[3:8] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"])

print("[DONE] Finished scanning for process objects.")

dlllist = []
print("[RUNNING] windows.dlllist.DllList")

args = [vol3_directory, "-f", raw_directory, "windows.dlllist.DllList"]
command = subprocess.Popen(["python"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')

for line in command.stdout:
    line = line.strip()
    parts = line.split()
    if regex.match(line):
        if parts[len(parts)-2] not in ["N/A"]:
            parts[len(parts)-2] = datetime.strptime(parts[len(parts)-2], '%H:%M:%S.%f').strftime('%H:%M:%S')
            parts.insert(0, parts[len(parts)-2])
            parts.insert(0, parts[len(parts)-3])
            parts = parts[0:-3]
            parts[7] = " ".join(parts[7:])
            dlllist.append(parts[0:2] + ["dll_load"] + [parts[3]] + [parts[2]] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + [parts[7]])

print("[DONE] Finished scanning for loaded DLLs.")

netscan = []
print("[RUNNING] windows.netscan.NetScan")

args = [vol3_directory, "-f", raw_directory, "windows.netscan.NetScan"]
command = subprocess.Popen(["python"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')

regex = re.compile(r'^0x[0-9a-fA-F]+')
for line in command.stdout:
    line = line.strip()
    parts = line.split()
    if regex.match(line):
        if parts[9] not in ["N/A", "-"]:
            parts[9] = datetime.strptime(parts[9], '%H:%M:%S.%f').strftime('%H:%M:%S')
            netscan.append(parts[8:10] + ["network_connection"] + [parts[7]] + [parts[6]] + ["-"] + ["-"] + [parts[0]] + ["-"] + ["-"] + ["-"] + ["-"] + parts[1:6] + ["-"])

print("[DONE] Finished scanning for network connections and sockets.")

thrdscan = []
print("[RUNNING] windows.thrdscan.ThrdScan")

args = [vol3_directory, "-f", raw_directory, "windows.thrdscan.ThrdScan"]
command = subprocess.Popen(["python"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')

for line in command.stdout:
    line = line.strip()
    parts = line.split()
    if regex.match(line):
        if len(parts) == 8:
            parts[5] = datetime.strptime(parts[5], '%H:%M:%S.%f').strftime('%H:%M:%S')
            thrdscan.append(parts[4:6] + ["thread_creation"] + [parts[1]] + ["-"] + [parts[2]] + [parts[0]] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"])

            parts[7] = datetime.strptime(parts[7], '%H:%M:%S.%f').strftime('%H:%M:%S')
            thrdscan.append(parts[6:8] + ["thread_creation"] + [parts[1]] + ["-"] + [parts[2]] + [parts[0]] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"])
        if len(parts) == 7:
            parts[5] = datetime.strptime(parts[5], '%H:%M:%S.%f').strftime('%H:%M:%S')
            thrdscan.append(parts[4:6] + ["thread_creation"] + [parts[1]] + ["-"] + [parts[2]] + [parts[0]] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"] + ["-"])

print("[DONE] Finished scanning for thread objects.")

stdout, _ = command.communicate()

combined = psscan + dlllist + netscan + thrdscan
sorted_combined = sorted(combined, key=lambda x: (x[0], x[1]), reverse=True)

headers = ["Local Date", "Local Time", "Type", "Process", "PID", "PPID", "TID", "Offset", "Threads", "Handles", "SessionID", "Wow64", "Protocol", "Local Address", "Local Port", "Foreign Address", "Foreign Port", "Path"]

with open(f"{csv_directory}\mem_output.csv", mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(headers)
    writer.writerows(sorted_combined)

print(f"\nForensic Image Timeline (MEMORY) saved as mem_output.csv at {csv_directory}")