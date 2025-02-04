import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import hashlib
import os
import pandas as pd
import csv
from datetime import datetime
import subprocess
import shutil

class CorruptedFileException(Exception):
    pass

# list of known malware hashes
#virus_signatures = [
#    "72adde6903619acf53767fd92016868e4d329a3815086cafe564a66b3113d1e5"
#]

# Define the quarantine directory
QUARANTINE_DIR = "quarantine"

# Create the quarantine directory if it doesn't exist
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

def load_virus_signatures(file_path):
    df = pd.read_csv(file_path)
    signatures = {row['hash'] for _, row in df.iterrows()}
    return signatures

virus_signatures = load_virus_signatures("recent_hashes.csv")

def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
    except (IOError, OSError) as e:
        raise CorruptedFileException(f"Error reading file: {file_path}") from e
    return sha256.hexdigest()

def check_for_malwared(file_path):
    try:
        file_hash = calculate_file_hash(file_path)
    except CorruptedFileException as e:
        return "Corrupted file"
    
    if file_hash in virus_signatures:
        # Move the file to the quarantine directory
        shutil.move(file_path, os.path.join(QUARANTINE_DIR, os.path.basename(file_path)))
        return "Malware detected and moved to quarantine!"
    else:
        return "File appears clean."

def scan_directory(directory_path, progress_bar):
    results = []
    total_files = sum([len(files) for _, _, files in os.walk(directory_path)])
    processed_files = 0

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                result = check_for_malwared(file_path)
            except PermissionError:
                result = "Permission denied"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            results.append((file_path, result, timestamp))

            processed_files += 1
            progress_bar['value'] = (processed_files / total_files) * 100
            progress_bar.update()

    return results

def open_directory():
    directory_path = filedialog.askdirectory()
    if directory_path:
        progress_bar['value'] = 0
        progress_bar.grid(row=4, column=0, sticky="ns", padx=10, pady=5)

        scan_results = scan_directory(directory_path, progress_bar)
        result_message = "\n".join([f"{file}: {result} at {timestamp}" for file, result, timestamp in scan_results])
        messagebox.showinfo("Scan Results", result_message)
        
        # Save results to CSV file
        save_results_to_csv(scan_results, "scan_results.csv")
        progress_bar.grid_remove()

def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        result = check_for_malwared(file_path)
        messagebox.showinfo("Scan Result", result)

        # Save the result to a CSV file
        save_result_to_csv(file_path, result)

def save_result_to_csv(file_path, result):
    try:
        with open('scan_results.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([file_path, result, timestamp])
        print(f"Result saved to scan_results.csv")
    except PermissionError as e:
        messagebox.showerror("Error", f"Permission denied: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save result: {e}")

def save_results_to_csv(results, csv_file_path):
    try:
        with open(csv_file_path, mode='a', newline='') as file:
            writer = csv.writer(file)
            for result in results:
                writer.writerow(result)
        print(f"Results saved to {csv_file_path}")
    except PermissionError as e:
        messagebox.showerror("Error", f"Permission denied: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save results: {e}")

def view_results():
    csv_file_path = "scan_results.csv"
    try:
        subprocess.Popen(['start', csv_file_path], shell=True)
    except Exception as e:
        messagebox.showerror("Error", f"Could not open file: {e}")

def view_quarantine():
    try:
        subprocess.Popen(['start', QUARANTINE_DIR], shell=True)
    except Exception as e:
        messagebox.showerror("Error", f"Could not open quarantine directory: {e}")

# main application window
root = tk.Tk()
root.title("MDS")

root.rowconfigure(0, minsize=300, weight=1)
root.columnconfigure(0, minsize=200, weight=1)

#frm_results = tk.Frame(root)
#frm_results.grid(row=0, column=1, sticky="nsew")

# Buttons Frame
frm_buttons = tk.Frame(root, relief=tk.RAISED, bd=1, background="Black")
frm_buttons.grid(row=0, column=0, sticky="ns")

# Name
name = tk.Label(frm_buttons, text="Malware Detection System", background="Black", fg="white", font=("Helvetica", 14, "bold italic"))
name.grid(row=1, column=0, sticky="ns", padx=10, pady=5)

# 'Select File' button
btn_select_file = tk.Button(frm_buttons, text="Select File to Scan", command=open_file)
btn_select_file.grid(row=2, column=0, sticky="ns", padx=10, pady=5)

# 'Select Directory' button
btn_select_dir = tk.Button(frm_buttons, text="Select Directory to Scan", command=open_directory)
btn_select_dir.grid(row=3, column=0, sticky="ns", padx=10, pady=5)

# 'View Results' button
btn_view_results = tk.Button(frm_buttons, text="View Results", command=view_results)
btn_view_results.grid(row=4, column=0, sticky="ns", padx=10, pady=5)

# 'View Quarantine' button
btn_view_quarantine = tk.Button(frm_buttons, text="View Quarantine", command=view_quarantine)
btn_view_quarantine.grid(row=5, column=0, sticky="ns", padx=10, pady=5)

# Progress Bar
progress_bar = ttk.Progressbar(frm_buttons, orient="horizontal", length=200, mode="determinate")

# Tkinter event loop
root.mainloop()