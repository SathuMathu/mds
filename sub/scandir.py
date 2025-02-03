import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
import pefile

# Create the main application window
root = tk.Tk()
root.title("Malware Detection System")

# list of known malware hashes
KNOWN_MALWARE_HASHES = [
    "72adde6903619acf53767fd92016868e4d329a3815086cafe564a66b3113d1e5"
]

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of the given file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def check_for_malware(file_path):
    """Check if the file is malicious based on its hash."""
    file_hash = calculate_file_hash(file_path)
    if file_hash in KNOWN_MALWARE_HASHES:
        return True
    else:
        return False

def scan_directory(directory_path):
    """Scan the directory for malicious files."""
    results = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            if check_for_malware(file_path):
                results.append(f"Malware detected: {file_path}")
            else:
                results.append(f"File appears clean: {file_path}")
    return results

def open_directory():
    directory_path = filedialog.askdirectory()
    if directory_path:
        scan_results = scan_directory(directory_path)
        result_message = "\n".join(scan_results)
        messagebox.showinfo("Scan Results", result_message)

# Create and place the 'Select Directory' button
select_directory_button = tk.Button(root, text="Select Directory to Scan", command=open_directory)
select_directory_button.pack(pady=20)

# Run the Tkinter event loop
root.mainloop()
