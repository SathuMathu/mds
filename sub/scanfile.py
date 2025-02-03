import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
import pefile

# main application window
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
        return "Malware detected!"
    else:
        return "File appears clean."

def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        result = check_for_malware(file_path)
        messagebox.showinfo("Scan Result", result)

# 'Select File' button
select_file_button = tk.Button(root, text="Select File to Scan", command=open_file)
select_file_button.pack(pady=20)

# Run the Tkinter event loop
root.mainloop()