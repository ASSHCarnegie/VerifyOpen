# -*- coding: utf-8 -*-
"""


@author: ASSHCarnegie
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))# First option using bat
GITHUB_KEYS_URL = "" # Add repo for hash veryfier

"""
if getattr(sys, 'frozen', False):
    # Running as a bundled .exe
    SCRIPT_DIR = os.path.dirname(sys.executable)
else:
    # Running as a .py file
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
"""
# Second option using pyinstaller

class RemoteConnectApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Remote Server Connector")
        self.root.geometry("500x450")
        self.root.configure(bg="#2c3e50")

        self.verified = False
        self.server_data = None

        # License Key Entry Frame
        self.license_frame = tk.Frame(root, bg="#2c3e50")
        self.license_frame.pack(pady=30)

        tk.Label(self.license_frame, text="Enter Your License Key:", font=("Helvetica", 12),
                 bg="#2c3e50", fg="white").pack(pady=5)

        self.license_var = tk.StringVar()
        self.license_entry = tk.Entry(self.license_frame, textvariable=self.license_var, width=30)
        self.license_entry.pack(pady=5)

        self.verify_button = tk.Button(self.license_frame, text="Verify License", command=self.verify_license,
                                       bg="#2980b9", fg="white", font=("Helvetica", 10, "bold"))
        self.verify_button.pack(pady=5)

        # Main GUI Elements (hidden until verified)
        self.interface_frame = tk.Frame(root, bg="#2c3e50")
        self.dir_var = tk.StringVar()
        self.file_var = tk.StringVar()

        self.dir_dropdown = ttk.Combobox(self.interface_frame, textvariable=self.dir_var, state="readonly")
        self.file_dropdown = ttk.Combobox(self.interface_frame, textvariable=self.file_var, state="readonly")
        self.info_text = tk.Text(self.interface_frame, height=6, font=("Courier", 10), bg="#34495e", fg="#ecf0f1")
        self.connect_button = tk.Button(self.interface_frame, text="Connect to Server",
                                        command=self.connect_to_server, bg="#27ae60", fg="white",
                                        font=("Helvetica", 12, "bold"))

        # Bindings
        self.dir_dropdown.bind("<<ComboboxSelected>>", self.update_files)
        self.file_dropdown.bind("<<ComboboxSelected>>", self.display_info)

    def verify_license(self):
        user_key = self.license_var.get().strip()
        if not user_key:
            messagebox.showerror("Error", "Please enter a license key.")
            return
    
        hashed = hashlib.sha256(user_key.encode()).hexdigest()
        try:
            response = requests.get(GITHUB_KEYS_URL)
            if response.status_code != 200:
                messagebox.showerror("Error", "Failed to reach verification server.")
                return
    
            # Each line is a plain hash
            hashes = [line.strip() for line in response.text.splitlines()]
            if hashed in hashes:
                messagebox.showinfo("Success", "✅ License verified. Welcome!")
                self.show_main_interface()
            else:
                messagebox.showerror("Access Denied", "❌ Invalid license key.")
        except Exception as e:
            messagebox.showerror("Error", f"Verification error: {e}")


    def show_main_interface(self):
        self.license_frame.pack_forget()
        self.interface_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        tk.Label(self.interface_frame, text="Choose Directory:", bg="#2c3e50", fg="#bdc3c7").pack()
        self.dir_dropdown.pack(pady=5)
        tk.Label(self.interface_frame, text="Choose Player File:", bg="#2c3e50", fg="#bdc3c7").pack()
        self.file_dropdown.pack(pady=5)

        self.info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.connect_button.pack(pady=10)
        self.load_directories()

    def load_directories(self):
        dirs = [d for d in os.listdir(SCRIPT_DIR) if os.path.isdir(os.path.join(SCRIPT_DIR, d))]
        self.dir_dropdown['values'] = dirs

    def update_files(self, event):
        selected_dir = self.dir_var.get()
        full_path = os.path.join(SCRIPT_DIR, selected_dir)
        txt_files = [f for f in os.listdir(full_path) if f.endswith('.txt')]
        self.file_dropdown['values'] = txt_files
        self.file_var.set("")
        self.info_text.delete("1.0", tk.END)

    def display_info(self, event):
        self.info_text.delete("1.0", tk.END)
        try:
            selected_dir = self.dir_var.get()
            selected_file = self.file_var.get()
            full_file_path = os.path.join(SCRIPT_DIR, selected_dir, selected_file)

            with open(full_file_path, 'r') as f:
                parts = f.read().strip().split(":")
                if len(parts) != 5:
                    raise ValueError("Invalid file format. Expected 5 parts.")

                owner, ip, password, ingame, player_id = parts
                username = "Administrator"

                self.server_data = {
                    "IP": ip,
                    "Password": password,
                    "Username": username,
                    "Ingame Name": ingame,
                    "Player ID": player_id
                }

                display = (f"Owner: {owner}\n"
                           f"IP Address: {ip}\n"
                           f"Username: {username}\n"
                           f"Ingame Name: {ingame}\n"
                           f"Player ID: {player_id}")
                self.info_text.insert(tk.END, display)
        except Exception as e:
            messagebox.showerror("Error", f"File read error: {e}")

    def connect_to_server(self):
        if not self.server_data:
            messagebox.showwarning("Warning", "No server selected.")
            return

        ip = self.server_data["IP"]
        user = self.server_data["Username"]
        pwd = self.server_data["Password"]

        try:
            self.info_text.insert(tk.END, "\n\nLaunching RDP...\n")
            import subprocess
            subprocess.run(
                ["cmdkey", "/generic:TERMSRV/" + ip, f"/user:{user}", f"/pass:{pwd}"],
                check=True, shell=True
            )
            subprocess.Popen(["mstsc", "/v:" + ip], shell=True)
            self.info_text.insert(tk.END, "RDP launched ✅\n")
        except Exception as e:
            self.info_text.insert(tk.END, f"Connection failed ❌: {e}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = RemoteConnectApp(root)
    root.mainloop()

