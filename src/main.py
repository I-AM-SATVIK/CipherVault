import tkinter as tk
from tkinter import messagebox
import random
import string
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

# --- CONSTANTS ---
DATA_FILE = "vault.enc"

# --- CORE LOGIC ---
class PasswordManager:
    def __init__(self):
        self.key = None
        self.fernet = None
        self.passwords = {}

    def derive_key(self, master_password):
        # Derives a secure Fernet key from the master password using SHA-256
        digest = hashlib.sha256(master_password.encode()).digest()
        self.key = base64.urlsafe_b64encode(digest)
        self.fernet = Fernet(self.key)

    def load_passwords(self, master_password):
        self.derive_key(master_password)
        
        if not os.path.exists(DATA_FILE):
            # First time setup
            self.save_passwords()
            return True

        try:
            with open(DATA_FILE, "rb") as file:
                encrypted_data = file.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.passwords = json.loads(decrypted_data.decode())
            return True
        except InvalidToken:
            return False # Incorrect master password

    def save_passwords(self):
        json_data = json.dumps(self.passwords).encode()
        encrypted_data = self.fernet.encrypt(json_data)
        with open(DATA_FILE, "wb") as file:
            file.write(encrypted_data)

    def add_password(self, site, username, password):
        self.passwords[site] = {"username": username, "password": password}
        self.save_passwords()

    def generate_password(self, length=16):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

# --- GUI LOGIC ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Password Vault")
        self.geometry("400x350")
        self.manager = PasswordManager()

        self.build_login_screen()

    def build_login_screen(self):
        self.clear_window()
        
        tk.Label(self, text="Password Vault", font=("Arial", 18, "bold")).pack(pady=20)
        
        status_text = "Enter Master Password:" if os.path.exists(DATA_FILE) else "Create a Master Password:"
        tk.Label(self, text=status_text).pack(pady=5)
        
        self.master_pwd_entry = tk.Entry(self, show="*", width=30)
        self.master_pwd_entry.pack(pady=5)
        
        tk.Button(self, text="Login / Setup", command=self.attempt_login).pack(pady=10)

    def attempt_login(self):
        pwd = self.master_pwd_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        if self.manager.load_passwords(pwd):
            self.build_main_screen()
        else:
            messagebox.showerror("Error", "Incorrect Master Password!")

    def build_main_screen(self):
        self.clear_window()

        # UI Elements for Data Entry
        tk.Label(self, text="Website/App Name:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.site_entry = tk.Entry(self, width=30)
        self.site_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(self, text="Username/Email:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.user_entry = tk.Entry(self, width=30)
        self.user_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Label(self, text="Password:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.pwd_entry = tk.Entry(self, width=30)
        self.pwd_entry.grid(row=2, column=1, padx=10, pady=10)

        # Buttons
        tk.Button(self, text="Generate", command=self.ui_generate_password).grid(row=3, column=0, pady=10)
        tk.Button(self, text="Save", command=self.ui_save_password).grid(row=3, column=1, pady=10, sticky="w")
        
        tk.Button(self, text="View Saved Passwords", command=self.view_passwords).grid(row=4, column=0, columnspan=2, pady=10)

    def ui_generate_password(self):
        self.pwd_entry.delete(0, tk.END)
        new_password = self.manager.generate_password()
        self.pwd_entry.insert(0, new_password)

    def ui_save_password(self):
        site = self.site_entry.get()
        user = self.user_entry.get()
        pwd = self.pwd_entry.get()

        if not site or not user or not pwd:
            messagebox.showwarning("Incomplete", "Please fill out all fields.")
            return

        self.manager.add_password(site, user, pwd)
        messagebox.showinfo("Success", f"Credentials for {site} saved securely!")
        
        # Clear fields
        self.site_entry.delete(0, tk.END)
        self.user_entry.delete(0, tk.END)
        self.pwd_entry.delete(0, tk.END)

    def view_passwords(self):
        view_window = tk.Toplevel(self)
        view_window.title("Saved Passwords")
        view_window.geometry("300x300")

        listbox = tk.Listbox(view_window, width=40, height=15)
        listbox.pack(pady=10, padx=10)

        if not self.manager.passwords:
            listbox.insert(tk.END, "Vault is empty.")
        else:
            for site, data in self.manager.passwords.items():
                listbox.insert(tk.END, f"Site: {site}")
                listbox.insert(tk.END, f"User: {data['username']}")
                listbox.insert(tk.END, f"Pass: {data['password']}")
                listbox.insert(tk.END, "-" * 20)

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()