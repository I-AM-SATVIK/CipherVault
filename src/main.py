import tkinter as tk
from tkinter import messagebox
from tkinter import ttk # Importing Themed Tkinter for modern UI
import secrets
import string
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

# Fix blurry text on Windows High-DPI displays
try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

# --- CONSTANTS ---
DATA_FILE = "vault.enc"

# --- CORE LOGIC ---
class PasswordManager:
    def __init__(self):
        self.key = None
        self.fernet = None
        self.passwords = {}

    def derive_key(self, master_password):
        digest = hashlib.sha256(master_password.encode()).digest()
        self.key = base64.urlsafe_b64encode(digest)
        self.fernet = Fernet(self.key)

    def load_passwords(self, master_password):
        self.derive_key(master_password)
        
        if not os.path.exists(DATA_FILE):
            self.save_passwords()
            return True

        try:
            with open(DATA_FILE, "rb") as file:
                encrypted_data = file.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.passwords = json.loads(decrypted_data.decode())
            return True
        except InvalidToken:
            return False

    def save_passwords(self):
        json_data = json.dumps(self.passwords).encode()
        encrypted_data = self.fernet.encrypt(json_data)
        with open(DATA_FILE, "wb") as file:
            file.write(encrypted_data)

    def add_password(self, site, username, password):
        self.passwords[site] = {"username": username, "password": password}
        self.save_passwords()

    def delete_password(self, site):
        if site in self.passwords:
            del self.passwords[site]
            self.save_passwords()
            return True
        return False

    def generate_password(self, length=24):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                sum(c.isdigit() for c in password) >= 2 and
                sum(c in string.punctuation for c in password) >= 2):
                return password

# --- GUI LOGIC ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cipher Vault")
        self.geometry("550x500")
        self.manager = PasswordManager()

        # Apply standard UI styling
        self.option_add("*Font", "SegoeUI 10")
        style = ttk.Style(self)
        style.theme_use('clam') # 'clam', 'vista', or 'winnative' provide cleaner looks

        self.build_login_screen()

    def build_login_screen(self):
        self.clear_window()
        
        ttk.Label(self, text="🔒 Cipher Vault", font=("SegoeUI", 24, "bold")).pack(pady=(40, 10))
        
        status_text = "Enter Master Password to Unlock:" if os.path.exists(DATA_FILE) else "Create a New Master Password:"
        ttk.Label(self, text=status_text).pack(pady=5)
        
        self.master_pwd_entry = ttk.Entry(self, show="*", width=35, font=("SegoeUI", 12))
        self.master_pwd_entry.pack(pady=5)

        # Show/Hide Password Toggle
        self.show_pwd_var = tk.BooleanVar()
        ttk.Checkbutton(self, text="Show Password", variable=self.show_pwd_var, command=self.toggle_login_visibility).pack(pady=5)
        
        ttk.Button(self, text="Login", command=self.attempt_login).pack(pady=20)

    def toggle_login_visibility(self):
        if self.show_pwd_var.get():
            self.master_pwd_entry.config(show="")
        else:
            self.master_pwd_entry.config(show="*")

    def attempt_login(self):
        pwd = self.master_pwd_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        if self.manager.load_passwords(pwd):
            self.build_main_screen()
        else:
            messagebox.showerror("Access Denied", "Incorrect Master Password!")

    def build_main_screen(self):
        self.clear_window()

        # Dashboard Header
        ttk.Label(self, text="🔒 Cipher Vault Dashboard", font=("SegoeUI", 18, "bold")).pack(pady=(20, 10))

        # Visually Grouped Input Area
        input_frame = ttk.LabelFrame(self, text=" Save New Credential ", padding=(20, 10))
        input_frame.pack(pady=10, fill="x", padx=40)

        ttk.Label(input_frame, text="Website / App:").grid(row=0, column=0, padx=5, pady=10, sticky="e")
        self.site_entry = ttk.Entry(input_frame, width=35)
        self.site_entry.grid(row=0, column=1, padx=5, pady=10)

        ttk.Label(input_frame, text="Username / Email:").grid(row=1, column=0, padx=5, pady=10, sticky="e")
        self.user_entry = ttk.Entry(input_frame, width=35)
        self.user_entry.grid(row=1, column=1, padx=5, pady=10)

        ttk.Label(input_frame, text="Password:").grid(row=2, column=0, padx=5, pady=10, sticky="e")
        self.pwd_entry = ttk.Entry(input_frame, width=35)
        self.pwd_entry.grid(row=2, column=1, padx=5, pady=10)

        # Action Buttons Area
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=15)

        ttk.Button(btn_frame, text="⚡ Generate", command=self.ui_generate_password).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="📋 Copy", command=self.copy_password).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="💾 Save", command=self.ui_save_password).grid(row=0, column=2, padx=5)
        
        ttk.Separator(self, orient='horizontal').pack(fill='x', padx=40, pady=10)
        
        ttk.Button(self, text="View & Manage Vault", command=self.view_passwords).pack(pady=10)

    def ui_generate_password(self):
        self.pwd_entry.delete(0, tk.END)
        new_password = self.manager.generate_password()
        self.pwd_entry.insert(0, new_password)
        
        self.clipboard_clear()
        self.clipboard_append(new_password)
        self.update()
        messagebox.showinfo("Generated", "Strong password generated and copied to clipboard!")

    def copy_password(self):
        pwd = self.pwd_entry.get()
        if pwd:
            self.clipboard_clear()
            self.clipboard_append(pwd)
            self.update()
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Empty", "No password to copy.")

    def ui_save_password(self):
        site = self.site_entry.get().strip()
        user = self.user_entry.get().strip()
        pwd = self.pwd_entry.get().strip()

        if not site or not user or not pwd:
            messagebox.showwarning("Incomplete", "Please fill out all fields.")
            return

        self.manager.add_password(site, user, pwd)
        messagebox.showinfo("Success", f"Credentials for {site} saved securely!")
        
        self.site_entry.delete(0, tk.END)
        self.user_entry.delete(0, tk.END)
        self.pwd_entry.delete(0, tk.END)

    def view_passwords(self):
        view_window = tk.Toplevel(self)
        view_window.title("Manage Vault")
        view_window.geometry("600x400")

        columns = ("site", "username", "password")
        tree = ttk.Treeview(view_window, columns=columns, show="headings", selectmode="browse")
        
        tree.heading("site", text="Site / App")
        tree.heading("username", text="Username")
        tree.heading("password", text="Password")
        
        tree.column("site", width=150)
        tree.column("username", width=200)
        tree.column("password", width=200)

        tree.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        self.refresh_table(tree)

        def delete_selected():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("No Selection", "Please select a password to delete.", parent=view_window)
                return
            
            item_values = tree.item(selected_item[0], "values")
            site_to_delete = item_values[0]

            confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for '{site_to_delete}'?", parent=view_window)
            
            if confirm:
                self.manager.delete_password(site_to_delete)
                self.refresh_table(tree)

        ttk.Button(view_window, text="🗑️ Delete Selected", command=delete_selected).pack(pady=10)

    def refresh_table(self, tree):
        for item in tree.get_children():
            tree.delete(item)
        for site, data in self.manager.passwords.items():
            tree.insert("", tk.END, values=(site, data['username'], data['password']))

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()