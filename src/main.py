import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
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
        self.resizable(False, False) # Locks the window size
        self.manager = PasswordManager()
        self.current_master_pwd = None

        self.option_add("*Font", "SegoeUI 10")
        style = ttk.Style(self)
        style.theme_use('clam')

        self.build_login_screen()

    def build_login_screen(self):
        self.clear_window()
        
        ttk.Label(self, text="🔒 Cipher Vault", font=("SegoeUI", 24, "bold")).pack(pady=(40, 10))
        
        status_text = "Enter Master Password to Unlock:" if os.path.exists(DATA_FILE) else "Create a New Master Password:"
        ttk.Label(self, text=status_text).pack(pady=5)
        
        self.master_pwd_entry = ttk.Entry(self, show="*", width=35, font=("SegoeUI", 12))
        self.master_pwd_entry.pack(pady=5)
        
        ttk.Button(self, text="Login", command=self.attempt_login).pack(pady=20)

    def attempt_login(self):
        pwd = self.master_pwd_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        if self.manager.load_passwords(pwd):
            self.current_master_pwd = pwd
            self.build_main_screen()
        else:
            messagebox.showerror("Access Denied", "Incorrect Master Password!")

    def build_main_screen(self):
        self.clear_window()

        ttk.Label(self, text="🔒 Cipher Vault Dashboard", font=("SegoeUI", 18, "bold")).pack(pady=(20, 10))

        # Visually Grouped Input Area
        input_frame = ttk.LabelFrame(self, text=" Save New Credential ", padding=(20, 10))
        input_frame.pack(pady=10, fill="x", padx=40)

        # Invisible container to perfectly center the inputs
        inner_center_frame = ttk.Frame(input_frame)
        inner_center_frame.pack(expand=True)

        ttk.Label(inner_center_frame, text="Website / App:").grid(row=0, column=0, padx=5, pady=10, sticky="e")
        self.site_entry = ttk.Entry(inner_center_frame, width=35)
        self.site_entry.grid(row=0, column=1, padx=5, pady=10)

        ttk.Label(inner_center_frame, text="Username / Email:").grid(row=1, column=0, padx=5, pady=10, sticky="e")
        self.user_entry = ttk.Entry(inner_center_frame, width=35)
        self.user_entry.grid(row=1, column=1, padx=5, pady=10)

        ttk.Label(inner_center_frame, text="Password:").grid(row=2, column=0, padx=5, pady=10, sticky="e")
        self.pwd_entry = ttk.Entry(inner_center_frame, width=35)
        self.pwd_entry.grid(row=2, column=1, padx=5, pady=10)

        # Buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=15)

        ttk.Button(btn_frame, text="⚡ Generate", command=self.ui_generate_password).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="📋 Copy", command=self.copy_password).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="💾 Save", command=self.ui_save_password).grid(row=0, column=2, padx=5)
        
        ttk.Separator(self, orient='horizontal').pack(fill='x', padx=40, pady=10)
        
        ttk.Button(self, text="View & Manage Vault", command=self.view_passwords_auth).pack(pady=10)

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

        if site == "__vault_password_hash__":
            messagebox.showerror("Error", "Reserved system name. Choose a different site name.")
            return

        self.manager.add_password(site, user, pwd)
        messagebox.showinfo("Success", f"Credentials for {site} saved securely!")
        
        self.site_entry.delete(0, tk.END)
        self.user_entry.delete(0, tk.END)
        self.pwd_entry.delete(0, tk.END)

    def view_passwords_auth(self):
        if "__vault_password_hash__" not in self.manager.passwords:
            self.setup_secondary_password()
        else:
            self.verify_secondary_password()

    def setup_secondary_password(self):
        setup_win = tk.Toplevel(self)
        setup_win.title("Setup Vault Password")
        setup_win.geometry("350x250")
        setup_win.transient(self)
        setup_win.grab_set()

        ttk.Label(setup_win, text="Create a secondary password to view credentials.", wraplength=300).pack(pady=10)
        
        ttk.Label(setup_win, text="New Secondary Password:").pack(pady=5)
        pwd_entry = ttk.Entry(setup_win, show="*")
        pwd_entry.pack(pady=5)
        
        ttk.Label(setup_win, text="Confirm Password:").pack(pady=5)
        confirm_entry = ttk.Entry(setup_win, show="*")
        confirm_entry.pack(pady=5)

        def save_sec_pwd():
            p1 = pwd_entry.get()
            p2 = confirm_entry.get()
            if p1 != p2:
                messagebox.showerror("Error", "Passwords do not match.", parent=setup_win)
                return
            if p1 == self.current_master_pwd:
                messagebox.showerror("Error", "Secondary password must be different from the Master Password.", parent=setup_win)
                return
            if not p1:
                return

            hashed = hashlib.sha256(p1.encode()).hexdigest()
            self.manager.passwords["__vault_password_hash__"] = hashed
            self.manager.save_passwords()
            setup_win.destroy()
            self.view_passwords()

        ttk.Button(setup_win, text="Save & Continue", command=save_sec_pwd).pack(pady=15)

    def verify_secondary_password(self):
        verify_win = tk.Toplevel(self)
        verify_win.title("Vault Authentication")
        verify_win.geometry("300x150")
        verify_win.transient(self)
        verify_win.grab_set()

        ttk.Label(verify_win, text="Enter Secondary Password:").pack(pady=10)
        pwd_entry = ttk.Entry(verify_win, show="*")
        pwd_entry.pack(pady=5)

        def check_pwd():
            p = pwd_entry.get()
            hashed = hashlib.sha256(p.encode()).hexdigest()
            if hashed == self.manager.passwords["__vault_password_hash__"]:
                verify_win.destroy()
                self.view_passwords()
            else:
                messagebox.showerror("Denied", "Incorrect Secondary Password", parent=verify_win)

        ttk.Button(verify_win, text="Unlock Vault", command=check_pwd).pack(pady=10)

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
            if site == "__vault_password_hash__":
                continue
            tree.insert("", tk.END, values=(site, data['username'], data['password']))

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()