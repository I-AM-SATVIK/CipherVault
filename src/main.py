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

try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

# --- CONSTANTS ---
DATA_FILE = "vault.enc"
TIMEOUT_MS = 60000

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
            raw_data = json.loads(decrypted_data.decode())
            
            self.passwords = {}
            needs_save = False
            for key, val in raw_data.items():
                if key == "__vault_password_hash__":
                    self.passwords[key] = val
                else:
                    if "actual_site" not in val:
                        new_key = f"{key}_{val['username']}"
                        self.passwords[new_key] = {
                            "actual_site": key, 
                            "username": val["username"], 
                            "password": val["password"]
                        }
                        needs_save = True
                    else:
                        self.passwords[key] = val
            if needs_save:
                self.save_passwords()
            return True
        except InvalidToken:
            return False

    def save_passwords(self):
        json_data = json.dumps(self.passwords).encode()
        encrypted_data = self.fernet.encrypt(json_data)
        with open(DATA_FILE, "wb") as file:
            file.write(encrypted_data)

    def add_password(self, site, username, password):
        unique_key = f"{site}_{username}"
        self.passwords[unique_key] = {"actual_site": site, "username": username, "password": password}
        self.save_passwords()

    def delete_password(self, unique_key):
        if unique_key in self.passwords:
            del self.passwords[unique_key]
            self.save_passwords()
            return True
        return False

    def change_master_password(self, new_master_password):
        self.derive_key(new_master_password)
        self.save_passwords()

    def change_secondary_password(self, new_secondary_password):
        hashed = hashlib.sha256(new_secondary_password.encode()).hexdigest()
        self.passwords["__vault_password_hash__"] = hashed
        self.save_passwords()

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
        self.geometry("550x650")
        self.resizable(False, False)
        self.manager = PasswordManager()
        self.current_master_pwd = None
        self.timeout_id = None

        self.option_add("*Font", "SegoeUI 10")
        style = ttk.Style(self)
        style.theme_use('clam')

        try:
            self.update_idletasks()
            ctypes.windll.user32.SetWindowDisplayAffinity(self.winfo_id(), 17)
        except Exception:
            pass

        self.bind("<Any-KeyPress>", self.reset_timer)
        self.bind("<Any-Button>", self.reset_timer)
        self.bind("<Motion>", self.reset_timer)

        self.build_login_screen()

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    # --- UI COMPONENTS ---
    def build_virtual_keyboard(self, parent_frame, target_entry, submit_text="Submit", submit_command=None):
        vk_frame = ttk.Frame(parent_frame)
        vk_frame.pack(pady=10)

        chars = list(string.ascii_letters + string.digits + "!@#$%^&*()")
        secrets.SystemRandom().shuffle(chars)

        for i, char in enumerate(chars):
            row = i // 10
            col = i % 10
            btn = ttk.Button(vk_frame, text=char, width=3,
                             command=lambda c=char: target_entry.insert(tk.END, c))
            btn.grid(row=row, column=col, padx=2, pady=2)

        utils_frame = ttk.Frame(vk_frame)
        utils_frame.grid(row=(len(chars)//10)+1, column=0, columnspan=10, pady=10)
        
        ttk.Button(utils_frame, text="Backspace", width=12, command=lambda: target_entry.delete(len(target_entry.get())-1, tk.END)).pack(side="left", padx=2)
        ttk.Button(utils_frame, text="Clear", width=8, command=lambda: target_entry.delete(0, tk.END)).pack(side="left", padx=2)
        
        def shuffle_keys():
            vk_frame.destroy()
            self.build_virtual_keyboard(parent_frame, target_entry, submit_text, submit_command)
            
        ttk.Button(utils_frame, text="Shuffle", width=8, command=shuffle_keys).pack(side="left", padx=2)
        
        if submit_command:
            ttk.Button(utils_frame, text=submit_text, width=12, command=submit_command).pack(side="left", padx=2)

    # --- TIMEOUT LOGIC ---
    def reset_timer(self, event=None):
        if self.timeout_id:
            self.after_cancel(self.timeout_id)
        if self.current_master_pwd:
            self.timeout_id = self.after(TIMEOUT_MS, self.lock_vault)

    def lock_vault(self):
        self.current_master_pwd = None
        self.manager.passwords = {}
        self.clipboard_clear()
        self.build_login_screen()
        messagebox.showwarning("Locked", "Vault locked securely due to inactivity.")

    # --- SCREEN: LOGIN ---
    def build_login_screen(self):
        self.clear_window()
        
        ttk.Label(self, text="🔒 Cipher Vault", font=("SegoeUI", 24, "bold")).pack(pady=(40, 10))
        status_text = "Use the Secure Keyboard to Unlock:" if os.path.exists(DATA_FILE) else "Create Master Password (Secure Keyboard):"
        ttk.Label(self, text=status_text).pack(pady=5)
        
        self.master_pwd_entry = ttk.Entry(self, show="*", width=35, font=("SegoeUI", 12))
        self.master_pwd_entry.pack(pady=10)
        self.master_pwd_entry.bind("<Key>", lambda e: "break")

        self.build_virtual_keyboard(self, self.master_pwd_entry, "Login", self.attempt_login)

    def attempt_login(self):
        pwd = self.master_pwd_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        if self.manager.load_passwords(pwd):
            self.current_master_pwd = pwd
            self.reset_timer()
            self.build_dashboard_screen()
        else:
            messagebox.showerror("Access Denied", "Incorrect Master Password!")
            self.master_pwd_entry.delete(0, tk.END)

    # --- SCREEN: MAIN DASHBOARD ---
    def build_dashboard_screen(self):
        self.clear_window()

        ttk.Label(self, text="🔒 Dashboard", font=("SegoeUI", 20, "bold")).pack(pady=(20, 10))

        input_frame = ttk.LabelFrame(self, text=" Save New Credential ", padding=(20, 10))
        input_frame.pack(pady=10, fill="x", padx=40)
        inner_center_frame = ttk.Frame(input_frame)
        inner_center_frame.pack(expand=True)

        ttk.Label(inner_center_frame, text="Website / App:").grid(row=0, column=0, padx=5, pady=10, sticky="e")
        self.site_entry = ttk.Entry(inner_center_frame, width=35)
        self.site_entry.grid(row=0, column=1, padx=5, pady=10)

        ttk.Label(inner_center_frame, text="Username:").grid(row=1, column=0, padx=5, pady=10, sticky="e")
        self.user_entry = ttk.Entry(inner_center_frame, width=35)
        self.user_entry.grid(row=1, column=1, padx=5, pady=10)

        ttk.Label(inner_center_frame, text="Password:").grid(row=2, column=0, padx=5, pady=10, sticky="e")
        self.pwd_entry = ttk.Entry(inner_center_frame, width=35)
        self.pwd_entry.grid(row=2, column=1, padx=5, pady=10)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="⚡ Generate", command=self.ui_generate_password).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="📋 Copy", command=self.copy_password).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="💾 Save", command=self.ui_save_password).grid(row=0, column=2, padx=5)
        
        ttk.Separator(self, orient='horizontal').pack(fill='x', padx=40, pady=10)
        
        ttk.Button(self, text="View & Manage Vault", command=self.route_vault_access).pack(pady=5)
        ttk.Button(self, text="⚙️ Settings", command=self.build_settings_screen).pack(pady=5)
        ttk.Button(self, text="🔒 Lock Vault", command=self.lock_vault).pack(pady=(15, 5))

    # --- DASHBOARD HELPER METHODS ---
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

    # --- SCREEN: VAULT AUTHENTICATION ---
    def route_vault_access(self):
        if "__vault_password_hash__" not in self.manager.passwords:
            self.build_vault_setup_screen()
        else:
            self.build_vault_auth_screen()

    def build_vault_setup_screen(self):
        self.clear_window()
        ttk.Label(self, text="Setup Vault Password", font=("SegoeUI", 18, "bold")).pack(pady=(40, 10))
        ttk.Label(self, text="Create a secondary password to view credentials.", wraplength=300).pack(pady=10)
        
        ttk.Label(self, text="New Secondary Password:").pack(pady=5)
        pwd_entry = ttk.Entry(self, show="*", width=35)
        pwd_entry.pack(pady=5)
        ttk.Label(self, text="Confirm Password:").pack(pady=5)
        confirm_entry = ttk.Entry(self, show="*", width=35)
        confirm_entry.pack(pady=5)

        def save_sec_pwd():
            p1 = pwd_entry.get()
            if p1 != confirm_entry.get():
                messagebox.showerror("Error", "Passwords do not match.")
                return
            if p1 == self.current_master_pwd:
                messagebox.showerror("Error", "Secondary password must be different from the Master Password.")
                return
            if not p1: return
            self.manager.change_secondary_password(p1)
            self.build_vault_view_screen()

        ttk.Button(self, text="Save & Continue", command=save_sec_pwd).pack(pady=15)
        ttk.Button(self, text="← Back to Dashboard", command=self.build_dashboard_screen).pack(pady=10)

    def build_vault_auth_screen(self):
        self.clear_window()
        ttk.Label(self, text="Vault Authentication", font=("SegoeUI", 18, "bold")).pack(pady=(40, 10))
        ttk.Label(self, text="Enter Secondary Password via Secure Keyboard:").pack(pady=10)
        
        self.sec_pwd_entry = ttk.Entry(self, show="*", width=35, font=("SegoeUI", 12))
        self.sec_pwd_entry.pack(pady=5)
        self.sec_pwd_entry.bind("<Key>", lambda e: "break")

        def check_pwd():
            p = self.sec_pwd_entry.get()
            hashed = hashlib.sha256(p.encode()).hexdigest()
            if hashed == self.manager.passwords["__vault_password_hash__"]:
                self.build_vault_view_screen()
            else:
                messagebox.showerror("Denied", "Incorrect Secondary Password")
                self.sec_pwd_entry.delete(0, tk.END)

        self.build_virtual_keyboard(self, self.sec_pwd_entry, "Unlock Vault", check_pwd)
        ttk.Button(self, text="← Back to Dashboard", command=self.build_dashboard_screen).pack(pady=10)

    # --- SCREEN: VIEW VAULT ---
    def build_vault_view_screen(self):
        self.clear_window()
        ttk.Label(self, text="Saved Credentials", font=("SegoeUI", 18, "bold")).pack(pady=(20, 10))

        columns = ("site", "username", "password")
        tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")
        tree.heading("site", text="Site / App")
        tree.heading("username", text="Username")
        tree.heading("password", text="Password")
        tree.column("site", width=150)
        tree.column("username", width=180)
        tree.column("password", width=180)
        tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.refresh_table(tree)

        def toggle_password_visibility():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("No Selection", "Please select a credential to show/hide.")
                return
            
            unique_key = selected_item[0] 
            item_values = tree.item(unique_key, "values")
            site = item_values[0]
            username = item_values[1]
            displayed_password = item_values[2]
            
            # Retrieve the real password from the encrypted memory dictionary
            actual_password = self.manager.passwords[unique_key]['password']

            # Toggle the display value
            if displayed_password == "********":
                tree.item(unique_key, values=(site, username, actual_password))
            else:
                tree.item(unique_key, values=(site, username, "********"))

        def delete_selected():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("No Selection", "Please select a password to delete.")
                return
            unique_key = selected_item[0] 
            item_values = tree.item(unique_key, "values")
            site_to_delete = item_values[0]
            confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for '{site_to_delete}'?")
            if confirm:
                self.manager.delete_password(unique_key)
                self.build_vault_view_screen() 

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="👁️ Show / Hide", command=toggle_password_visibility).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="🗑️ Delete Selected", command=delete_selected).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="← Back to Dashboard", command=self.build_dashboard_screen).pack(side="left", padx=10)

    def refresh_table(self, tree):
        for item in tree.get_children():
            tree.delete(item)
        for key, data in self.manager.passwords.items():
            if key == "__vault_password_hash__": continue
            # Passwords are masked with asterisks by default during UI injection
            tree.insert("", tk.END, iid=key, values=(data['actual_site'], data['username'], "********"))

    # --- SCREEN: SETTINGS ---
    def build_settings_screen(self):
        self.clear_window()
        ttk.Label(self, text="⚙️ Security Settings", font=("SegoeUI", 18, "bold")).pack(pady=(20, 10))

        master_frame = ttk.LabelFrame(self, text=" Change Master Password ", padding=15)
        master_frame.pack(fill="x", padx=40, pady=10)
        ttk.Label(master_frame, text="Current Master Password:").pack(anchor="w")
        current_master_entry = ttk.Entry(master_frame, show="*")
        current_master_entry.pack(fill="x", pady=(0, 5))
        ttk.Label(master_frame, text="New Master Password:").pack(anchor="w")
        new_master_entry = ttk.Entry(master_frame, show="*")
        new_master_entry.pack(fill="x", pady=(0, 10))

        def update_master():
            if current_master_entry.get() != self.current_master_pwd:
                messagebox.showerror("Error", "Current Master Password is incorrect.")
                return
            new_pwd = new_master_entry.get()
            if not new_pwd: return
            self.manager.change_master_password(new_pwd)
            self.current_master_pwd = new_pwd
            messagebox.showinfo("Success", "Master Password updated! Vault re-encrypted.")
            current_master_entry.delete(0, tk.END)
            new_master_entry.delete(0, tk.END)
        ttk.Button(master_frame, text="Update Master Password", command=update_master).pack(pady=5)

        sec_frame = ttk.LabelFrame(self, text=" Change Vault Password ", padding=15)
        sec_frame.pack(fill="x", padx=40, pady=10)
        ttk.Label(sec_frame, text="Current Vault Password:").pack(anchor="w")
        current_sec_entry = ttk.Entry(sec_frame, show="*")
        current_sec_entry.pack(fill="x", pady=(0, 5))
        ttk.Label(sec_frame, text="New Vault Password:").pack(anchor="w")
        new_sec_entry = ttk.Entry(sec_frame, show="*")
        new_sec_entry.pack(fill="x", pady=(0, 10))

        def update_secondary():
            if "__vault_password_hash__" not in self.manager.passwords: return
            hashed_current = hashlib.sha256(current_sec_entry.get().encode()).hexdigest()
            if hashed_current != self.manager.passwords["__vault_password_hash__"]:
                messagebox.showerror("Error", "Current Vault Password is incorrect.")
                return
            new_pwd = new_sec_entry.get()
            if not new_pwd: return
            if new_pwd == self.current_master_pwd:
                messagebox.showerror("Error", "Secondary password must be different from Master.")
                return
            self.manager.change_secondary_password(new_pwd)
            messagebox.showinfo("Success", "Vault Password successfully updated!")
            current_sec_entry.delete(0, tk.END)
            new_sec_entry.delete(0, tk.END)
        ttk.Button(sec_frame, text="Update Vault Password", command=update_secondary).pack(pady=5)

        ttk.Button(self, text="← Back to Dashboard", command=self.build_dashboard_screen).pack(pady=15)

if __name__ == "__main__":
    app = App()
    app.mainloop()