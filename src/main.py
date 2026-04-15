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

# OS-Level API bindings for High DPI and Screen Defense
try:
    import ctypes
    from ctypes import wintypes
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
        
        # Theme State (Default to Dark Mode for professional look)
        self.current_theme = "dark"

        # Base UI Setup
        self.option_add("*Font", "SegoeUI 10")
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.apply_theme()

        # Execute 64-bit API Screen Defense after window draws
        self.after(100, self.apply_screen_defense)

        # Global Inactivity Listeners
        self.bind("<Any-KeyPress>", self.reset_timer)
        self.bind("<Any-Button>", self.reset_timer)
        self.bind("<Motion>", self.reset_timer)

        self.build_login_screen()

    # --- THEME MANAGER (FEATURE 3) ---
    def apply_theme(self):
        if self.current_theme == "dark":
            bg = "#1e1e1e"
            fg = "#ffffff"
            input_bg = "#2d2d2d"
            btn_bg = "#3a3a3a"
            btn_active = "#505050"
            tree_bg = "#252525"
            accent = "#0078D7"
        else:
            bg = "#f3f3f3"
            fg = "#000000"
            input_bg = "#ffffff"
            btn_bg = "#e1e1e1"
            btn_active = "#cce4f7"
            tree_bg = "#ffffff"
            accent = "#0078D7"

        self.configure(bg=bg)
        
        # Global Style Overrides
        self.style.configure(".", background=bg, foreground=fg, fieldbackground=input_bg, insertcolor=fg)
        self.style.configure("TFrame", background=bg)
        self.style.configure("TLabel", background=bg, foreground=fg)
        self.style.configure("TButton", background=btn_bg, foreground=fg, borderwidth=0, padding=5)
        self.style.map("TButton", background=[("active", btn_active)])
        self.style.configure("TLabelframe", background=bg, foreground=fg, borderwidth=1)
        self.style.configure("TLabelframe.Label", background=bg, foreground=fg, font=("SegoeUI", 10, "bold"))
        self.style.configure("TEntry", fieldbackground=input_bg, foreground=fg, insertcolor=fg, borderwidth=1)
        self.style.configure("TSeparator", background=btn_active)

        # Treeview (Data Table) Styling
        self.style.configure("Treeview", background=tree_bg, foreground=fg, fieldbackground=tree_bg, borderwidth=0)
        self.style.configure("Treeview.Heading", background=btn_bg, foreground=fg, relief="flat", font=("SegoeUI", 10, "bold"))
        self.style.map("Treeview", background=[("selected", accent)], foreground=[("selected", "#ffffff")])
        self.style.map("Treeview.Heading", background=[("active", btn_active)])

        # Setup Strength Meter Colors
        self.style.configure("Weak.TLabel", foreground="#ff5555" if self.current_theme=="dark" else "#cc0000")
        self.style.configure("Medium.TLabel", foreground="#ffb84d" if self.current_theme=="dark" else "#d68900")
        self.style.configure("Strong.TLabel", foreground="#4dff4d" if self.current_theme=="dark" else "#008800")
        self.style.configure("Default.TLabel", foreground=fg)

    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.apply_theme()
        self.build_settings_screen() # Refresh to update toggle text

    # --- SCREEN DEFENSE ---
    def apply_screen_defense(self):
        try:
            user32 = ctypes.windll.user32
            user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
            user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
            hwnd = int(self.wm_frame(), 16)
            success = user32.SetWindowDisplayAffinity(hwnd, 17)
            if not success:
                user32.SetWindowDisplayAffinity(hwnd, 1)
        except Exception:
            pass

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

    # --- SCREEN: LOGIN ---
    def build_login_screen(self):
        self.clear_window()
        ttk.Label(self, text="🔒 Cipher Vault", font=("SegoeUI", 26, "bold")).pack(pady=(50, 10))
        status_text = "Use the Secure Keyboard to Unlock:" if os.path.exists(DATA_FILE) else "Create Master Password (Secure Keyboard):"
        ttk.Label(self, text=status_text).pack(pady=5)
        self.master_pwd_entry = ttk.Entry(self, show="*", width=35, font=("SegoeUI", 14))
        self.master_pwd_entry.pack(pady=10)
        self.master_pwd_entry.bind("<Key>", lambda e: "break")
        self.build_virtual_keyboard(self, self.master_pwd_entry, "Login", self.attempt_login)

    def attempt_login(self):
        pwd = self.master_pwd_entry.get()
        if not pwd: return
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

        ttk.Label(inner_center_frame, text="Password:").grid(row=2, column=0, padx=5, pady=(10, 2), sticky="e")
        self.pwd_entry = ttk.Entry(inner_center_frame, width=35)
        self.pwd_entry.grid(row=2, column=1, padx=5, pady=(10, 2))
        
        # FEATURE 2: Dynamic Strength Label
        self.strength_label = ttk.Label(inner_center_frame, text="", font=("SegoeUI", 9, "bold"), style="Default.TLabel")
        self.strength_label.grid(row=3, column=1, sticky="w", padx=5, pady=(0, 10))
        self.pwd_entry.bind("<KeyRelease>", self.check_password_strength)

        btn_frame = tk.Frame(self, bg=self.cget('bg'))
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="⚡ Generate", command=self.ui_generate_password).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="📋 Copy", command=self.copy_password).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="💾 Save", command=self.ui_save_password).grid(row=0, column=2, padx=5)
        
        ttk.Separator(self, orient='horizontal').pack(fill='x', padx=40, pady=10)
        
        ttk.Button(self, text="View & Manage Vault", command=self.route_vault_access).pack(pady=5)
        ttk.Button(self, text="⚙️ Settings", command=self.build_settings_screen).pack(pady=5)
        ttk.Button(self, text="🔒 Lock Vault Now", command=self.lock_vault).pack(pady=(15, 5))

    # --- DASHBOARD HELPER METHODS ---
    def check_password_strength(self, event=None):
        pwd = self.pwd_entry.get()
        length = len(pwd)
        score = sum([any(c.isupper() for c in pwd), any(c.islower() for c in pwd), 
                     any(c.isdigit() for c in pwd), any(c in string.punctuation for c in pwd)])
        
        if length == 0:
            self.strength_label.configure(text="", style="Default.TLabel")
        elif length < 8 or score < 2:
            self.strength_label.configure(text="Strength: Weak", style="Weak.TLabel")
        elif length < 12 or score < 4:
            self.strength_label.configure(text="Strength: Medium", style="Medium.TLabel")
        else:
            self.strength_label.configure(text="Strength: Strong", style="Strong.TLabel")

    def ui_generate_password(self):
        self.pwd_entry.delete(0, tk.END)
        new_password = self.manager.generate_password()
        self.pwd_entry.insert(0, new_password)
        self.check_password_strength() # Update visual meter
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

    def ui_save_password(self):
        site = self.site_entry.get().strip()
        user = self.user_entry.get().strip()
        pwd = self.pwd_entry.get().strip()
        if not site or not user or not pwd: return
        if site == "__vault_password_hash__": return
        self.manager.add_password(site, user, pwd)
        messagebox.showinfo("Success", f"Credentials for {site} saved securely!")
        self.site_entry.delete(0, tk.END)
        self.user_entry.delete(0, tk.END)
        self.pwd_entry.delete(0, tk.END)
        self.strength_label.configure(text="")

    # --- SCREEN: VAULT ROUTING ---
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
            if not p1 or p1 != confirm_entry.get() or p1 == self.current_master_pwd: return
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
            selected = tree.selection()
            if not selected: return
            key = selected[0] 
            vals = tree.item(key, "values")
            actual_password = self.manager.passwords[key]['password']
            if vals[2] == "********":
                tree.item(key, values=(vals[0], vals[1], actual_password))
            else:
                tree.item(key, values=(vals[0], vals[1], "********"))

        def delete_selected():
            selected = tree.selection()
            if not selected: return
            key = selected[0] 
            if messagebox.askyesno("Confirm Delete", f"Delete password for '{tree.item(key, 'values')[0]}'?"):
                self.manager.delete_password(key)
                self.build_vault_view_screen() 

        btn_frame = tk.Frame(self, bg=self.cget('bg'))
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="👁️ Show / Hide", command=toggle_password_visibility).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="🗑️ Delete", command=delete_selected).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="← Back", command=self.build_dashboard_screen).pack(side="left", padx=10)

    def refresh_table(self, tree):
        for item in tree.get_children():
            tree.delete(item)
        for key, data in self.manager.passwords.items():
            if key == "__vault_password_hash__": continue
            tree.insert("", tk.END, iid=key, values=(data['actual_site'], data['username'], "********"))

    # --- SCREEN: SETTINGS ---
    # --- SCREEN: SETTINGS ---
    def build_settings_screen(self):
        self.clear_window()
        ttk.Label(self, text="⚙️ Settings", font=("SegoeUI", 18, "bold")).pack(pady=(15, 5))

        # FEATURE 3: Dark Mode Toggle
        appearance_frame = ttk.LabelFrame(self, text=" Appearance ", padding=10)
        appearance_frame.pack(fill="x", padx=40, pady=5)
        ttk.Label(appearance_frame, text=f"Active Theme: {self.current_theme.capitalize()} Mode").pack(side="left", padx=5)
        ttk.Button(appearance_frame, text="🌓 Toggle Theme", command=self.toggle_theme).pack(side="right", padx=5)

        # Update Master Password Section
        master_frame = ttk.LabelFrame(self, text=" Change Master Password ", padding=10)
        master_frame.pack(fill="x", padx=40, pady=5)
        ttk.Label(master_frame, text="Current Master Password:").pack(anchor="w")
        current_master = ttk.Entry(master_frame, show="*")
        current_master.pack(fill="x", pady=(0, 5))
        ttk.Label(master_frame, text="New Master Password:").pack(anchor="w")
        new_master = ttk.Entry(master_frame, show="*")
        new_master.pack(fill="x", pady=(0, 5))

        def update_master():
            if current_master.get() != self.current_master_pwd:
                messagebox.showerror("Error", "Current Master Password is incorrect.")
                return
            if not new_master.get():
                messagebox.showerror("Error", "New password cannot be empty.")
                return
            
            self.manager.change_master_password(new_master.get())
            self.current_master_pwd = new_master.get()
            messagebox.showinfo("Success", "Master Password updated! Vault re-encrypted.")
            self.build_settings_screen() # Refresh to clear boxes
            
        ttk.Button(master_frame, text="Update Master Password", command=update_master).pack(pady=5)

        # Update Vault (Secondary) Password Section
        sec_frame = ttk.LabelFrame(self, text=" Change Vault Password ", padding=10)
        sec_frame.pack(fill="x", padx=40, pady=5)
        ttk.Label(sec_frame, text="Current Vault Password:").pack(anchor="w")
        current_sec_entry = ttk.Entry(sec_frame, show="*")
        current_sec_entry.pack(fill="x", pady=(0, 5))
        ttk.Label(sec_frame, text="New Vault Password:").pack(anchor="w")
        new_sec_entry = ttk.Entry(sec_frame, show="*")
        new_sec_entry.pack(fill="x", pady=(0, 5))

        def update_secondary():
            if "__vault_password_hash__" not in self.manager.passwords:
                messagebox.showerror("Error", "Vault password not set up yet. Open the vault first.")
                return
                
            hashed_current = hashlib.sha256(current_sec_entry.get().encode()).hexdigest()
            if hashed_current != self.manager.passwords["__vault_password_hash__"]:
                messagebox.showerror("Error", "Current Vault Password is incorrect.")
                return
                
            new_pwd = new_sec_entry.get()
            if not new_pwd:
                messagebox.showerror("Error", "New password cannot be empty.")
                return
            if new_pwd == self.current_master_pwd:
                messagebox.showerror("Error", "Secondary password must be different from Master.")
                return
                
            self.manager.change_secondary_password(new_pwd)
            messagebox.showinfo("Success", "Vault Password successfully updated!")
            self.build_settings_screen() # Refresh to clear boxes
            
        ttk.Button(sec_frame, text="Update Vault Password", command=update_secondary).pack(pady=5)

        ttk.Button(self, text="← Back to Dashboard", command=self.build_dashboard_screen).pack(pady=10)

if __name__ == "__main__":
    app = App()
    app.mainloop()