#!/usr/bin/env python3
"""
Password Manager & Generator — GUI version (Tkinter)
=====================================================
Graphical application for Linux Mint to generate complex dual passwords
and store them in an encrypted vault.
Dependencies:
    sudo apt install python3-tk
    pip install cryptography
Run:
    python3 password_manager_gui.py
"""
import os
import json
import time
import base64
import hashlib
import secrets
import string
import math
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.fernet import Fernet, InvalidToken
VAULT_PATH = Path(__file__).resolve().parent / "password_vault.enc"
SALT_SIZE = 16
TARGET_KDF_SECONDS = 1.0
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAX_N_POW = 20
SCRYPT_MAX_MEM_MB = 512
CLIPBOARD_CLEAR_DELAY_MS = 30000  # Auto-clear clipboard after 30 sec
# ----------------------------------------------------------------------
# Password generation logic
# ----------------------------------------------------------------------
def generate_single_password(length: int, use_upper=True, use_lower=True,
                             use_digits=True, use_symbols=True,
                             exclude_ambiguous=False) -> str:
    ambiguous = "Il1O0"
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{}<>?/.,;:~")
    if not pools:
        raise ValueError("Select at least one character type.")
    if exclude_ambiguous:
        pools = ["".join(c for c in p if c not in ambiguous) for p in pools]
    all_chars = "".join(pools)
    if length < len(pools):
        raise ValueError("Length is too small for the selected character types.")
    password_chars = [secrets.choice(pool) for pool in pools]
    password_chars += [secrets.choice(all_chars) for _ in range(length - len(pools))]
    # Fisher-Yates shuffle using secrets
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
    return "".join(password_chars)
def generate_dual_password(len1: int, len2: int, use_upper=True, use_lower=True,
                           use_digits=True, use_symbols=True,
                           exclude_ambiguous=False, allow_equal_lengths=False) -> tuple[str, str, int, int]:
    if not allow_equal_lengths and len1 == len2:
        choices = [l for l in range(16, 25) if l != len1]
        len2 = secrets.choice(choices)
    p1 = generate_single_password(len1, use_upper, use_lower, use_digits, use_symbols, exclude_ambiguous)
    p2 = generate_single_password(len2, use_upper, use_lower, use_digits, use_symbols, exclude_ambiguous)
    combined_password = f"{p1}-{p2}"
    length_str = f"{len1}-{len2}"
    return combined_password, length_str, len1, len2
def entropy_bits(length: int, use_upper: bool, use_lower: bool, use_digits: bool, use_symbols: bool) -> float:
    pool_size = 0
    pool_size += 26 if use_lower else 0
    pool_size += 26 if use_upper else 0
    pool_size += 10 if use_digits else 0
    pool_size += 28 if use_symbols else 0
    if pool_size == 0:
        return 0.0
    return length * math.log2(pool_size)
def strength_label(bits: float) -> str:
    if bits < 40:
        return "Weak"
    elif bits < 60:
        return "Medium"
    elif bits < 80:
        return "Good"
    return "Very strong"
# ----------------------------------------------------------------------
# Encrypted storage (Vault)
# ----------------------------------------------------------------------
def derive_key(master_password: str, salt: bytes, n_pow: int, r: int, p: int) -> bytes:
    n = 2 ** n_pow
    mem_needed = 128 * n * r * p
    maxmem = mem_needed * 2 + (16 * 1024 * 1024)
    raw_key = hashlib.scrypt(master_password.encode("utf-8"), salt=salt,
                             n=n, r=r, p=p, dklen=32, maxmem=maxmem)
    return base64.urlsafe_b64encode(raw_key)
def calibrate_scrypt(target_seconds: float = TARGET_KDF_SECONDS,
                     r: int = SCRYPT_R, p: int = SCRYPT_P) -> int:
    salt = os.urandom(SALT_SIZE)
    n_pow = 14
    while True:
        n = 2 ** n_pow
        mem_mb = (128 * n * r * p) / (1024 * 1024)
        maxmem = int(mem_mb * 1024 * 1024 * 2 + 16 * 1024 * 1024)
        start = time.perf_counter()
        hashlib.scrypt(b"calibration-sample", salt=salt, n=n, r=r, p=p,
                       dklen=32, maxmem=maxmem)
        elapsed = time.perf_counter() - start
        if elapsed >= target_seconds or mem_mb >= SCRYPT_MAX_MEM_MB or n_pow >= SCRYPT_MAX_N_POW:
            return n_pow
        n_pow += 1
def _read_header():
    if not VAULT_PATH.exists():
        return None
    raw = VAULT_PATH.read_bytes()
    if len(raw) < SALT_SIZE + 3:
        return None
    salt = raw[:SALT_SIZE]
    n_pow = raw[SALT_SIZE]
    r = raw[SALT_SIZE + 1]
    p = raw[SALT_SIZE + 2]
    return salt, n_pow, r, p
def load_vault(master_password: str) -> dict:
    if not VAULT_PATH.exists():
        return {}
    raw = VAULT_PATH.read_bytes()
    if len(raw) <= SALT_SIZE + 3:
        raise ValueError("The vault file is corrupt or empty.")
    salt = raw[:SALT_SIZE]
    n_pow, r, p = raw[SALT_SIZE], raw[SALT_SIZE + 1], raw[SALT_SIZE + 2]
    token = raw[SALT_SIZE + 3:]
    key = derive_key(master_password, salt, n_pow, r, p)
    try:
        decrypted = Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError("Wrong master password or corrupt file.")
    
    vault_data = json.loads(decrypted.decode("utf-8"))
    # Migration: convert single objects into lists
    for service, entries in list(vault_data.items()):
        if isinstance(entries, dict):
            vault_data[service] = [entries]
    return vault_data
def save_vault(data: dict, master_password: str) -> int:
    header = _read_header()
    if header is not None:
        salt, n_pow, r, p = header
    else:
        salt = os.urandom(SALT_SIZE)
        r, p = SCRYPT_R, SCRYPT_P
        n_pow = calibrate_scrypt(r=r, p=p)
    key = derive_key(master_password, salt, n_pow, r, p)
    encrypted = Fernet(key).encrypt(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
    header_bytes = salt + bytes([n_pow, r, p])
    
    # Atomic write to avoid corruption on unexpected crash
    temp_path = VAULT_PATH.with_suffix(".tmp")
    temp_path.write_bytes(header_bytes + encrypted)
    os.chmod(temp_path, 0o600)
    temp_path.replace(VAULT_PATH)
    
    return n_pow
# ----------------------------------------------------------------------
# GUI Components
# ----------------------------------------------------------------------
class LoginDialog(simpledialog.Dialog):
    def __init__(self, parent, title, prompt, confirm=False):
        self.prompt = prompt
        self.confirm = confirm
        self.result_password = None
        super().__init__(parent, title)
    def body(self, master):
        ttk.Label(master, text=self.prompt).grid(row=0, column=0, columnspan=2, pady=(0, 8))
        ttk.Label(master, text="Password:").grid(row=1, column=0, sticky="e", padx=4)
        self.entry1 = ttk.Entry(master, show="•", width=30)
        self.entry1.grid(row=1, column=1, pady=4, padx=4)
        if self.confirm:
            ttk.Label(master, text="Repeat:").grid(row=2, column=0, sticky="e", padx=4)
            self.entry2 = ttk.Entry(master, show="•", width=30)
            self.entry2.grid(row=2, column=1, pady=4, padx=4)
        return self.entry1
    def validate(self):
        pwd1 = self.entry1.get()
        if not pwd1:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            return False
        if self.confirm:
            pwd2 = self.entry2.get()
            if pwd1 != pwd2:
                messagebox.showerror("Error", "Passwords do not match.", parent=self)
                return False
        return True
    def apply(self):
        self.result_password = self.entry1.get()
class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dual Password Manager")
        self.geometry("820x600")
        self.minsize(740, 520)
        self.master_password = None
        self.vault = {}
        self.clipboard_job = None
        self._configure_styles()
        self._build_ui()
        self._unlock_or_create_vault()
    def _configure_styles(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.gen_tab = ttk.Frame(notebook)
        self.vault_tab = ttk.Frame(notebook)
        notebook.add(self.gen_tab, text="Dual Password Generator")
        notebook.add(self.vault_tab, text="Saved passwords")
        self._build_generator_tab()
        self._build_vault_tab()
        menubar = tk.Menu(self)
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Change master password", command=self.change_master_password)
        settings_menu.add_separator()
        settings_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        self.config(menu=menubar)
    def _build_generator_tab(self):
        frame = self.gen_tab
        pad = {"padx": 10, "pady": 6}
        length_frame = ttk.LabelFrame(frame, text="Length of both passwords (16 to 24 characters)")
        length_frame.pack(fill="x", **pad)
        ttk.Label(length_frame, text="Password 1:").grid(row=0, column=0, padx=8, pady=6)
        self.len1_var = tk.IntVar(value=18)
        self.len1_scale = ttk.Scale(length_frame, from_=16, to=24, orient="horizontal",
                                    variable=self.len1_var, command=self._on_length_change)
        self.len1_scale.grid(row=0, column=1, sticky="ew", padx=8, pady=6)
        self.len1_display = ttk.Label(length_frame, text="18", width=4)
        self.len1_display.grid(row=0, column=2, padx=4)
        ttk.Label(length_frame, text="Password 2:").grid(row=1, column=0, padx=8, pady=6)
        self.len2_var = tk.IntVar(value=23)
        self.len2_scale = ttk.Scale(length_frame, from_=16, to=24, orient="horizontal",
                                    variable=self.len2_var, command=self._on_length_change)
        self.len2_scale.grid(row=1, column=1, sticky="ew", padx=8, pady=6)
        self.len2_display = ttk.Label(length_frame, text="23", width=4)
        self.len2_display.grid(row=1, column=2, padx=4)
        length_frame.columnconfigure(1, weight=1)
        opts_frame = ttk.LabelFrame(frame, text="Character types")
        opts_frame.pack(fill="x", **pad)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        self.allow_equal = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts_frame, text="Uppercase (A-Z)", variable=self.use_upper,
                        command=self._update_strength).grid(row=0, column=0, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(opts_frame, text="Lowercase (a-z)", variable=self.use_lower,
                        command=self._update_strength).grid(row=0, column=1, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(opts_frame, text="Digits (0-9)", variable=self.use_digits,
                        command=self._update_strength).grid(row=1, column=0, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(opts_frame, text="Symbols (!@#$...)", variable=self.use_symbols,
                        command=self._update_strength).grid(row=1, column=1, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(opts_frame, text="Exclude ambiguous characters (Il1O0)",
                        variable=self.exclude_ambiguous).grid(row=2, column=0, columnspan=2, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(opts_frame, text="Allow equal lengths (random only)",
                        variable=self.allow_equal).grid(row=3, column=0, columnspan=2, sticky="w", padx=8, pady=4)
        result_frame = ttk.LabelFrame(frame, text="Generated dual password")
        result_frame.pack(fill="x", **pad)
        self.result_var = tk.StringVar(value="")
        result_entry = ttk.Entry(result_frame, textvariable=self.result_var, font=("Monospace", 11), state="readonly")
        result_entry.pack(side="left", fill="x", expand=True, padx=8, pady=8)
        ttk.Button(result_frame, text="Copy", command=self.copy_password).pack(side="left", padx=4)
        self.info_var = tk.StringVar(value="Length: - | Strength: -")
        ttk.Label(frame, textvariable=self.info_var, font=("Sans", 9, "bold")).pack(anchor="w", padx=12, pady=4)
        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=8)
        ttk.Button(btns, text="Generate dual password", command=self.on_generate).pack(side="left", padx=8)
        ttk.Button(btns, text="Save to vault...", command=self.on_save_generated).pack(side="left", padx=8)
        self._update_strength()
    def _build_vault_tab(self):
        frame = self.vault_tab
        pad = {"padx": 8, "pady": 4}
        # Search and actions bar
        top_bar = ttk.Frame(frame)
        top_bar.pack(fill="x", **pad)
        ttk.Label(top_bar, text="Search:").pack(side="left", padx=(4, 2))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.refresh_vault_list())
        ttk.Entry(top_bar, textvariable=self.search_var, width=20).pack(side="left", padx=(0, 10))
        ttk.Button(top_bar, text="Add new", command=self.add_manual_entry).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Edit", command=self.edit_selected_entry).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Delete", command=self.delete_selected_entry).pack(side="left", padx=4)
        columns = ("service", "username")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("service", text="Service / Site")
        self.tree.heading("username", text="Username")
        self.tree.column("service", width=250)
        self.tree.column("username", width=250)
        self.tree.pack(fill="both", expand=True, padx=8, pady=4)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_entry)
        detail_frame = ttk.LabelFrame(frame, text="Details")
        detail_frame.pack(fill="x", padx=8, pady=8)
        ttk.Label(detail_frame, text="Password:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.detail_password_var = tk.StringVar(value="")
        self.detail_password_entry = ttk.Entry(detail_frame, textvariable=self.detail_password_var,
                                               show="•", width=36, state="readonly")
        self.detail_password_entry.grid(row=0, column=1, sticky="w", padx=6, pady=4)
        self.show_pwd_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(detail_frame, text="Show", variable=self.show_pwd_var,
                        command=self._toggle_detail_password).grid(row=0, column=2, padx=4)
        ttk.Button(detail_frame, text="Copy", command=self.copy_detail_password).grid(row=0, column=3, padx=4)
        ttk.Label(detail_frame, text="Notes:").grid(row=1, column=0, sticky="ne", padx=6, pady=4)
        self.detail_notes_var = tk.StringVar(value="")
        ttk.Label(detail_frame, textvariable=self.detail_notes_var, wraplength=450, justify="left").grid(
            row=1, column=1, columnspan=3, sticky="w", padx=6, pady=4)
    # ---------------- Security helpers ----------------
    def _safe_copy_to_clipboard(self, text: str):
        """Copy text and clear it automatically after a delay."""
        self.clipboard_clear()
        self.clipboard_append(text)
        
        if self.clipboard_job:
            self.after_cancel(self.clipboard_job)
        self.clipboard_job = self.after(
            CLIPBOARD_CLEAR_DELAY_MS,
            lambda: self.clipboard_clear() if self.clipboard_get() == text else None
        )
        messagebox.showinfo("Copied", "Password copied! The clipboard will be cleared in 30 seconds.")
    # ---------------- Lock / unlock vault ----------------
    def _unlock_or_create_vault(self):
        vault_exists = VAULT_PATH.exists()
        title = "Unlock vault" if vault_exists else "Create new vault"
        prompt = ("A password file already exists.\nEnter your master password:"
                  if vault_exists else
                  "No existing vault was found.\nSet a master password:")
        while True:
            dlg = LoginDialog(self, title, prompt, confirm=not vault_exists)
            pwd = dlg.result_password
            if pwd is None:
                self.destroy()
                return
            try:
                self.vault = load_vault(pwd)
                self.master_password = pwd
                break
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        if not vault_exists:
            n_pow = save_vault(self.vault, self.master_password)
            mem_mb = (128 * (2 ** n_pow) * SCRYPT_R * SCRYPT_P) / (1024 * 1024)
            messagebox.showinfo(
                "Success",
                f"Vault created successfully!\nCalibration: scrypt N=2^{n_pow} (~{mem_mb:.0f} MB RAM)."
            )
        self.refresh_vault_list()
    def change_master_password(self):
        dlg = LoginDialog(self, "New master password", "Enter the new master password:", confirm=True)
        new_pwd = dlg.result_password
        if not new_pwd:
            return
        
        save_vault(self.vault, new_pwd)
        self.master_password = new_pwd
        messagebox.showinfo("Done", "Master password changed successfully.")
    # ---------------- Generator ----------------
    def _on_length_change(self, _event=None):
        l1 = int(float(self.len1_var.get()))
        l2 = int(float(self.len2_var.get()))
        self.len1_display.config(text=str(l1))
        self.len2_display.config(text=str(l2))
        self._update_strength()
    def _update_strength(self):
        l1 = int(float(self.len1_var.get()))
        l2 = int(float(self.len2_var.get()))
        total_len = l1 + l2
        bits = entropy_bits(total_len, self.use_upper.get(), self.use_lower.get(),
                            self.use_digits.get(), self.use_symbols.get())
        self.info_var.set(f"Format: {l1}-{l2} ({total_len + 1} characters) | Strength: {strength_label(bits)} (~{bits:.0f} bits of entropy)")
    def on_generate(self):
        l1 = int(float(self.len1_var.get()))
        l2 = int(float(self.len2_var.get()))
        try:
            pwd, fmt_len, used_l1, used_l2 = generate_dual_password(
                l1, l2, self.use_upper.get(), self.use_lower.get(),
                self.use_digits.get(), self.use_symbols.get(),
                self.exclude_ambiguous.get(), self.allow_equal.get()
            )
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
        self.len1_var.set(used_l1)
        self.len2_var.set(used_l2)
        self.len1_display.config(text=str(used_l1))
        self.len2_display.config(text=str(used_l2))
        self.result_var.set(pwd)
        self._update_strength()
    def copy_password(self):
        pwd = self.result_var.get()
        if not pwd:
            messagebox.showwarning("No password", "Generate a password first.")
            return
        self._safe_copy_to_clipboard(pwd)
    def on_save_generated(self):
        pwd = self.result_var.get()
        if not pwd:
            messagebox.showwarning("No password", "Generate a password first.")
            return
        self._open_entry_dialog(prefilled_password=pwd)
    # ---------------- Vault ----------------
    def refresh_vault_list(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
            
        search_term = self.search_var.get().lower().strip()
        for service in sorted(self.vault.keys()):
            entries = self.vault[service]
            for idx, entry in enumerate(entries):
                username = entry.get("username", "")
                if search_term and (search_term not in service.lower() and search_term not in username.lower()):
                    continue
                row_id = f"{service}::{idx}"
                self.tree.insert("", "end", iid=row_id, values=(service, username))
    def on_select_entry(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        row_id = sel[0]
        service, idx_str = row_id.split("::")
        idx = int(idx_str)
        
        entry = self.vault.get(service, [])[idx]
        self.show_pwd_var.set(False)
        self.detail_password_entry.config(state="normal", show="•")
        self.detail_password_var.set(entry.get("password", ""))
        self.detail_password_entry.config(state="readonly")
        self.detail_notes_var.set(entry.get("notes", ""))
    def _toggle_detail_password(self):
        show = self.show_pwd_var.get()
        self.detail_password_entry.config(state="normal")
        self.detail_password_entry.config(show="" if show else "•")
        self.detail_password_entry.config(state="readonly")
    def copy_detail_password(self):
        pwd = self.detail_password_var.get()
        if not pwd:
            return
        self._safe_copy_to_clipboard(pwd)
    def add_manual_entry(self):
        self._open_entry_dialog()
    def edit_selected_entry(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Select an entry to edit.")
            return
        
        service, idx_str = sel[0].split("::")
        idx = int(idx_str)
        entry = self.vault[service][idx]
        self._open_entry_dialog(
            service_name=service,
            username=entry.get("username", ""),
            prefilled_password=entry.get("password", ""),
            notes=entry.get("notes", ""),
            edit_target=(service, idx)
        )
    def _open_entry_dialog(self, service_name="", username="", prefilled_password="", notes="", edit_target=None):
        top = tk.Toplevel(self)
        top.title("Edit entry" if edit_target else "New entry")
        top.geometry("420x320")
        top.transient(self)
        top.grab_set()
        pad = {"padx": 8, "pady": 6}
        ttk.Label(top, text="Service/site:").grid(row=0, column=0, sticky="e", **pad)
        service_var = tk.StringVar(value=service_name)
        ttk.Entry(top, textvariable=service_var, width=30).grid(row=0, column=1, **pad)
        ttk.Label(top, text="Username:").grid(row=1, column=0, sticky="e", **pad)
        username_var = tk.StringVar(value=username)
        ttk.Entry(top, textvariable=username_var, width=30).grid(row=1, column=1, **pad)
        ttk.Label(top, text="Password:").grid(row=2, column=0, sticky="e", **pad)
        password_var = tk.StringVar(value=prefilled_password or "")
        pwd_entry = ttk.Entry(top, textvariable=password_var, width=30)
        pwd_entry.grid(row=2, column=1, **pad)
        def gen_new():
            p, _, _, _ = generate_dual_password(
                18, 23, self.use_upper.get(), self.use_lower.get(),
                self.use_digits.get(), self.use_symbols.get(),
                self.exclude_ambiguous.get()
            )
            password_var.set(p)
        ttk.Button(top, text="Generate", command=gen_new).grid(row=2, column=2, padx=4)
        ttk.Label(top, text="Notes:").grid(row=3, column=0, sticky="ne", **pad)
        notes_text = tk.Text(top, width=30, height=4)
        notes_text.grid(row=3, column=1, **pad)
        if notes:
            notes_text.insert("1.0", notes)
        def do_save():
            new_service = service_var.get().strip()
            if not new_service:
                messagebox.showerror("Error", "Service name is required.", parent=top)
                return
            new_entry = {
                "username": username_var.get().strip(),
                "password": password_var.get(),
                "notes": notes_text.get("1.0", "end").strip(),
            }
            # On edit, delete the old record first
            if edit_target:
                old_service, old_idx = edit_target
                del self.vault[old_service][old_idx]
                if not self.vault[old_service]:
                    del self.vault[old_service]
            if new_service not in self.vault:
                self.vault[new_service] = []
            self.vault[new_service].append(new_entry)
            save_vault(self.vault, self.master_password)
            self.refresh_vault_list()
            top.destroy()
            messagebox.showinfo("Done", f"Entry for '{new_service}' has been saved.")
        ttk.Button(top, text="Save", command=do_save).grid(row=4, column=0, columnspan=2, pady=12)
    def delete_selected_entry(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Select an entry from the list first.")
            return
        row_id = sel[0]
        service, idx_str = row_id.split("::")
        idx = int(idx_str)
        username = self.vault[service][idx].get("username", "")
        msg = f"Really delete account '{username}' for '{service}'?" if username else f"Really delete this entry for '{service}'?"
        if messagebox.askyesno("Confirm", msg):
            del self.vault[service][idx]
            if not self.vault[service]:
                del self.vault[service]
            save_vault(self.vault, self.master_password)
            self.refresh_vault_list()
            self.detail_password_var.set("")
            self.detail_notes_var.set("")
if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
