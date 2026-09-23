#!/usr/bin/env python3
"""
Password Manager & Generator — GUI версия (Tkinter)
=====================================================
Графично приложение за Linux Mint за генериране на сложни пароли
и криптирано съхранение на пароли.

Ако при стартиране получиш "ModuleNotFoundError: No module named 'tkinter'",
инсталирай пакета с:
    sudo apt install python3-tk

Стартиране:
    python3 password_manager_gui.py

Криптиране: scrypt (RFC 7914, вграден в hashlib — без нужда от pip install)
за извеждане на ключ от главната парола + Fernet (AES) за самите данни.
scrypt е "memory-hard" (изисква много RAM на опит), което го прави
значително по-устойчив на GPU/ASIC атаки от обикновен PBKDF2 — същият
принцип, който LUKS2 и повечето модерни password manager-и ползват
чрез Argon2id.
Файлът с пароли (password_vault.enc) се пази в СЪЩАТА ПАПКА като скрипта —
това го прави преносим: копирай папката (скрипт + .enc файл) на
флашка/външен диск и работи на всеки компютър с Python и tkinter.
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

# Трезорът се пази ДО скрипта (не в home папката), за да е портативен —
# ако копираш скрипта и .enc файла на флашка/SSD, работят заедно навсякъде.
VAULT_PATH = Path(__file__).resolve().parent / "password_vault.enc"
SALT_SIZE = 16
TARGET_KDF_SECONDS = 1.0
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAX_N_POW = 20
SCRYPT_MAX_MEM_MB = 512


# ----------------------------------------------------------------------
# Логика за генериране на пароли (без промяна на алгоритъма от CLI версията)
# ----------------------------------------------------------------------

def generate_password(length=16, use_upper=True, use_lower=True,
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
        raise ValueError("Избери поне един тип символи.")

    if exclude_ambiguous:
        pools = ["".join(c for c in p if c not in ambiguous) for p in pools]

    all_chars = "".join(pools)
    if length < len(pools):
        raise ValueError("Дължината е твърде малка за избраните типове символи.")

    password_chars = [secrets.choice(pool) for pool in pools]
    password_chars += [secrets.choice(all_chars) for _ in range(length - len(pools))]

    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def entropy_bits(length, use_upper, use_lower, use_digits, use_symbols) -> float:
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
        return "Слаба"
    elif bits < 60:
        return "Средна"
    elif bits < 80:
        return "Добра"
    return "Много силна"


# ----------------------------------------------------------------------
# Криптирано съхранение (Vault) — идентично на CLI версията
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
    salt = raw[:SALT_SIZE]
    n_pow = raw[SALT_SIZE]
    r = raw[SALT_SIZE + 1]
    p = raw[SALT_SIZE + 2]
    return salt, n_pow, r, p


def load_vault(master_password: str) -> dict:
    if not VAULT_PATH.exists():
        return {}
    raw = VAULT_PATH.read_bytes()
    salt = raw[:SALT_SIZE]
    n_pow, r, p = raw[SALT_SIZE], raw[SALT_SIZE + 1], raw[SALT_SIZE + 2]
    token = raw[SALT_SIZE + 3:]
    key = derive_key(master_password, salt, n_pow, r, p)
    try:
        decrypted = Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError("Грешна главна парола или повреден файл.")
    return json.loads(decrypted.decode("utf-8"))


def save_vault(data: dict, master_password: str) -> int:
    """Връща n_pow (за евентуално показване на потребителя)."""
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
    VAULT_PATH.write_bytes(header_bytes + encrypted)
    os.chmod(VAULT_PATH, 0o600)
    return n_pow


# ----------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------

class LoginDialog(simpledialog.Dialog):
    """Диалог за въвеждане на главна парола при стартиране."""

    def __init__(self, parent, title, prompt, confirm=False):
        self.prompt = prompt
        self.confirm = confirm
        self.result_password = None
        super().__init__(parent, title)

    def body(self, master):
        tk.Label(master, text=self.prompt).grid(row=0, column=0, columnspan=2, pady=(0, 8))
        tk.Label(master, text="Парола:").grid(row=1, column=0, sticky="e")
        self.entry1 = tk.Entry(master, show="•", width=30)
        self.entry1.grid(row=1, column=1, pady=4)

        if self.confirm:
            tk.Label(master, text="Повтори:").grid(row=2, column=0, sticky="e")
            self.entry2 = tk.Entry(master, show="•", width=30)
            self.entry2.grid(row=2, column=1, pady=4)

        return self.entry1

    def validate(self):
        pwd1 = self.entry1.get()
        if not pwd1:
            messagebox.showerror("Грешка", "Паролата не може да е празна.", parent=self)
            return False
        if self.confirm:
            pwd2 = self.entry2.get()
            if pwd1 != pwd2:
                messagebox.showerror("Грешка", "Паролите не съвпадат.", parent=self)
                return False
        return True

    def apply(self):
        self.result_password = self.entry1.get()


class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Мениджър на пароли")
        self.geometry("760x520")
        self.minsize(680, 460)

        self.master_password = None
        self.vault = {}

        self._build_ui()
        self._unlock_or_create_vault()

    # ---------------- UI изграждане ----------------

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.gen_tab = ttk.Frame(notebook)
        self.vault_tab = ttk.Frame(notebook)
        notebook.add(self.gen_tab, text="Генератор на пароли")
        notebook.add(self.vault_tab, text="Запазени пароли")

        self._build_generator_tab()
        self._build_vault_tab()

        menubar = tk.Menu(self)
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Смени главната парола", command=self.change_master_password)
        settings_menu.add_separator()
        settings_menu.add_command(label="Изход", command=self.quit)
        menubar.add_cascade(label="Настройки", menu=settings_menu)
        self.config(menu=menubar)

    def _build_generator_tab(self):
        frame = self.gen_tab
        pad = {"padx": 8, "pady": 6}

        # Дължина
        length_frame = ttk.LabelFrame(frame, text="Дължина на паролата")
        length_frame.pack(fill="x", **pad)
        self.length_var = tk.IntVar(value=16)
        self.length_scale = ttk.Scale(length_frame, from_=6, to=64, orient="horizontal",
                                       variable=self.length_var, command=self._on_length_change)
        self.length_scale.pack(side="left", fill="x", expand=True, padx=8, pady=8)
        self.length_display = ttk.Label(length_frame, text="16", width=4)
        self.length_display.pack(side="left", padx=(0, 8))

        # Опции
        opts_frame = ttk.LabelFrame(frame, text="Типове символи")
        opts_frame.pack(fill="x", **pad)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)

        ttk.Checkbutton(opts_frame, text="Главни букви (A-Z)", variable=self.use_upper,
                         command=self._update_strength).grid(row=0, column=0, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(opts_frame, text="Малки букви (a-z)", variable=self.use_lower,
                         command=self._update_strength).grid(row=0, column=1, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(opts_frame, text="Цифри (0-9)", variable=self.use_digits,
                         command=self._update_strength).grid(row=1, column=0, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(opts_frame, text="Символи (!@#$...)", variable=self.use_symbols,
                         command=self._update_strength).grid(row=1, column=1, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(opts_frame, text="Изключи объркващи символи (Il1O0)",
                         variable=self.exclude_ambiguous).grid(row=2, column=0, columnspan=2, sticky="w", padx=8, pady=4)

        # Резултат
        result_frame = ttk.LabelFrame(frame, text="Генерирана парола")
        result_frame.pack(fill="x", **pad)
        self.result_var = tk.StringVar(value="")
        result_entry = ttk.Entry(result_frame, textvariable=self.result_var, font=("Monospace", 13), state="readonly")
        result_entry.pack(side="left", fill="x", expand=True, padx=8, pady=8)
        ttk.Button(result_frame, text="Копирай", command=self.copy_password).pack(side="left", padx=4)

        self.strength_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.strength_var).pack(anchor="w", padx=12)

        # Бутони
        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=12)
        ttk.Button(btns, text="Генерирай парола", command=self.on_generate).pack(side="left", padx=8)
        ttk.Button(btns, text="Запази в трезора...", command=self.on_save_generated).pack(side="left", padx=8)

        self._update_strength()

    def _build_vault_tab(self):
        frame = self.vault_tab
        pad = {"padx": 8, "pady": 6}

        top_btns = ttk.Frame(frame)
        top_btns.pack(fill="x", **pad)
        ttk.Button(top_btns, text="Добави ръчно", command=self.add_manual_entry).pack(side="left", padx=4)
        ttk.Button(top_btns, text="Изтрий избрания", command=self.delete_selected_entry).pack(side="left", padx=4)
        ttk.Button(top_btns, text="Обнови списъка", command=self.refresh_vault_list).pack(side="left", padx=4)

        columns = ("service", "username")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("service", text="Услуга")
        self.tree.heading("username", text="Потребител")
        self.tree.column("service", width=220)
        self.tree.column("username", width=220)
        self.tree.pack(fill="both", expand=True, padx=8, pady=4)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_entry)

        detail_frame = ttk.LabelFrame(frame, text="Детайли")
        detail_frame.pack(fill="x", padx=8, pady=8)

        ttk.Label(detail_frame, text="Парола:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.detail_password_var = tk.StringVar(value="")
        self.detail_password_entry = ttk.Entry(detail_frame, textvariable=self.detail_password_var,
                                                 show="•", width=40, state="readonly")
        self.detail_password_entry.grid(row=0, column=1, sticky="w", padx=6, pady=4)
        self.show_pwd_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(detail_frame, text="Покажи", variable=self.show_pwd_var,
                         command=self._toggle_detail_password).grid(row=0, column=2, padx=6)
        ttk.Button(detail_frame, text="Копирай паролата", command=self.copy_detail_password).grid(row=0, column=3, padx=6)

        ttk.Label(detail_frame, text="Бележки:").grid(row=1, column=0, sticky="ne", padx=6, pady=4)
        self.detail_notes_var = tk.StringVar(value="")
        ttk.Label(detail_frame, textvariable=self.detail_notes_var, wraplength=400).grid(
            row=1, column=1, columnspan=3, sticky="w", padx=6, pady=4)

    # ---------------- Заключване / отключване на трезора ----------------

    def _unlock_or_create_vault(self):
        vault_exists = VAULT_PATH.exists()
        title = "Отключи трезора" if vault_exists else "Създай нов трезор"
        prompt = ("Файлът с пароли вече съществува.\nВъведи главната си парола:"
                  if vault_exists else
                  "Няма съществуващ трезор.\nЗадади главна парола, за да го създадеш:")

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
                messagebox.showerror("Грешка", str(e))
                # ако vault-ът вече съществуваше и паролата е грешна, питаме пак

        if not vault_exists:
            # запазваме празен трезор веднага, за да се създаде файлът с новата сол
            n_pow = save_vault(self.vault, self.master_password)
            mem_mb = (128 * (2 ** n_pow) * SCRYPT_R * SCRYPT_P) / (1024 * 1024)
            messagebox.showinfo(
                "Трезорът е създаден",
                f"Калибровка спрямо този компютър: scrypt N=2^{n_pow} "
                f"(~{mem_mb:.0f} MB памет на опит, ~{TARGET_KDF_SECONDS:.1f} сек за отключване)."
            )

        self.refresh_vault_list()

    def change_master_password(self):
        dlg = LoginDialog(self, "Нова главна парола", "Въведи новата главна парола:", confirm=True)
        new_pwd = dlg.result_password
        if not new_pwd:
            return
        if VAULT_PATH.exists():
            VAULT_PATH.unlink()
        save_vault(self.vault, new_pwd)
        self.master_password = new_pwd
        messagebox.showinfo("Готово", "Главната парола е сменена успешно.")

    # ---------------- Генератор ----------------

    def _on_length_change(self, _event=None):
        length = int(float(self.length_var.get()))
        self.length_display.config(text=str(length))
        self._update_strength()

    def _update_strength(self):
        length = int(float(self.length_var.get()))
        bits = entropy_bits(length, self.use_upper.get(), self.use_lower.get(),
                             self.use_digits.get(), self.use_symbols.get())
        self.strength_var.set(f"Сила: {strength_label(bits)}  (~{bits:.0f} бита ентропия)")

    def on_generate(self):
        length = int(float(self.length_var.get()))
        try:
            pwd = generate_password(length, self.use_upper.get(), self.use_lower.get(),
                                     self.use_digits.get(), self.use_symbols.get(),
                                     self.exclude_ambiguous.get())
        except ValueError as e:
            messagebox.showerror("Грешка", str(e))
            return
        self.result_var.set(pwd)
        self._update_strength()

    def copy_password(self):
        pwd = self.result_var.get()
        if not pwd:
            messagebox.showwarning("Няма парола", "Първо генерирай парола.")
            return
        self.clipboard_clear()
        self.clipboard_append(pwd)
        messagebox.showinfo("Копирано", "Паролата е копирана в клипборда.")

    def on_save_generated(self):
        pwd = self.result_var.get()
        if not pwd:
            messagebox.showwarning("Няма парола", "Първо генерирай парола.")
            return
        self._open_add_entry_dialog(prefilled_password=pwd)

    # ---------------- Трезор (списък, добавяне, изтриване) ----------------

    def refresh_vault_list(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for service in sorted(self.vault.keys()):
            entry = self.vault[service]
            self.tree.insert("", "end", iid=service, values=(service, entry.get("username", "")))

    def on_select_entry(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        service = sel[0]
        entry = self.vault.get(service, {})
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
        self.clipboard_clear()
        self.clipboard_append(pwd)
        messagebox.showinfo("Копирано", "Паролата е копирана в клипборда.")

    def add_manual_entry(self):
        self._open_add_entry_dialog()

    def _open_add_entry_dialog(self, prefilled_password=None):
        top = tk.Toplevel(self)
        top.title("Нов запис")
        top.geometry("380x260")
        top.transient(self)
        top.grab_set()

        pad = {"padx": 8, "pady": 6}

        ttk.Label(top, text="Услуга/сайт:").grid(row=0, column=0, sticky="e", **pad)
        service_var = tk.StringVar()
        ttk.Entry(top, textvariable=service_var, width=30).grid(row=0, column=1, **pad)

        ttk.Label(top, text="Потребител:").grid(row=1, column=0, sticky="e", **pad)
        username_var = tk.StringVar()
        ttk.Entry(top, textvariable=username_var, width=30).grid(row=1, column=1, **pad)

        ttk.Label(top, text="Парола:").grid(row=2, column=0, sticky="e", **pad)
        password_var = tk.StringVar(value=prefilled_password or "")
        pwd_entry = ttk.Entry(top, textvariable=password_var, width=30)
        pwd_entry.grid(row=2, column=1, **pad)

        def gen_new():
            password_var.set(generate_password(16))

        if not prefilled_password:
            ttk.Button(top, text="Генерирай", command=gen_new).grid(row=2, column=2, padx=4)

        ttk.Label(top, text="Бележки:").grid(row=3, column=0, sticky="ne", **pad)
        notes_text = tk.Text(top, width=30, height=4)
        notes_text.grid(row=3, column=1, **pad)

        def do_save():
            service = service_var.get().strip()
            if not service:
                messagebox.showerror("Грешка", "Името на услугата е задължително.", parent=top)
                return
            self.vault[service] = {
                "username": username_var.get().strip(),
                "password": password_var.get(),
                "notes": notes_text.get("1.0", "end").strip(),
            }
            save_vault(self.vault, self.master_password)
            self.refresh_vault_list()
            top.destroy()
            messagebox.showinfo("Готово", f"Записът '{service}' е запазен.")

        ttk.Button(top, text="Запази", command=do_save).grid(row=4, column=0, columnspan=2, pady=12)

    def delete_selected_entry(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Няма избор", "Избери запис от списъка първо.")
            return
        service = sel[0]
        if messagebox.askyesno("Потвърждение", f"Наистина ли да изтрия '{service}'?"):
            del self.vault[service]
            save_vault(self.vault, self.master_password)
            self.refresh_vault_list()
            self.detail_password_var.set("")
            self.detail_notes_var.set("")


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
