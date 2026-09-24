#!/usr/bin/env python3
"""
Password Manager & Generator
=============================
Simple console program for Linux (tested on Linux Mint) that:
  1. Generates complex random passwords.
  2. Stores passwords encrypted on disk (protected by a master password).
Storage uses:
  - scrypt (RFC 7914) to derive a key from the master password
  - Fernet (AES-128 in CBC mode + HMAC) to encrypt the data
The password file (password_vault.enc) is kept IN THE SAME FOLDER as
the script — this makes it portable.
"""
import os
import sys
import json
import time
import base64
import hashlib
import secrets
import string
import getpass
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
VAULT_PATH = Path(__file__).resolve().parent / "password_vault.enc"
SALT_SIZE = 16
TARGET_KDF_SECONDS = 1.0     # goal: key derivation should take ~1 second
SCRYPT_R = 8                 # standard value (block size)
SCRYPT_P = 1                 # standard value (parallelism)
SCRYPT_MAX_N_POW = 20        # upper bound (2^20 * 128 * r * p ≈ 1 GB)
SCRYPT_MAX_MEM_MB = 512      # memory cap during calibration (MB)
# ----------------------------------------------------------------------
# Password generation
# ----------------------------------------------------------------------
def generate_password(length: int = 16,
                      use_upper: bool = True,
                      use_lower: bool = True,
                      use_digits: bool = True,
                      use_symbols: bool = True,
                      exclude_ambiguous: bool = False) -> str:
    """Generate a cryptographically secure random password."""
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
        raise ValueError("At least one character type must be selected.")
    if exclude_ambiguous:
        pools = ["".join(c for c in p if c not in ambiguous) for p in pools]
    all_chars = "".join(pools)
    if length < len(pools):
        raise ValueError("Length must be at least the number of selected character types.")
    password_chars = [secrets.choice(pool) for pool in pools]
    password_chars += [secrets.choice(all_chars) for _ in range(length - len(pools))]
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
    return "".join(password_chars)
def password_strength_hint(length: int, use_upper, use_lower, use_digits, use_symbols) -> str:
    pool_size = 0
    pool_size += 26 if use_lower else 0
    pool_size += 26 if use_upper else 0
    pool_size += 10 if use_digits else 0
    pool_size += 28 if use_symbols else 0
    if pool_size == 0:
        return "none"
    import math
    entropy_bits = length * math.log2(pool_size)
    if entropy_bits < 40:
        return f"weak (~{entropy_bits:.0f} bits of entropy)"
    elif entropy_bits < 60:
        return f"medium (~{entropy_bits:.0f} bits of entropy)"
    elif entropy_bits < 80:
        return f"good (~{entropy_bits:.0f} bits of entropy)"
    else:
        return f"very strong (~{entropy_bits:.0f} bits of entropy)"
# ----------------------------------------------------------------------
# Encrypted storage (Vault)
# ----------------------------------------------------------------------
def derive_key(master_password: str, salt: bytes, n_pow: int, r: int, p: int) -> bytes:
    """Derive a 32-byte key with scrypt and base64-encode it for Fernet."""
    n = 2 ** n_pow
    mem_needed = 128 * n * r * p
    maxmem = mem_needed * 2 + (16 * 1024 * 1024)
    raw_key = hashlib.scrypt(master_password.encode("utf-8"), salt=salt,
                             n=n, r=r, p=p, dklen=32, maxmem=maxmem)
    return base64.urlsafe_b64encode(raw_key)
def calibrate_scrypt(target_seconds: float = TARGET_KDF_SECONDS,
                     r: int = SCRYPT_R, p: int = SCRYPT_P) -> int:
    """Double N until derivation time reaches ~target_seconds."""
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
    """Return (salt, n_pow, r, p) from an existing file, or None if there is no file."""
    if not VAULT_PATH.exists():
        return None
    raw = VAULT_PATH.read_bytes()
    salt = raw[:SALT_SIZE]
    n_pow = raw[SALT_SIZE]
    r = raw[SALT_SIZE + 1]
    p = raw[SALT_SIZE + 2]
    return salt, n_pow, r, p
def load_vault(master_password: str) -> dict:
    """Load and decrypt the vault."""
    if not VAULT_PATH.exists():
        return {}
    raw = VAULT_PATH.read_bytes()
    salt = raw[:SALT_SIZE]
    n_pow, r, p = raw[SALT_SIZE], raw[SALT_SIZE + 1], raw[SALT_SIZE + 2]
    token = raw[SALT_SIZE + 3:]
    key = derive_key(master_password, salt, n_pow, r, p)
    f = Fernet(key)
    try:
        decrypted = f.decrypt(token)
    except InvalidToken:
        raise ValueError("Wrong master password or corrupt file.")
    return json.loads(decrypted.decode("utf-8"))
def save_vault(data: dict, master_password: str, force_recalibrate: bool = False) -> None:
    """Encrypt and write the vault atomically via a temporary .tmp file."""
    header = None if force_recalibrate else _read_header()
    if header is not None:
        salt, n_pow, r, p = header
    else:
        salt = os.urandom(SALT_SIZE)
        r, p = SCRYPT_R, SCRYPT_P
        n_pow = calibrate_scrypt(r=r, p=p)
        mem_mb = (128 * (2 ** n_pow) * r * p) / (1024 * 1024)
        print(f"(Calibration: scrypt N=2^{n_pow}, r={r}, p={p} "
              f"(~{mem_mb:.0f} MB memory per attempt, ~{TARGET_KDF_SECONDS:.1f} sec))")
    key = derive_key(master_password, salt, n_pow, r, p)
    f = Fernet(key)
    encrypted = f.encrypt(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
    header_bytes = salt + bytes([n_pow, r, p])
    
    # Safe atomic write
    temp_path = VAULT_PATH.with_suffix(".tmp")
    temp_path.write_bytes(header_bytes + encrypted)
    os.chmod(temp_path, 0o600)
    temp_path.replace(VAULT_PATH)
# ----------------------------------------------------------------------
# Console UI helpers
# ----------------------------------------------------------------------
def ask_yes_no(prompt: str, default: bool = True) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    answer = input(prompt + suffix).strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes", "д", "да")
def ask_int(prompt: str, default: int) -> int:
    raw = input(f"{prompt} (default {default}): ").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print("Invalid number, using the default value.")
        return default
def get_master_password(confirm: bool = False) -> str:
    while True:
        pwd = getpass.getpass("Master password: ")
        if not pwd:
            print("Master password cannot be empty.")
            continue
        if confirm:
            pwd2 = getpass.getpass("Repeat master password: ")
            if pwd != pwd2:
                print("Passwords do not match, try again.")
                continue
        return pwd
# ----------------------------------------------------------------------
# Menu actions
# ----------------------------------------------------------------------
def action_generate_only():
    print("\n--- Generate password ---")
    length = ask_int("Password length", 16)
    use_upper = ask_yes_no("Uppercase letters (A-Z)?", True)
    use_lower = ask_yes_no("Lowercase letters (a-z)?", True)
    use_digits = ask_yes_no("Digits (0-9)?", True)
    use_symbols = ask_yes_no("Symbols (!@#$...)?", True)
    exclude_ambiguous = ask_yes_no("Exclude ambiguous characters (Il1O0)?", False)
    try:
        pwd = generate_password(length, use_upper, use_lower, use_digits,
                               use_symbols, exclude_ambiguous)
    except ValueError as e:
        print(f"Error: {e}")
        return
    strength = password_strength_hint(length, use_upper, use_lower, use_digits, use_symbols)
    print(f"\nGenerated password: {pwd}")
    print(f"Strength: {strength}")
    if ask_yes_no("\nDo you want to save it to the vault?", False):
        save_entry_flow(prefilled_password=pwd)
def save_entry_flow(prefilled_password: str = None):
    master = get_master_password()
    try:
        vault = load_vault(master)
    except ValueError as e:
        print(f"Error: {e}")
        return
    service = input("Service/site name (e.g. gmail, facebook): ").strip()
    if not service:
        print("Name cannot be empty, aborting save.")
        return
    username = input("Username / email: ").strip()
    if prefilled_password:
        password = prefilled_password
    else:
        if ask_yes_no("Generate a new password automatically?", True):
            length = ask_int("Length", 16)
            password = generate_password(length)
            print(f"Generated password: {password}")
        else:
            password = getpass.getpass("Enter the password manually: ")
    notes = input("Notes (optional): ").strip()
    vault[service] = {
        "username": username,
        "password": password,
        "notes": notes,
    }
    save_vault(vault, master)
    print(f"\n✔ Saved '{service}' to {VAULT_PATH}")
def list_entries_flow():
    master = get_master_password()
    try:
        vault = load_vault(master)
    except ValueError as e:
        print(f"Error: {e}")
        return
    if not vault:
        print("The vault is empty.")
        return
    print(f"\nEntries ({len(vault)}):")
    for i, service in enumerate(sorted(vault.keys()), 1):
        print(f"  {i}. {service}")
    choice = input("\nEnter a service name to view details (Enter to exit): ").strip()
    if choice and choice in vault:
        entry = vault[choice]
        print(f"\n--- {choice} ---")
        print(f"Username: {entry.get('username', '')}")
        print(f"Password: {entry.get('password', '')}")
        if entry.get("notes"):
            print(f"Notes:    {entry['notes']}")
    elif choice:
        print("No such service.")
def delete_entry_flow():
    master = get_master_password()
    try:
        vault = load_vault(master)
    except ValueError as e:
        print(f"Error: {e}")
        return
    if not vault:
        print("The vault is empty.")
        return
    for i, service in enumerate(sorted(vault.keys()), 1):
        print(f"  {i}. {service}")
    choice = input("\nEnter the service name to delete: ").strip()
    if choice in vault:
        if ask_yes_no(f"Really delete '{choice}'?", False):
            del vault[choice]
            save_vault(vault, master)
            print("✔ Deleted.")
    else:
        print("No such service.")
def change_master_password_flow():
    print("\n--- Change master password ---")
    old_master = get_master_password()
    try:
        vault = load_vault(old_master)
    except ValueError as e:
        print(f"Error: {e}")
        return
    print("Enter the new master password:")
    new_master = get_master_password(confirm=True)
    # Save with force_recalibrate=True to generate a new salt and header
    save_vault(vault, new_master, force_recalibrate=True)
    print("✔ Master password changed successfully.")
# ----------------------------------------------------------------------
# Main menu
# ----------------------------------------------------------------------
MENU = """
==============================
   Password Manager
==============================
1. Generate password (no save)
2. Generate/add and save an entry
3. View saved entries
4. Delete an entry
5. Change master password
0. Exit
"""
def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return
    print(f"Password file: {VAULT_PATH}")
    while True:
        print(MENU)
        choice = input("Choose an option: ").strip()
        if choice == "1":
            action_generate_only()
        elif choice == "2":
            save_entry_flow()
        elif choice == "3":
            list_entries_flow()
        elif choice == "4":
            delete_entry_flow()
        elif choice == "5":
            change_master_password_flow()
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, try again.")
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
