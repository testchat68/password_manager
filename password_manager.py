#!/usr/bin/env python3
"""
Password Manager & Generator
=============================
Проста конзолна программа за Linux (тествана за Linux Mint), която:
  1. Генерира сложни, случайни пароли.
  2. Съхранява паролите криптирано на диска (защитени с главна парола).

Съхранението използва:
  - scrypt (RFC 7914) за извеждане на ключ от главната парола
  - Fernet (AES-128 в CBC режим + HMAC) за криптиране на самите данни

Файлът с паролите (password_vault.enc) се пази В СЪЩАТА ПАПКА, в която
е скриптът — това го прави преносим.
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
TARGET_KDF_SECONDS = 1.0     # цел: извеждането на ключа да отнема ~1 секунда
SCRYPT_R = 8                 # стандартна стойност (block size)
SCRYPT_P = 1                 # стандартна стойност (паралелизъм)
SCRYPT_MAX_N_POW = 20        # горна граница (2^20 * 128 * r * p ≈ 1 GB)
SCRYPT_MAX_MEM_MB = 512      # горна граница на паметта при калибровка (MB)


# ----------------------------------------------------------------------
# Генериране на пароли
# ----------------------------------------------------------------------

def generate_password(length: int = 16,
                      use_upper: bool = True,
                      use_lower: bool = True,
                      use_digits: bool = True,
                      use_symbols: bool = True,
                      exclude_ambiguous: bool = False) -> str:
    """Генерира криптографски сигурна случайна парола."""
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
        raise ValueError("Трябва да е избран поне един тип символи.")

    if exclude_ambiguous:
        pools = ["".join(c for c in p if c not in ambiguous) for p in pools]

    all_chars = "".join(pools)

    if length < len(pools):
        raise ValueError("Дължината трябва да е поне колкото броя избрани типове символи.")

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
        return "няма"
    import math
    entropy_bits = length * math.log2(pool_size)
    if entropy_bits < 40:
        return f"слаба (~{entropy_bits:.0f} бита ентропия)"
    elif entropy_bits < 60:
        return f"средна (~{entropy_bits:.0f} бита ентропия)"
    elif entropy_bits < 80:
        return f"добра (~{entropy_bits:.0f} бита ентропия)"
    else:
        return f"много силна (~{entropy_bits:.0f} бита ентропия)"


# ----------------------------------------------------------------------
# Криптирано съхранение (Vault)
# ----------------------------------------------------------------------

def derive_key(master_password: str, salt: bytes, n_pow: int, r: int, p: int) -> bytes:
    """Извежда 32-байтов ключ чрез scrypt и го base64-кодира за Fernet."""
    n = 2 ** n_pow
    mem_needed = 128 * n * r * p
    maxmem = mem_needed * 2 + (16 * 1024 * 1024)
    raw_key = hashlib.scrypt(master_password.encode("utf-8"), salt=salt,
                             n=n, r=r, p=p, dklen=32, maxmem=maxmem)
    return base64.urlsafe_b64encode(raw_key)


def calibrate_scrypt(target_seconds: float = TARGET_KDF_SECONDS,
                     r: int = SCRYPT_R, p: int = SCRYPT_P) -> int:
    """Удвоява N, докато времето за извеждане достигне ~target_seconds."""
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
    """Връща (salt, n_pow, r, p) от съществуващия файл, или None ако няма файл."""
    if not VAULT_PATH.exists():
        return None
    raw = VAULT_PATH.read_bytes()
    salt = raw[:SALT_SIZE]
    n_pow = raw[SALT_SIZE]
    r = raw[SALT_SIZE + 1]
    p = raw[SALT_SIZE + 2]
    return salt, n_pow, r, p


def load_vault(master_password: str) -> dict:
    """Зарежда и дешифрира vault-а."""
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
        raise ValueError("Грешна главна парола или повреден файл.")
    return json.loads(decrypted.decode("utf-8"))


def save_vault(data: dict, master_password: str, force_recalibrate: bool = False) -> None:
    """Криптира и записва vault-а атомарно чрез временен .tmp файл."""
    header = None if force_recalibrate else _read_header()
    if header is not None:
        salt, n_pow, r, p = header
    else:
        salt = os.urandom(SALT_SIZE)
        r, p = SCRYPT_R, SCRYPT_P
        n_pow = calibrate_scrypt(r=r, p=p)
        mem_mb = (128 * (2 ** n_pow) * r * p) / (1024 * 1024)
        print(f"(Калибровка: scrypt N=2^{n_pow}, r={r}, p={p} "
              f"(~{mem_mb:.0f} MB памет на опит, ~{TARGET_KDF_SECONDS:.1f} сек))")

    key = derive_key(master_password, salt, n_pow, r, p)
    f = Fernet(key)
    encrypted = f.encrypt(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))

    header_bytes = salt + bytes([n_pow, r, p])
    
    # Безопасен атомарен запис
    temp_path = VAULT_PATH.with_suffix(".tmp")
    temp_path.write_bytes(header_bytes + encrypted)
    os.chmod(temp_path, 0o600)
    temp_path.replace(VAULT_PATH)


# ----------------------------------------------------------------------
# Помощни функции за конзолен интерфейс
# ----------------------------------------------------------------------

def ask_yes_no(prompt: str, default: bool = True) -> bool:
    suffix = " [Д/n]: " if default else " [д/N]: "
    answer = input(prompt + suffix).strip().lower()
    if not answer:
        return default
    return answer in ("д", "y", "yes", "да")


def ask_int(prompt: str, default: int) -> int:
    raw = input(f"{prompt} (по подразбиране {default}): ").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print("Невалидно число, използвам стойността по подразбиране.")
        return default


def get_master_password(confirm: bool = False) -> str:
    while True:
        pwd = getpass.getpass("Главна парола: ")
        if not pwd:
            print("Главната парола не може да е празна.")
            continue
        if confirm:
            pwd2 = getpass.getpass("Повтори главната парола: ")
            if pwd != pwd2:
                print("Паролите не съвпадат, опитай пак.")
                continue
        return pwd


# ----------------------------------------------------------------------
# Основни действия от менюто
# ----------------------------------------------------------------------

def action_generate_only():
    print("\n--- Генериране на парола ---")
    length = ask_int("Дължина на паролата", 16)
    use_upper = ask_yes_no("Главни букви (A-Z)?", True)
    use_lower = ask_yes_no("Малки букви (a-z)?", True)
    use_digits = ask_yes_no("Цифри (0-9)?", True)
    use_symbols = ask_yes_no("Символи (!@#$...)?", True)
    exclude_ambiguous = ask_yes_no("Изключи объркващи символи (Il1O0)?", False)

    try:
        pwd = generate_password(length, use_upper, use_lower, use_digits,
                               use_symbols, exclude_ambiguous)
    except ValueError as e:
        print(f"Грешка: {e}")
        return

    strength = password_strength_hint(length, use_upper, use_lower, use_digits, use_symbols)
    print(f"\nГенерирана парола: {pwd}")
    print(f"Сила: {strength}")

    if ask_yes_no("\nИскаш ли да я запазиш във vault-а?", False):
        save_entry_flow(prefilled_password=pwd)


def save_entry_flow(prefilled_password: str = None):
    master = get_master_password()
    try:
        vault = load_vault(master)
    except ValueError as e:
        print(f"Грешка: {e}")
        return

    service = input("Име на услугата/сайта (напр. gmail, facebook): ").strip()
    if not service:
        print("Името не може да е празно, отказвам записа.")
        return
    username = input("Потребителско име / имейл: ").strip()

    if prefilled_password:
        password = prefilled_password
    else:
        if ask_yes_no("Да генерирам ли нова парола автоматично?", True):
            length = ask_int("Дължина", 16)
            password = generate_password(length)
            print(f"Генерирана парола: {password}")
        else:
            password = getpass.getpass("Въведи паролата ръчно: ")

    notes = input("Бележки (незадължително): ").strip()

    vault[service] = {
        "username": username,
        "password": password,
        "notes": notes,
    }

    save_vault(vault, master)
    print(f"\n✔ Записано за '{service}' във {VAULT_PATH}")


def list_entries_flow():
    master = get_master_password()
    try:
        vault = load_vault(master)
    except ValueError as e:
        print(f"Грешка: {e}")
        return

    if not vault:
        print("Vault-ът е празен.")
        return

    print(f"\nЗаписи ({len(vault)}):")
    for i, service in enumerate(sorted(vault.keys()), 1):
        print(f"  {i}. {service}")

    choice = input("\nВъведи име на услуга, за да видиш детайли (Enter за изход): ").strip()
    if choice and choice in vault:
        entry = vault[choice]
        print(f"\n--- {choice} ---")
        print(f"Потребител: {entry.get('username', '')}")
        print(f"Парола:     {entry.get('password', '')}")
        if entry.get("notes"):
            print(f"Бележки:    {entry['notes']}")
    elif choice:
        print("Няма такава услуга.")


def delete_entry_flow():
    master = get_master_password()
    try:
        vault = load_vault(master)
    except ValueError as e:
        print(f"Грешка: {e}")
        return

    if not vault:
        print("Vault-ът е празен.")
        return

    for i, service in enumerate(sorted(vault.keys()), 1):
        print(f"  {i}. {service}")

    choice = input("\nВъведи име на услугата за изтриване: ").strip()
    if choice in vault:
        if ask_yes_no(f"Наистина ли да изтрия '{choice}'?", False):
            del vault[choice]
            save_vault(vault, master)
            print("✔ Изтрито.")
    else:
        print("Няма такава услуга.")


def change_master_password_flow():
    print("\n--- Смяна на главна парола ---")
    old_master = get_master_password()
    try:
        vault = load_vault(old_master)
    except ValueError as e:
        print(f"Грешка: {e}")
        return

    print("Въведи новата главна парола:")
    new_master = get_master_password(confirm=True)

    # Записваме с force_recalibrate=True, за да генерираме нова сол и хедър
    save_vault(vault, new_master, force_recalibrate=True)
    print("✔ Главната парола е сменена успешно.")


# ----------------------------------------------------------------------
# Главно меню
# ----------------------------------------------------------------------

MENU = """
==============================
   Мениджър на пароли (BG)
==============================
1. Генерирай парола (без запис)
2. Генерирай/добави и запази запис
3. Виж запазени записи
4. Изтрий запис
5. Смени главната парола
0. Изход
"""


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return

    print(f"Файл с пароли: {VAULT_PATH}")
    while True:
        print(MENU)
        choice = input("Избери опция: ").strip()

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
            print("Довиждане!")
            break
        else:
            print("Невалиден избор, опитай пак.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрекратено от потребителя.")