"""Завдання 3: Хешування SHA-1, CSV-база та JSON-логування (Варіант 15)."""

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_PATH = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 9
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"  # Результат: "00015"


class ValidationError(Exception):
    """Власний виняток: пароль не відповідає критеріям довжини."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Обчислює SHA-1 хеш від пароля разом із сіллю."""
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль закороткий: мінімум {MIN_PASSWORD_LENGTH} символів."
        )

    # Об' пароль із сіллю та  SHA-1 хеш
    combined = f"{password}{salt}".encode()
    return hashlib.sha1(combined).hexdigest()


def log_event(func):
    """Декоратор для автоматичного журналу входу у файл log.json."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = kwargs.get("username") or (args[0] if args else "unknown")
        result = "failure"

        try:
            res = func(*args, **kwargs)
            result = "success" if res else "failure"
            return res
        except Exception:
            result = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now(tz=timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "args": [str(a) for a in args],
                "kwargs": {k: str(v) for k, v in kwargs.items()},
            }

            os.makedirs(DATA_DIR, exist_ok=True)
            logs = []
            if os.path.exists(LOG_PATH):
                try:
                    with open(LOG_PATH, mode="r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (OSError, json.JSONDecodeError):
                    logs = []

            logs.append(log_entry)
            with open(LOG_PATH, mode="w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

    return wrapper


def create_user(username: str, password: str) -> tuple[str, str]:
    """Генерує хеш для нового користувача."""
    pwd_hash = generate_hash(password, PERSONAL_SALT)
    return username, pwd_hash


def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    """Створює каталог data та записує користувачів у users.csv."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["username", "password_hash"])
        for user, pwd in users_list:
            u, h = create_user(user, pwd)
            writer.writerow([u, h])


def read_users_db() -> list[dict[str, str]]:
    """Зчитує дані з users.csv у список словників."""
    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError(f"Файл {CSV_PATH} не знайдено.")

    with open(CSV_PATH, mode="r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)


@log_event
def login(username: str, password: str) -> bool:
    """Звіряє введений логін і пароль із записами в users.csv."""
    if not username or not password:
        raise ValueError("Логін та пароль є обов'язковими")

    target_hash = generate_hash(password, PERSONAL_SALT)
    users = read_users_db()

    for entry in users:
        if entry["username"] == username and entry["password_hash"] == target_hash:
            return True
    return False


def run_task3() -> None:
    """Головний сценарій тестування Завдання 3."""
    print("\n- Завдання 3: Хешування, База CSV та JSON-логування -")

    users_to_register = (
        ("alice_sec", "QuantumPass99!"),
        ("bob_crypto", "SuperSecur3#"),
        ("charlie_q", "PostQuantum77"),
        ("dave_root", "KernelProt#1"),
        ("emma_net", "Firewall_2026"),
        ("frank_ops", "DevSecOps_Pwd!"),
        ("grace_ai", "NeuralSafe#9"),
        ("heidi_lab", "Research_Access!"),
        ("ivan_audit", "AuditVerify9"),
        ("judy_admin", "AdminStrong#15"),
    )

    try:
        print("1. Збереження 10 користувачів у файл users.csv...")
        create_users(users_to_register)

        print("\n2. Зміст згенерованого файлу users.csv:")
        db_records = read_users_db()
        print(f"{'Користувач':<15} | {'SHA-1 Хеш із сіллю 00015'}")
        print("-" * 60)
        for rec in db_records:
            print(f"{rec['username']:<15} | {rec['password_hash']}")

        print("\n3. Тестування спроб авторизації (логуються в log.json):")
        test_attempts = [
            ("alice_sec", "QuantumPass99!"),  # Правильний пароль
            ("bob_crypto", "WrongPassword!"),  # Неправильний пароль
            ("judy_admin", "AdminStrong#15"),  # Правильний пароль
        ]

        for user, pwd in test_attempts:
            try:
                success = login(user, pwd)
                status = "Успішно" if success else "Відмовлено (невірний пароль)"
                print(f"Спроба входу '{user}': {status}")
            except (ValidationError, ValueError) as err:
                print(f"Помилка для '{user}': {err}")

        print("\n4. Перевірка валідації короткого пароля (< 9 символів):")
        try:
            generate_hash("short", PERSONAL_SALT)
        except ValidationError as err:
            print(f"Очікувано перехоплено ValidationError: {err}")

    except OSError as io_err:
        print(f"Помилка файлової системи: {io_err}")


if __name__ == "__main__":
    run_task3()
