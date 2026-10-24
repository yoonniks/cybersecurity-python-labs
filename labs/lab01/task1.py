"""

Завдання 1: Комплексний аналізатор надійності паролів (Варіант 15).

"""

import os
import random
import sys
from collections import Counter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Дані для 15 варіанту
PASSWORDS = [
    "IoT@S3curity",
    "standard",
    "Blockchain@Protect",
    "typical123",
    "AI@Cybersec",
    "normal",
    "Quantum@Crypto",
    "general123",
    "Edge@S3curity",
    "common",
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "standard",
    "typical123",
    "normal",
    "general123",
    "common",
    "guest",
}


def evaluate_password(password: str, counts: Counter) -> str:
    """
    Оцінює рівень надійності окремого пароля.
    """
    min_len = CRITERIA["min_length"]

    if password in FORBIDDEN_PASSWORDS or len(password) < min_len:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(not char.isalnum() for char in password)

    meets_all = has_digit and has_upper and has_special and (len(password) >= min_len)
    total_criteria_met = sum([has_digit, has_upper, has_lower, has_special])

    # Дуже сильний або Сильний
    if meets_all:
        if len(password) >= (min_len + 4) and counts[password] == 1:
            return "Дуже сильний"
        return "Сильний"

    # Середній
    if len(password) >= min_len and total_criteria_met > 1:
        return "Середній"

    # Слабкий
    if total_criteria_met >= 1:
        return "Слабкий"

    return "Заборонений"


def run_task1() -> None:
    """
    Запускає процес аналізу паролів та виводить таблицю.
    """
    print(f"\n- Завдання 1 | Студент: {STUDENT_NAME} (Вар. {VARIANT_NUMBER}) -")

    test_passwords = list(PASSWORDS)
    random.seed(VARIANT_NUMBER)

    random_indices = random.sample(range(len(test_passwords)), 3)
    duplicates = [test_passwords[idx] for idx in random_indices]
    test_passwords.extend(duplicates)

    counts = Counter(test_passwords)

    print(f"{'Пароль':<22} | {'Довжина':<7} | {'Унікальний':<10} | {'Надійність'}")
    print("-" * 65)

    for pwd in test_passwords:
        level = evaluate_password(pwd, counts)
        is_unique = "Так" if counts[pwd] == 1 else "Ні (дубль)"
        print(f"{pwd:<22} | {len(pwd):<7} | {is_unique:<10} | {level}")


if __name__ == "__main__":
    run_task1()
