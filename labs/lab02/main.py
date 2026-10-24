"""labs/lab02/main.py

Головний файл запуску лабораторної роботи №2.
Підтримує підкоманди:
  - demo: демонстрація об'єктно-орієнтованої архітектури (Завдання 1)
  - analyze: запуск аналізатора журналів sudo (Завдання 2, Варіант 15)
"""

from __future__ import annotations

import argparse

from labs.lab02.task1 import (
    SESSION_TIMEOUT_SEC,
    Admin,
    AuditLog,
    User,
    UserAccount,
)
from labs.lab02.task2 import run_audit


def run_demo() -> None:
    """Демонстрація виконання Завдання 1 (ООП)."""
    print(" - " * 40)
    print("ДЕМОНСТРАЦІЯ ЗАВДАННЯ 1: СИСТЕМА ОБЛІКОВИХ ЗАПИСІВ")
    print(" - " * 40)

    user = User(username="analyst_veronika", email="veronika@cybersec.org")
    user.set_password("SecurePassword2026!")
    print(f"[+] Створено користувача: {user}")

    print("\n[*] Тестування валідації email:")
    try:
        user.email = "bad-email@"
    except ValueError as err:
        print(f"    [OK] Спіймано очікувану помилку валідації: {err}")

    user.email = "veronika_new@cybersec.org"
    print(f"    [OK] Email успішно змінено на: {user.email}")

    print("\n[*] Тестування класу Admin:")
    admin = Admin(
        username="sec_admin",
        email="admin_root@cybersec.org",
        permissions=["READ_LOGS", "EXEC_SCAN"],
    )
    print(f"    Початковий стан: {admin}")
    admin.grant_permission("MANAGE_USERS")
    admin.revoke_permission("EXEC_SCAN")
    print(f"    Чи є дозвіл 'MANAGE_USERS'? -> {admin.has_permission('MANAGE_USERS')}")
    print(f"    Чи є дозвіл 'EXEC_SCAN'?    -> {admin.has_permission('EXEC_SCAN')}")
    print(f"    Оновлений стан: {admin}")

    print("\n[*] Тестування автентифікації та UserAccount:")
    audit_log = AuditLog()
    account = UserAccount(user=user, audit_log=audit_log)

    failed = account.login("analyst_veronika", "WrongPassword", ip="192.168.1.15")
    print(f"    Спроба входу з хибним паролем: успіх={failed}")
    print(f"    Стан автентифікації: {account.is_authenticated()}")

    success = account.login(
        "analyst_veronika", "SecurePassword2026!", ip="192.168.1.15"
    )
    print(f"    Спроба входу з правильним паролем: успіх={success}")
    print(f"    Стан автентифікації: {account.is_authenticated()}")

    print("\n[*] Перевірка завершення сеансу за таймаутом:")
    print(
        f"    Поточна сесія активна (таймаут {SESSION_TIMEOUT_SEC} c): {account.is_authenticated()}"
    )
    if account.session:
        print(
            f"    Сесія при таймауті 0 секунд: {account.session.is_active(timeout_sec=1)}"
        )

    account.logout()
    print(f"    Після logout стан автентифікації: {account.is_authenticated()}")

    print("\n[*] Тестування спеціальних методів __getitem__:")
    account_user = account["user"]
    print(f"    account['user'] -> {account_user}")

    print("\n- - Записи AuditLog - -")
    for record in account.audit_log.show_all():
        print(
            f"    [{record.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] "
            f"User: {record.username:<18} Action: {record.action}"
        )
    print(" - " * 40)


def main() -> None:
    """Маршрутизація підкоманд CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="Лабораторна робота №2 (Варіант 15)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("demo", help="Запустити демонстрацію Завдання 1 (ООП)")

    analyze_parser = subparsers.add_parser(
        "analyze", help="Запустити CLI-утиліту аудиту sudo (Завдання 2)"
    )
    analyze_parser.add_argument(
        "--sudo-log",
        required=True,
        help="Шлях до файлу sudo.log",
    )
    analyze_parser.add_argument(
        "--alert-commands",
        default="labs/lab02/data/data_v15/alert_commands.txt",
        help="Шлях до alert_commands.txt",
    )
    analyze_parser.add_argument(
        "--out-json",
        default="labs/lab02/data/sudo_audit_report.json",
        help="Шлях до результуючого JSON",
    )
    analyze_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Рівень логування",
    )

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_audit(
            sudo_log_path=args.sudo_log,
            alert_commands_arg=args.alert_commands,
            out_json_path=args.out_json,
            log_level=args.log_level,
        )


if __name__ == "__main__":
    main()
