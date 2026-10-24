"""labs/lab02/task2.py

Варіант 15: Аудитор логів використання привілейованих команд (Sudo / Privileged Access).
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
import re
import sys

logger = logging.getLogger(__name__)

SUDO_LOG_REGEX: re.Pattern[str] = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r"\s+(?:[\w.-]+\s+)?sudo(?:\[\d+\])?:\s+"
    r"(?P<user>[\w.-]+)\s*:\s*"
    r"TTY=(?P<tty>[^;]+)\s*;\s*"
    r"PWD=(?P<pwd>[^;]+)\s*;\s*"
    r"USER=(?P<target_user>[^;]+)\s*;\s*"
    r"COMMAND=(?P<command>.*)$"
)

DEFAULT_ALERT_COMMANDS: list[str] = [
    "chmod 777",
    "chmod -R 777",
    "nc ",
    "nmap",
    "dd ",
    "/etc/shadow",
    "/etc/sudoers",
    "/bin/bash",
    "/bin/sh",
    "useradd",
    "passwd",
]


@dataclass
class SudoEntry:
    """Структурований запис виклику команди через sudo."""

    timestamp: str
    user: str
    tty: str
    pwd: str
    target_user: str
    command: str


@dataclass
class SecurityAlert:
    """Тривожне сповіщення про виявлену небезпечну команду."""

    timestamp: str
    user: str
    tty: str
    pwd: str
    target_user: str
    command: str
    matched_rule: str


def load_alert_commands(alert_arg: str | None) -> list[str]:
    """Завантаження переліку небезпечних команд із файлу або рядка."""
    if not alert_arg:
        return DEFAULT_ALERT_COMMANDS

    path = Path(alert_arg)
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8") as f:
                commands = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]
            logger.info(
                "Завантажено %d правил тривог із файлу %s", len(commands), path
            )
            return commands
        except OSError as err:
            logger.error("Не вдалося прочитати файл правил %s: %s", path, err)
            return DEFAULT_ALERT_COMMANDS

    commands = [cmd.strip() for cmd in alert_arg.split(",") if cmd.strip()]
    return commands if commands else DEFAULT_ALERT_COMMANDS


def parse_sudo_log(file_path: Path) -> list[SudoEntry]:
    """Зчитування та парсинг файлу логу sudo."""
    entries: list[SudoEntry] = []
    if not file_path.exists():
        raise FileNotFoundError(f"Файл логу не знайдено: {file_path}")

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            match = SUDO_LOG_REGEX.search(line_str)
            if match:
                data = match.groupdict()
                entries.append(
                    SudoEntry(
                        timestamp=data["timestamp"].strip(),
                        user=data["user"].strip(),
                        tty=data["tty"].strip(),
                        pwd=data["pwd"].strip(),
                        target_user=data["target_user"].strip(),
                        command=data["command"].strip(),
                    )
                )
            else:
                logger.debug("Рядок %d не відповідає формату: %s", line_num, line_str)

    return entries


def analyze_sudo_logs(
    entries: list[SudoEntry], alert_patterns: list[str]
) -> tuple[int, int, list[SecurityAlert], Counter[str], Counter[str]]:
    """Аналіз викликів sudo, виявлення запуску під root та пошук сигнатур загроз."""
    total_commands = len(entries)
    root_executions = 0
    alerts: list[SecurityAlert] = []
    user_total_counter: Counter[str] = Counter()
    user_alert_counter: Counter[str] = Counter()

    for entry in entries:
        user_total_counter[entry.user] += 1

        if entry.target_user.lower() == "root":
            root_executions += 1

        for pattern in alert_patterns:
            if pattern in entry.command:
                alert = SecurityAlert(
                    timestamp=entry.timestamp,
                    user=entry.user,
                    tty=entry.tty,
                    pwd=entry.pwd,
                    target_user=entry.target_user,
                    command=entry.command,
                    matched_rule=pattern,
                )
                alerts.append(alert)
                user_alert_counter[entry.user] += 1
                logger.warning(
                    "Користувач '%s' виконав небезпечну команду: 'sudo %s' на TTY=%s (Правило: '%s')",                    entry.user,
                    entry.command,
                    entry.tty,
                    pattern,
                )
                break

    return total_commands, root_executions, alerts, user_total_counter, user_alert_counter


def export_report_json(
    output_path: Path,
    total_commands: int,
    root_executions: int,
    alerts: list[SecurityAlert],
    user_total_counter: Counter[str],
    user_alert_counter: Counter[str],
) -> None:
    """Збереження результатів аудиту у форматі JSON."""
    user_stats = {}
    for user, count in user_total_counter.most_common():
        user_stats[user] = {
            "total_commands": count,
            "high_risk_commands": user_alert_counter[user],
        }

    report = {
        "summary": {
            "total_sudo_commands": total_commands,
            "root_executions": root_executions,
            "suspicious_commands_detected": len(alerts),
        },
        "suspicious_executions": [asdict(alert) for alert in alerts],
        "user_statistics": user_stats,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)


def run_audit(
    sudo_log_path: str,
    alert_commands_arg: str | None,
    out_json_path: str,
    log_level: str = "INFO",
) -> None:
    """Основний цикл виконання аналізу логів."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="[%(levelname)s] %(message)s",
    )

    log_file = Path(sudo_log_path)
    output_file = Path(out_json_path)

    logger.info("Парсинг логу sudo з файлу %s...", log_file)
    try:
        entries = parse_sudo_log(log_file)
    except FileNotFoundError as err:
        logger.error("%s", err)
        sys.exit(1)

    logger.info("Оброблено %d записів привілейованого виконання.", len(entries))

    alert_patterns = load_alert_commands(alert_commands_arg)
    (
        total_cmd,
        root_exec,
        alerts,
        total_counter,
        alert_counter,
    ) = analyze_sudo_logs(entries, alert_patterns)

    print("\n - - Зведення про привілейовані команди - -")
    print(f"Всього команд sudo  : {total_cmd:,}")
    print(f"Виконано від root   : {root_exec:,}")

    print("\n - -  Підозрілі / Небезпечні команди  - - ")
    if alerts:
        for alert in alerts:
            print(
                f"[ТРИВОГА] Користувач '{alert.user}' виконав: 'sudo {alert.command}' на TTY={alert.tty}"            )
    else:
        print("Підозрілих команд не виявлено.")

    print("\n - -  Топ користувачів Sudo  - - ")
    for rank, (user, count) in enumerate(total_counter.most_common(5), start=1):
        risks = alert_counter[user]
        risk_str = f" (Небезпечних команд: {risks})" if risks > 0 else ""
        print(f"{rank}. {user:<12}: {count} команд{risk_str}")

    export_report_json(
        output_file,
        total_cmd,
        root_exec,
        alerts,
        total_counter,
        alert_counter,
    )
    logger.info("Звіт аудиту привілейованих команд збережено у %s\n", output_file)


def build_parser() -> argparse.ArgumentParser:
    """Налаштування парсера аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        description="CLI-утиліта аудиту логів sudo (Варіант 15)"
    )
    parser.add_argument(
        "--sudo-log",
        required=True,
        help="Шлях до файлу журналу sudo (наприклад, labs/lab02/data/data_v15/sudo.log)",
    )
    parser.add_argument(
        "--alert-commands",
        default="labs/lab02/data/data_v15/alert_commands.txt",
        help="Шлях до файлу зі списком підозрілих команд або команди через кому",
    )
    parser.add_argument(
        "--out-json",
        default="labs/lab02/data/sudo_audit_report.json",
        help="Шлях для збереження JSON-звіту",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Рівень деталізації логування (за замовчуванням: INFO)",
    )
    return parser


def main() -> None:
    """Точка входу для автономного запуску task2.py."""
    parser = build_parser()
    args = parser.parse_args()
    run_audit(
        sudo_log_path=args.sudo_log,
        alert_commands_arg=args.alert_commands,
        out_json_path=args.out_json,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()