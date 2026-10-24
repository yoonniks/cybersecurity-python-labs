"""
Реалізація моделі користувача, безпечних сесій, аудиту та облікового запису
з використанням принципів ООП.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PBKDF2_ITERATIONS: int = 100_000
SESSION_TIMEOUT_SEC: int = 900

EMAIL_REGEX: re.Pattern[str] = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$"
)


class User:
    """Клас користувача системи із захищеним зберіганням пароля."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        self.username: str = username
        self._email: str = ""
        self.email = email
        self.role: str = role
        self.active: bool = active
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        """Отримати email адресу."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Встановити email з попередньою валідацією формату."""
        if not isinstance(value, str) or not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email: '{value}'")
        self._email = value

    def set_password(self, password: str) -> None:
        """Хешування пароля алгоритмом PBKDF2-HMAC-SHA256 з унікальною сіллю."""
        if not password:
            raise ValueError("Пароль не може бути порожнім.")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевірка пароля із захистом від атак за часом (timing attacks)."""
        if (
            not self.active
            or self.__password_hash is None
            or self.__password_salt is None
        ):
            return False

        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, computed_hash)

    def deactivate(self) -> None:
        """Деактивація облікового запису."""
        self.active = False

    def __str__(self) -> str:
        return (
            f"User(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', active={self.active})"
        )


class Admin(User):
    """Клас адміністратора, що розширює User набором прав доступу."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: set[str] | list[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username=username, email=email, role="admin", active=active)
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        """Надати право доступу."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Відкликати право доступу."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевірити наявність права доступу."""
        return permission in self.permissions

    def __str__(self) -> str:
        sorted_perms = sorted(self.permissions)
        return (
            f"Admin(username='{self.username}', email='{self.email}', "
            f"active={self.active}, permissions={sorted_perms})"
        )


class Session:
    """Клас сеансу автентифікації користувача."""

    def __init__(self, ip: str, login_time: datetime, last_activity: datetime) -> None:
        self.ip: str = ip
        self.login_time: datetime = login_time
        self.last_activity: datetime = last_activity

    def touch(self) -> None:
        """Оновити час останньої активності поточним часом UTC."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевірити, чи сесія не перевищила ліміт неактивності."""
        if timeout_sec <= 0:
            raise ValueError("Таймаут повинен бути строго більшим за 0.")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditRecord:
    """Незмінний запис журналу аудиту безпеки."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій безпеки."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        """Додати подію до журналу (час генерується в UTC)."""
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self._records.append(record)

    def show_all(self) -> list[AuditRecord]:
        """Отримати копію всіх записів журналу."""
        return list(self._records)


class UserAccount:
    """Агрегуючий клас облікового запису (композиція User, Session, AuditLog)."""

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user: User = user
        self.session: Session | None = session
        self.audit_log: AuditLog = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Вхід у систему: перевірка облікових даних та створення сеансу."""
        if (
            self.user.username != username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False

        now = datetime.now(timezone.utc)
        self.session = Session(ip=ip, login_time=now, last_activity=now)
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Перевірка чинності поточної сесії (невдала спроба не подовжує час)."""
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Вихід із системи та завершення сеансу."""
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, item: str) -> object:
        """Спеціальний доступ до атрибутів через індексатор."""
        allowed_attrs = {
            "user": self.user,
            "session": self.session,
            "audit_log": self.audit_log,
        }
        if item in allowed_attrs:
            return allowed_attrs[item]
        raise KeyError(f"Ключ '{item}' заборонено або він відсутній у UserAccount.")

    def __setitem__(self, item: str, value: object) -> None:
        """Безпечне встановлення атрибутів через індексатор із перевіркою типів."""
        if item == "user":
            if not isinstance(value, User):
                raise TypeError("Значення для 'user' повинно бути екземпляром User.")
            self.user = value
        elif item == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення для 'session' повинно бути Session або None.")
            self.session = value
        elif item == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError(
                    "Значення для 'audit_log' повинно бути екземпляром AuditLog."
                )
            self.audit_log = value
        else:
            raise KeyError(f"Встановлення ключа '{item}' заборонено.")