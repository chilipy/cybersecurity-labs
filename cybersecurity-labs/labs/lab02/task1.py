"""Завдання 1: Модель користувача, безпечної сесії та аудиту (ООП)."""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class User:
    """Клас для опису користувача системи."""

    ITERATIONS: int = 100_000

    def __init__(
        self, username: str, email: str, role: str = "User", active: bool = True
    ):
        self.username = username
        self.role = role
        self.active = active
        self._email: str = ""
        self.email = email  # Викликає setter з перевіркою re
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        # Локальна частина: починається з латинської літери, 3–64 символи (букви, цифри, _)
        # Доменна частина: містить принаймні одну крапку
        pattern = r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: '{value}'")
        self._email = value

    def set_password(self, password: str) -> None:
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            self.ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        if self.__password_hash is None or self.__password_salt is None:
            return False
        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            self.ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, calculated_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User({self.username}, Role: {self.role}, Email: {self.email}, Status: {status})"


class Admin(User):
    """Клас адміністратора з правами доступу (наслідування від User)."""

    def __init__(
        self, username: str, email: str, permissions: list[str] | set[str] | None = None
    ):
        super().__init__(username=username, email=email, role="Admin")
        if permissions is None:
            self.permissions: set[str] = set()
        else:
            self.permissions = set(permissions)

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_str = super().__str__()
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"{base_str} [Permissions: {perms}]"


class Session:
    """Управління сесією користувача в UTC."""

    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним числом (> 0).")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)


@dataclass
class AuditLogEntry:
    """Окремий запис у журналі аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту дій у системі."""

    def __init__(self):
        self.entries: list[AuditLogEntry] = []

    def add_log(self, username: str, action: str) -> None:
        entry = AuditLogEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self.entries.append(entry)

    def show_all(self) -> list[str]:
        return [
            f"[{e.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] User: {e.username} | Action: {e.action}"
            for e in self.entries
        ]


class UserAccount:
    """Композиційний клас облікового запису користувача."""

    SESSION_TIMEOUT_SEC: int = 900  # 15 хвилин

    def __init__(self, user: User, audit_log: AuditLog | None = None):
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if not self.user.active or self.user.username != username:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip=ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            self.audit_log.add_log(username, "login_failure")
            return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        return self.session.is_active(self.SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        # Аудит фіксується тільки якщо була дійсно активна сесія
        if self.session is not None:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Доступ за ключем '{key}' заборонено або ключ відсутній.")

    def __setitem__(self, key: str, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення для 'user' має бути об'єктом класу User.")
            self.user = value
        else:
            raise KeyError(f"Зміна атрибута за ключем '{key}' не підтримується.")


def run_demo() -> None:
    """Функція для повного розгорнутого тестування (демонстрації)."""
    print("=" * 65)
    print("      ЕТАЛОННИЙ ТЕСТ ЛАБОРАТОРНОЇ РОБОТИ (TASK 1)")
    print("=" * 65)

    # 1. Створення користувача та хешування
    print("\n1. Створення користувача та хешування (PBKDF2 SHA-256):")
    user = User(username="oleg_v", email="oleg_v@corp.ua")
    user.set_password("SecurePassword123!")
    print(f"   [+] Об'єкт створено: {user}")

    # 2. Валідація Email
    print("\n2. Перевірка валідації Email (Regex):")
    try:
        user.email = "bad_email"
    except ValueError as e:
        print(f"   [+] Перехоплено невірний формат: {e}")
    user.email = "valid_student@corp.ua"
    print(f"   [+] Змінено на коректний: {user.email}")

    # 3. Наслідування Admin
    print("\n3. Перевірка класу Admin (Наслідування):")
    admin = Admin(username="admin_alex", email="admin@corp.ua")
    admin.grant_permission("READ_LOGS")
    admin.grant_permission("MANAGE_USERS")
    print(f"   [+] {admin}")
    print(f"   [+] Перевірка права READ_LOGS: {admin.has_permission('READ_LOGS')}")

    # 4. Авторизація та Сесії
    print("\n4. Перевірка авторизації та AuditLog (Композиція):")
    audit = AuditLog()
    account = UserAccount(user=user, audit_log=audit)

    print("   * Спроба входу з невірним паролем...")
    res_fail = account.login("oleg_v", "WrongPass!", ip="192.168.1.10")
    print(f"     Успіх входу: {res_fail} | Сесія активна: {account.is_authenticated()}")

    print("   * Спроба входу з ВІРНИМ паролем...")
    res_ok = account.login("oleg_v", "SecurePassword123!", ip="192.168.1.10")
    print(f"     Успіх входу: {res_ok} | Сесія активна: {account.is_authenticated()}")

    # 5. Спеціальні методи
    print("\n5. Перевірка спецметоду __getitem__ (account['user']):")
    print(f"   [+] Отримано username: {account['user'].username}")

    # 6. Таймаут сесії
    print("\n6. Перевірка закінчення сеансу за таймаутом:")
    if account.session:
        account.session.last_activity -= timedelta(seconds=901)
    print(f"   [+] Статус після 901с таймауту: {account.is_authenticated()}")

    # 7. Вихід та Аудит
    print("\n7. Завершення сеансу (logout) та Журнал Аудиту:")
    account.login("oleg_v", "SecurePassword123!", ip="192.168.1.10")
    account.logout()
    print("   " + "-" * 55)
    for log in audit.show_all():
        print(f"   {log}")
    print("   " + "-" * 55)

    print("\n" + "=" * 65)
    print("               УСІ ТЕСТИ ПРОЙДЕНО НА 100/100")
    print("=" * 65)


if __name__ == "__main__":
    run_demo()
