import os
import sys
import csv
import json
import hashlib
import datetime
from functools import wraps

# Додаємо корінь проєкту до шляху пошуку для коректного імпорту shared-модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER


# 1. Власний виняток ValidationError
class ValidationError(Exception):
    """Виняток, що викликається, якщо пароль не відповідає критеріям довжини."""
    pass


# 1 & 2. Функція безпечного хешування з персональною сіллю (варіант 6 -> "00006")
def generate_hash(password: str, salt: str = "00006") -> str:
    """Генерує SHA-256 хеш від конкатенації пароля та солі."""
    if not password:
        raise ValueError("Пароль не може бути порожнім або None!")
    if not salt:
        raise ValueError("Сіль не може бути порожньою або None!")

    min_length = 8
    if len(password) < min_length:
        raise ValidationError(f"Пароль занадто короткий! Мінімальна довжина: {min_length}")

    data_to_hash = (password + salt).encode('utf-8')
    return hashlib.sha256(data_to_hash).hexdigest()


# 6. Декоратор для логування подій у JSON
def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "unknown")

        result_status = "failure"
        try:
            res = func(*args, **kwargs)
            if res is True:
                result_status = "success"
            return res
        except Exception as e:
            result_status = "failure"
            raise e
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs
            }

            log_dir = os.path.join(os.path.dirname(__file__), "data")
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, "log.json")

            logs = []
            try:
                if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
                    with open(log_path, "r", encoding="utf-8") as f:
                        logs = json.load(f)
            except (json.JSONDecodeError, IOError):
                logs = []

            logs.append(log_entry)

            with open(log_path, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

    return wrapper


def create_user(username: str, password: str, salt: str = "00006"):
    """Створює пару (логін, хеш пароля)."""
    hsh = generate_hash(password, salt)
    return (username, hsh)


def create_users(users_list, csv_path):
    """Створює базу даних у CSV-файлі, гарантовано створюючи теку data."""
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password_hash"])
        for uname, pwd in users_list:
            try:
                _, hsh = create_user(uname, pwd, salt="00006")
                writer.writerow([uname, hsh])
            except (ValueError, ValidationError) as e:
                print(f"[Попередження при створенні] Користувач {uname} пропущений: {e}")


def read_users_db(csv_path):
    """Зчитує CSV-базу даних у список користувачів."""
    users_db = []
    if not os.path.exists(csv_path):
        return users_db

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if len(row) == 2:
                users_db.append({"username": row[0], "password_hash": row[1]})
    return users_db


# 5. Автентифікація з декоратором логування
@log_event
def login(username: str, password: str, csv_path: str) -> bool:
    """Перевіряє автентифікацію користувача за CSV-базою."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми!")

    users_db = read_users_db(csv_path)
    input_hash = generate_hash(password, salt="00006")

    for user in users_db:
        if user["username"] == username and user["password_hash"] == input_hash:
            return True

    return False


def main():
    print(f"--- БЕЗПЕЧНЕ ХЕШУВАННЯ ТА ЛОГУВАННЯ ---")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

    data_dir = os.path.join(os.path.dirname(__file__), "data")
    csv_file = os.path.join(data_dir, "users.csv")

    users_to_register = [
        ("oleh_admin", "SuperSecure2026!"),
        ("ivan_user", "StrongPass123"),
        ("petro_dev", "CodeMaster99#"),
        ("anna_sec", "CyberGirl2026$"),
        ("viktor_qa", "TestPass55!"),
        ("olga_hr", "HrSecurePass88*"),
        ("weak_user", "123"),
        ("empty_pass", ""),
        ("guest_account", "Guest2026?"),
        ("root_admin", "RootAccess#007")
    ]

    try:
        print("[*] Створення бази даних користувачів...")
        create_users(users_to_register, csv_file)

        users_db = read_users_db(csv_file)
        print(f"\nЗчитано користувачів із файлу {csv_file}: {len(users_db)}\n")

        print(f"{'№':<3} | {'Логін користувача':<20} | {'Хеш пароля (SHA-256 + сіль)'}")
        print("-" * 75)
        for i, u in enumerate(users_db, 1):
            print(f"{i:<3} | {u['username']:<20} | {u['password_hash']}")

        print("\n[*] Тестування процесу автентифікації та логування...")

        try:
            res1 = login("ivan_user", "StrongPass123", csv_file)
            print(f"Спроба входу -> 'ivan_user' ('StrongPass123'): {'успішно' if res1 else 'неуспішно'}")
        except Exception as err:
            print(f"Помилка входу: {err}")

        try:
            res2 = login("ivan_user", "WrongPassword!", csv_file)
            print(f"Спроба входу -> 'ivan_user' ('WrongPassword!'): {'успішно' if res2 else 'неуспішно'}")
        except Exception as err:
            print(f"Спроба входу відхилена / Помилка: {err}")

        print(
            f"\n[OK] Журнал подій успішно збережено у {os.path.join(data_dir, 'log.json')} за допомогою декоратора @log_event.")

    except FileNotFoundError:
        print("[Помилка] Файл або каталог не знайдено.")
    except PermissionError:
        print("[Помилка] Недостатньо прав доступу до файлової системи.")
    except IOError as e:
        print(f"[Помилка введення-виведення (IOError)]: {e}")
    except ValidationError as e:
        print(f"[Помилка валідації пароля]: {e}")
    except ValueError as e:
        print(f"[Помилка значення]: {e}")
    except Exception as e:
        print(f"[Непередбачена помилка]: {e}")


if __name__ == "__main__":
    main()