import csv
import datetime
import hashlib
import json
import os
import sys
from functools import wraps

# Додаємо корінь проєкту до шляху пошуку для коректного імпорту shared-модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Глобальні константи
MIN_PASSWORD_LENGTH = 8
DEFAULT_SALT = f"{VARIANT_NUMBER:05d}" if isinstance(VARIANT_NUMBER, int) else "00006"


class ValidationError(Exception):
    pass


# Власний виняток для контролю доступу
class AccessDeniedError(Exception):
    """Виняток, що викликається при відмові в доступі або неавторизованій дії."""


def generate_hash(password: str, salt: str = DEFAULT_SALT) -> str:
    if not password:
        raise ValueError("Пароль не може бути порожнім або None!")
    if not salt:
        raise ValueError("Сіль не може бути порожньою або None!")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий! Мінімальна довжина: {MIN_PASSWORD_LENGTH}"
        )

    data_to_hash = (password + salt).encode("utf-8")
    return hashlib.sha256(data_to_hash).hexdigest()


def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "unknown")

        result_status = "failure"
        try:
            res = func(*args, **kwargs)
            if res is True:
                result_status = "success"
            elif res is False:
                result_status = "failure"
            return res

        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            try:
                log_dir = os.path.join(os.path.dirname(__file__), "data")
                os.makedirs(log_dir, exist_ok=True)
                log_path = os.path.join(log_dir, "log.json")

                logs = []
                if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
                    with open(log_path, "r", encoding="utf-8") as f:
                        logs = json.load(f)

                logs.append(log_entry)

                with open(log_path, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except FileNotFoundError:
                print("[Помилка логування] Не вдалося знайти файл журналу подій.")
            except PermissionError:
                print("[Помилка логування] Недостатньо прав для запису журналу подій.")
            except OSError as e:
                print(
                    f"[Помилка логування] Помилка вводу-виводу при збереженні логів: {e}"
                )

    return wrapper


def create_user(username: str, password: str, salt: str = DEFAULT_SALT):
    hsh = generate_hash(password, salt)
    return (username, hsh)


def create_users(users_list, csv_path):
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    try:
        with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])
            for uname, pwd in users_list:
                try:
                    _, hsh = create_user(uname, pwd, salt=DEFAULT_SALT)
                    writer.writerow([uname, hsh])
                except (ValueError, ValidationError) as e:
                    print(
                        f"[Попередження при створенні] Користувач {uname} пропущений: {e}"
                    )
    except FileNotFoundError:
        print(f"[Помилка] Файл або шлях не знайдено: {csv_path}")
    except PermissionError:
        print(
            "[Помилка] Недостатньо прав доступу до файлової системи під час створення бази."
        )
    except OSError as e:
        print(f"[Помилка введення-виведення (IOError)] під час створення бази: {e}")


def read_users_db(csv_path):
    users_db = []

    try:
        if not os.path.exists(csv_path):
            raise FileNotFoundError(
                f"Файл бази даних не знайдено за шляхом: {csv_path}"
            )

        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if len(row) == 2:
                    users_db.append({"username": row[0], "password_hash": row[1]})
    except FileNotFoundError as e:
        print(f"[Помилка FileNotFoundError]: {e}")
    except PermissionError as e:
        print(f"[Помилка PermissionError] Недостатньо прав для читання бази: {e}")
    except OSError as e:
        print(f"[Помилка читання бази]: {e}")

    return users_db


@log_event
def login(username: str, password: str, csv_path: str) -> bool:
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми!")

    users_db = read_users_db(csv_path)
    if not users_db:
        raise AccessDeniedError("База даних користувачів порожня або недоступна!")

    input_hash = generate_hash(password, salt=DEFAULT_SALT)

    for user in users_db:
        if user["username"] == username and user["password_hash"] == input_hash:
            return True

    return False


def main():
    print("--- БЕЗПЕЧНЕ ХЕШУВАННЯ ТА ЛОГУВАННЯ ---")
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
    )

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
        ("root_admin", "RootAccess#007"),
    ]

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
        print(
            f"Спроба входу -> 'ivan_user' ('StrongPass123'): {'успішно' if res1 else 'неуспішно'}"
        )
    except Exception as err:
        print(f"Помилка входу: {err}")

    try:
        res2 = login("ivan_user", "WrongPassword!", csv_file)
        print(
            f"Спроба входу -> 'ivan_user' ('WrongPassword!'): {'успішно' if res2 else 'неуспішно'}"
        )
    except Exception as err:
        print(f"Спроба входу відхилена / Помилка: {err}")

    print(
        f"\n[OK] Журнал подій успішно збережено у {os.path.join(data_dir, 'log.json')} за допомогою декоратора @log_event."
    )


if __name__ == "__main__":
    main()
