import random
import sys
import os

# Додаємо корінь проєкту до шляху пошуку для коректного імпорту shared-модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER


def get_variant_data():
    """Повертає вихідні дані відповідно до завдання."""
    passwords = [
        "InfoS3c@2023", "simple123", "Def3ns3@Key", "public",
        "Encrypt3d#Pass", "basic123", "Secur3@Analysis", "temp123",
        "Pr0t3ct@Data", "default"
    ]

    criteria = {
        "min_length": 8,
        "require_digits": True,
        "require_upper": True,
        "require_special": True
    }

    forbidden_passwords = {
        "simple123", "public", "basic123", "temp123", "default",
        "guest"
    }

    return passwords, criteria, forbidden_passwords


def analyze_password(password, forbidden_list, criteria):
    """Оцінює надійність пароля за заданими критеріями."""
    min_length = criteria["min_length"]

    # 1. Заборонений або менший за мінімальну довжину
    if password in forbidden_list or len(password) < min_length:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = not password.isalnum()

    criteria_count = sum([has_digit, has_upper, has_lower, has_special])

    # Дуже сильний: всі критерії виконані, довжина >= min_length + 4
    if criteria_count == 4 and len(password) >= min_length + 4:
        return "Дуже сильний"

    # Сильний: всі критерії виконані, але довжина менша за min_length + 4
    if criteria_count == 4 and len(password) < min_length + 4:
        return "Сильний"

    # Середній: відповідає мінімальній довжині та частині критеріїв
    if len(password) >= min_length and criteria_count >= 2:
        return "Середній"

    # Слабкий
    return "Слабкий"


def main():
    print(f"--- АНАЛІЗАТОР НАДІЙНОСТІ ПАРОЛІВ ---")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

    passwords, criteria, forbidden_passwords = get_variant_data()

    # Генерація 3 випадкових індексів і додавання їх дублікатів у кінець списку
    random_indices = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    for idx in random_indices:
        passwords.append(passwords[idx])

    print(f"Загальна кількість паролів для аналізу (з урахуванням дублікатів): {len(passwords)}")
    print(f"Мінімальна довжина: {criteria['min_length']}\n")

    # Виведення результату в табличному форматі
    print(f"{'№':<3} | {'Пароль':<20} | {'Статус безпеки'}")
    print("-" * 50)

    for i, pwd in enumerate(passwords, 1):
        status = analyze_password(pwd, forbidden_passwords, criteria)
        print(f"{i:<3} | {pwd:<20} | {status}")


if __name__ == "__main__":
    main()