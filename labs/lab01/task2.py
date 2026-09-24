import sys
import os

# Додаємо корінь проєкту до шляху пошуку для коректного імпорту shared-модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER


def get_access_control_data():
    """Повертає точні вхідні дані для системи контролю доступу."""
    security_levels = ("Academic", "Operational", "Tactical", "Strategic")

    users = {
        "red_team_lead": {"role": "red_team", "clearance": 4, "department": "Red Team", "active": True},
        "blue_team_analyst": {"role": "blue_team", "clearance": 3, "department": "Blue Team", "active": True},
        "purple_team_coord": {"role": "purple_team", "clearance": 3, "department": "Purple Team", "active": True},
        "student_intern": {"role": "student", "clearance": 1, "department": "Academia", "active": True},
        "retired_expert": {"role": "retired", "clearance": 2, "department": "Emeritus", "active": False}
    }

    resources = [
        ("attack_scenarios", 4), ("defense_playbooks", 3),
        ("exercise_plans", 3), ("research_papers", 1), ("exploit_tools", 4),
        ("student_resources", 1), ("simulation_results", 3), ("red_team_tools", 4),
        ("blue_team_reports", 3), ("public_research", 1)
    ]

    blocked_users = {"retired_expert", "academic_violator", "leaked_account"}

    return security_levels, users, resources, blocked_users


def check_access(username, user_info, resource_name, resource_level, blocked_users):
    """Алгоритм перевірки доступу користувача до ресурсу."""
    # 1. Якщо користувача немає в системі
    if user_info is None:
        return "DENY (User not found)"

    # 2. Якщо користувач у списку заблокованих
    if username in blocked_users:
        return "DENY (User is blocked)"

    # 3. Якщо обліковий запис неактивний
    if not user_info.get("active", False):
        return "DENY (Account inactive)"

    # 4 & 5. Порівняння рівнів допуску
    user_clearance = user_info.get("clearance", 0)

    if user_clearance >= resource_level:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"


def main():
    print(f"--- БАГАТОРІВНЕВА СИСТЕМА КОНТРОЛЮ ДОСТУПУ ---")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

    security_levels, users, resources, blocked_users = get_access_control_data()

    # Виведення списку ресурсів із заміною числових рівнів на текстові назви з кортежу
    print("Список ресурсів системи:")
    for res_name, res_level in resources:
        level_name = security_levels[res_level - 1] if 0 < res_level <= len(security_levels) else "Unknown"
        print(f" - Ресурс: {res_name:<20} | Рівень безпеки: {level_name} ({res_level})")
    print("-" * 65)

    # Додамо тестового неіснуючого користувача для перевірки правила "User not found"
    all_test_users = list(users.items()) + [("unknown_hacker", None)]

    print("\nРезультати перевірки доступу:")
    for username, user_info in all_test_users:
        for res_name, res_level in resources:
            status = check_access(username, user_info, res_name, res_level, blocked_users)
            print(f"user={username:<18} | resource={res_name:<20} -> {status}")


if __name__ == "__main__":
    main()