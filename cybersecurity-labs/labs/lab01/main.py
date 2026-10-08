import os
import sys

# Додаємо корінь проєкту до шляху пошуку для коректного імпорту shared-модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Імпортуємо головні функції з кожного таску
from task1 import main as run_task1
from task2 import main as run_task2
from task3 import main as run_task3


def main():
    print("=" * 70)
    print("ГОЛОВНИЙ ЗАПУСК ЛАБОРАТОРНОЇ РОБОТИ")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 70 + "\n")

    # --- ЗАПУСК ТАСКУ 1 ---
    print(">>> ВИКОНАННЯ ЗАВДАННЯ 1: Аналізатор надійності паролів\n")
    try:
        run_task1()
    except Exception as e:
        print(f"[Помилка у Task 1]: {e}")

    print("\n" + "=" * 70 + "\n")

    # --- ЗАПУСК ТАСКУ 2 ---
    print(">>> ВИКОНАННЯ ЗАВДАННЯ 2: Багаторівнева система контролю доступу\n")
    try:
        run_task2()
    except Exception as e:
        print(f"[Помилка у Task 2]: {e}")

    print("\n" + "=" * 70 + "\n")

    # --- ЗАПУСК ТАСКУ 3 ---
    print(">>> ВИКОНАННЯ ЗАВДАННЯ 3: Безпечне хешування та логування\n")
    try:
        run_task3()
    except Exception as e:
        print(f"[Помилка у Task 3]: {e}")

    print("\n" + "=" * 70)
    print("ВСІ ЗАВДАННЯ УСПІШНО ВИКОНАНО!")
    print("=" * 70)


if __name__ == "__main__":
    main()
