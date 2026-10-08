"""Головний модуль запуску Лабораторної роботи №2.

Послідовно виконує обробку Завдання 1 та Завдання 2, виводячи підсумкові
результати аудиту у консоль.
"""

import logging
from pathlib import Path
import sys

# =====================================================================
# НАСТРОЙКА ПУТЕЙ И ИМПОРТОВ
# =====================================================================
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Импортируем модули целиком, чтобы избежать ошибок с именами функций
import task1
import task2

# =====================================================================
# НАСТРОЙКА ПУТЕЙ К ДАННЫМ
# =====================================================================
DATA_DIR = BASE_DIR / "data"

# Файлы для Задания 1 (Sudo Audit)
SUDO_LOG_PATH = DATA_DIR / "sudo.log"
SUDO_REPORT_PATH = DATA_DIR / "sudo_audit_report.json"

# Файлы для Задания 2 (Password Audit)
WORDLIST_PATH = DATA_DIR / "rockyou_sample.txt"
WORDLIST_REPORT_PATH = DATA_DIR / "mask_audit_report.json"

# =====================================================================
# НАСТРОЙКА ЛОГИРОВАНИЯ
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("Lab02Main")


def run_task1() -> None:
    """Вызывает главную функцию из task1.py универсальным способом."""
    # Определяем имеющуюся функцию аудита в task1.py
    for func_name in ("audit_sudo_logs", "audit_sudo_log", "parse_sudo_log", "main"):
        if hasattr(task1, func_name):
            audit_fn = getattr(task1, func_name)
            # Если функция принимает аргументы пути
            try:
                audit_fn(SUDO_LOG_PATH, SUDO_REPORT_PATH)
            except TypeError:
                try:
                    audit_fn(log_path=SUDO_LOG_PATH)
                except TypeError:
                    audit_fn()
            return
    logger.warning("Не удалось автоматически найти функцию аудита в task1.py")


def run_lab02() -> None:
    """Виконує повний цикл Лабораторної роботи №2 (Task 1 + Task 2)."""
    print("\n" + "=" * 60)
    print("      ЛАБОРАТОРНА РОБОТА №2: АНАЛІЗ ЛОГІВ ТА СЛОВНИКІВ")
    print("=" * 60 + "\n")

    # -----------------------------------------------------------------
    # ЗАДАНИЕ 1: Аудит sudo логов
    # -----------------------------------------------------------------
    print(">>> ЗАПУСК ЗАВДАННЯ 1: Аудит лог-файлів sudo...\n")
    if not SUDO_LOG_PATH.exists():
        logger.warning(
            f"Файл логов {SUDO_LOG_PATH} не найден. Создаем тестовую директорию..."
        )
        SUDO_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        SUDO_LOG_PATH.touch()

    try:
        run_task1()
    except Exception as e:
        logger.error(f"Помилка під час виконання Завдання 1: {e}")

    print("\n" + "-" * 60 + "\n")

    # -----------------------------------------------------------------
    # ЗАДАНИЕ 2: Аудит масок и надежности паролей
    # -----------------------------------------------------------------
    print(">>> ЗАПУСК ЗАВДАННЯ 2: Аудит масок словників паролів...\n")
    if not WORDLIST_PATH.exists() or WORDLIST_PATH.stat().st_size == 0:
        if hasattr(task2, "prepare_sample_data"):
            task2.prepare_sample_data(WORDLIST_PATH)

    try:
        if hasattr(task2, "audit_wordlist"):
            task2.audit_wordlist(
                wordlist_path=WORDLIST_PATH,
                min_length=8,
                top_masks_count=5,
                output_stats_path=WORDLIST_REPORT_PATH,
            )
        elif hasattr(task2, "main"):
            task2.main()
    except Exception as e:
        logger.error(f"Помилка під час виконання Завдання 2: {e}")

    print("\n" + "=" * 60)
    print("      ВИКОНАННЯ ЛАБОРАТОРНОЇ РОБОТИ №2 ЗАВЕРШЕНО")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run_lab02()