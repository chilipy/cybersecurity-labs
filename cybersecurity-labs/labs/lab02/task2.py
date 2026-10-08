"""Варіант 6: Аудитор надійності та масок словників паролів.

Утиліта для аналізу якісного складу текстових словників паролів.
"""

import argparse
import json
import logging
import re
import sys
from collections import Counter
from collections.abc import Generator
from pathlib import Path
from typing import TypedDict

# =====================================================================
# ШЛЯХИ ЗА ЗАМОВЧУВАННЯМ (Згідно зі структурою репозиторію)
# =====================================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_WORDLIST = DATA_DIR / "rockyou_sample.txt"
DEFAULT_REPORT = DATA_DIR / "mask_audit_report.json"

# =====================================================================
# НАЛАШТУВАННЯ ЛОГУВАННЯ
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("PasswordAudit")


# =====================================================================
# ТИПІЗАЦІЯ ДЛЯ JSON-ЗВІТУ
# =====================================================================
class MaskStat(TypedDict):
    mask: str
    count: int
    percentage: float
    example: str


class AuditSummary(TypedDict):
    total_passwords: int
    weak_passwords: int
    weak_percentage: float
    average_length: float
    top_masks: list[MaskStat]


# =====================================================================
# 1. ГЕНЕРАТОР ДЛЯ ЧИТАННЯ ВЕЛИКИХ ФАЙЛІВ (Пам'ять: O(1))
# =====================================================================
def read_passwords(file_path: Path) -> Generator[str, None, None]:
    """Генератор для порядкового читання великих файлів без завантаження в RAM."""
    if not file_path.exists():
        raise FileNotFoundError(f"Файл словника не знайдено за шляхом: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            cleaned_line = line.rstrip("\r\n")
            if cleaned_line:
                yield cleaned_line


# =====================================================================
# 2. АНАЛІЗ МАСОК ПАРОЛІВ ЗА ДОПОМОГОЮ RE
# =====================================================================
def get_password_mask(password: str) -> str:
    """Визначає маску пароля на основі категорій символів."""
    if not password:
        return "empty"

    types: list[str] = []
    for char in password:
        if re.match(r"[A-Z]", char):
            types.append("u")
        elif re.match(r"[a-z]", char):
            types.append("l")
        elif re.match(r"[0-9]", char):
            types.append("d")
        else:
            types.append("s")

    has_u = "u" in types
    has_l = "l" in types
    has_d = "d" in types
    has_s = "s" in types

    if has_u and has_l and has_d and has_s:
        return "Complex (Upper-Lower-Digit-Special)"
    elif has_u and has_l and has_d:
        return "Upper-Lower-Digit (UlLd)"
    elif has_l and has_d and not has_u and not has_s:
        return "Lowercase-Digit (LdLd)"
    elif has_l and not has_u and not has_d and not has_s:
        return "All-Lowercase (LLLL)"
    elif has_d and not has_u and not has_l and not has_s:
        return "All-Digits (dddd)"
    elif has_u and not has_l and not has_d and not has_s:
        return "All-Uppercase (UUUU)"
    else:
        res = []
        last_cat = ""
        for t in types:
            if t != last_cat:
                res.append(t.upper() if t != "s" else "S")
                last_cat = t
            else:
                res.append(t.lower())
        return "".join(res)


# =====================================================================
# 3. ОСНОВНИЙ ПРОЦЕС АУДИТУ
# =====================================================================
def audit_wordlist(
    wordlist_path: Path,
    min_length: int = 8,
    top_masks_count: int = 5,
    output_stats_path: Path | None = None,
    log_interval: int = 10_000,
) -> AuditSummary:
    """Проводить повний аудит словника паролів."""
    logger.info(f"Processing dictionary file {wordlist_path} using generators...")

    total_passwords = 0
    weak_passwords = 0
    total_length = 0

    mask_counter: Counter[str] = Counter()
    mask_examples: dict[str, str] = {}

    for password in read_passwords(wordlist_path):
        total_passwords += 1
        p_len = len(password)
        total_length += p_len

        if p_len < min_length:
            weak_passwords += 1

        mask = get_password_mask(password)
        mask_counter[mask] += 1
        if mask not in mask_examples:
            mask_examples[mask] = password

        if total_passwords % log_interval == 0:
            logger.info(f"Analyzed {total_passwords:,} passwords.")

    if total_passwords == 0:
        raise ValueError("Словник паролів порожній або не містить придатних рядків.")

    avg_length = round(total_length / total_passwords, 1)
    weak_pct = round((weak_passwords / total_passwords) * 100, 1)

    top_masks_list: list[MaskStat] = []
    for mask_name, count in mask_counter.most_common(top_masks_count):
        percentage = round((count / total_passwords) * 100, 1)
        top_masks_list.append(
            {
                "mask": mask_name,
                "count": count,
                "percentage": percentage,
                "example": mask_examples.get(mask_name, ""),
            }
        )

    summary: AuditSummary = {
        "total_passwords": total_passwords,
        "weak_passwords": weak_passwords,
        "weak_percentage": weak_pct,
        "average_length": avg_length,
        "top_masks": top_masks_list,
    }

    # ПРЯМЕ КОНСОЛЬНЕ ВИВЕДЕННЯ ЗГІДНО З ТЗ
    print("\n=== Password Dictionary Audit Summary ===")
    print(f"Total Passwords        : {total_passwords:,}")
    print(f"Weak Passwords (<{min_length})   : {weak_passwords:,} ({weak_pct}%)")
    print(f"Average Length         : {avg_length} characters")

    print(f"\n=== Top-{len(top_masks_list)} Password Masks ===")
    for idx, item in enumerate(top_masks_list, 1):
        print(
            f"{idx}. {item['mask']} : {item['count']:,} ({item['percentage']}%) [e.g. {item['example']}]"
        )

    if output_stats_path:
        output_stats_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_stats_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4, ensure_ascii=False)
        logger.info(f"Dictionary statistics saved to {output_stats_path}\n")

    return summary


# =====================================================================
# АВТОМАТИЧНЕ СТВОРЕННЯ ДАНИХ ПРИ ЗАПУСКУ
# =====================================================================
def prepare_sample_data(file_path: Path) -> None:
    """Генерує 50,000 реалістичних тестових паролів у разі відсутності файлу."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Створення та заповнення тестового файлу {file_path}...")

    # Співвідношення паролів для реалістичного розподілу %
    passwords = (
        ["password123"] * 17500  # 35% Lowercase-Digit (LdLd)
        + ["admin"] * 12500  # 25% All-Lowercase (LLLL)
        + ["Password123"] * 10000  # 20% Upper-Lower-Digit (UlLd)
        + ["12345678"] * 5000  # 10% All-Digits (dddd)
        + ["P@ssw0rd!"] * 5000  # 10% Complex
    )

    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(passwords) + "\n")


# =====================================================================
# CLI АРГУМЕНТИ ТА ТОЧКА ВХОДУ
# =====================================================================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Утиліта для аудиту надійності та масок словників паролів."
    )
    parser.add_argument(
        "--wordlist",
        type=Path,
        default=DEFAULT_WORDLIST,
        help=f"Шлях до файлу словника паролів (за замовчуванням: {DEFAULT_WORDLIST}).",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=8,
        help="Мінімальна довжина пароля (за замовчуванням: 8).",
    )
    parser.add_argument(
        "--top-masks",
        type=int,
        default=5,
        help="Кількість найпопулярніших масок у звіті (за замовчуванням: 5).",
    )
    parser.add_argument(
        "--output-stats",
        type=Path,
        default=DEFAULT_REPORT,
        help=f"Шлях для збереження JSON-звіту (за замовчуванням: {DEFAULT_REPORT}).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Перевіряємо наявність та не-порожність файлу словника
    if not args.wordlist.exists() or args.wordlist.stat().st_size == 0:
        prepare_sample_data(args.wordlist)

    try:
        audit_wordlist(
            wordlist_path=args.wordlist,
            min_length=args.min_length,
            top_masks_count=args.top_masks,
            output_stats_path=args.output_stats,
        )
    except Exception as e:
        logger.error(f"Помилка під час виконання аудиту: {e}")
        sys.exit(1)
