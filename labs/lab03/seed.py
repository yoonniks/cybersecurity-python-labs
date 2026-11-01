import json
import logging
import sqlite3
from contextlib import closing
from pathlib import Path

from labs.lab03.database import get_connection, initialize_database

BASE_DIR = Path(__file__).resolve().parent
SEED_FILE_PATH = BASE_DIR / "data" / "seed.json"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def seed_database() -> None:
    initialize_database()

    if not SEED_FILE_PATH.exists():
        logger.error(f"Файл початкових даних {SEED_FILE_PATH} не знайдено.")
        return

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM categories")
        categories_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM records")
        records_count = cursor.fetchone()[0]

        if categories_count > 0 or records_count > 0:
            logger.info("База даних вже містить дані. Початкове заповнення пропущено.")
            return

        try:
            with open(SEED_FILE_PATH, "r", encoding="utf-8") as file:
                data = json.load(file)

            categories = data.get("categories", [])
            records = data.get("records", [])

            with connection:
                connection.executemany(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    [(cat["id"], cat["name"]) for cat in categories],
                )
                connection.executemany(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            rec["code"],
                            rec["title"],
                            rec["category_id"],
                            rec["value"],
                            rec["status"],
                        )
                        for rec in records
                    ],
                )
            logger.info("Базу даних успішно заповнено початковими даними.")
        except (json.JSONDecodeError, KeyError, sqlite3.Error) as err:
            logger.error(f"Помилка при заповненні бази даних: {err}")


if __name__ == "__main__":
    seed_database()