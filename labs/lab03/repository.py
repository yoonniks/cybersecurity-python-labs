import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection


class RepositoryError(Exception):
    pass


class NotFoundError(RepositoryError):
    pass


class ConflictError(RepositoryError):
    pass


def get_all_categories() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute("SELECT id, name FROM categories ORDER BY id ASC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_category_by_id(category_id: int) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute("SELECT id, name FROM categories WHERE id = ?", (category_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def create_category(name: str) -> dict[str, Any]:
    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.cursor()
                cursor.execute("INSERT INTO categories (name) VALUES (?)", (name,))
                category_id = cursor.lastrowid
            return {"id": category_id, "name": name}
        except sqlite3.IntegrityError as err:
            raise ConflictError(f"Категорія з такою назвою вже існує: {name}") from err


def delete_category(category_id: int) -> None:
    if not get_category_by_id(category_id):
        raise NotFoundError(f"Категорію з id={category_id} не знайдено.")

    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.cursor()
                cursor.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        except sqlite3.IntegrityError as err:
            raise ConflictError(
                "Неможливо видалити категорію, яка містить записи."
            ) from err


def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    if category_id is not None and not get_category_by_id(category_id):
        return []

    sql = """
        SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE 1=1
    """
    params: list[Any] = []

    if category_id is not None:
        sql += " AND r.category_id = ?"
        params.append(category_id)

    if status is not None:
        sql += " AND r.status = ?"
        params.append(status)

    if min_value is not None:
        sql += " AND r.value >= ?"
        params.append(min_value)

    if q is not None:
        sql += " AND instr(r.title, ?) > 0"
        params.append(q)

    sql += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_record_by_id(record_id: int) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, r.value, r.status
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE r.id = ?
            """,
            (record_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def create_record(
    code: str, title: str, category_id: int, value: float, status: str
) -> dict[str, Any]:
    if not get_category_by_id(category_id):
        raise NotFoundError(f"Категорію з id={category_id} не знайдено.")

    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.cursor()
                cursor.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (code, title, category_id, value, status),
                )
                record_id = cursor.lastrowid
            return get_record_by_id(record_id)
        except sqlite3.IntegrityError as err:
            raise ConflictError(f"Запис із кодом {code} вже існує.") from err


def update_record(
    record_id: int, code: str, title: str, category_id: int, value: float, status: str
) -> dict[str, Any]:
    if not get_record_by_id(record_id):
        raise NotFoundError(f"Запис з id={record_id} не знайдено.")

    if not get_category_by_id(category_id):
        raise NotFoundError(f"Категорію з id={category_id} не знайдено.")

    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.cursor()
                cursor.execute(
                    """
                    UPDATE records
                    SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                    WHERE id = ?
                    """,
                    (code, title, category_id, value, status, record_id),
                )
            return get_record_by_id(record_id)
        except sqlite3.IntegrityError as err:
            raise ConflictError(f"Запис із кодом {code} вже існує.") from err


def delete_record(record_id: int) -> None:
    if not get_record_by_id(record_id):
        raise NotFoundError(f"Запис з id={record_id} не знайдено.")

    with closing(get_connection()) as connection, connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM records WHERE id = ?", (record_id,))


def bulk_create_records(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    codes = [item["code"] for item in items]
    if len(codes) != len(set(codes)):
        raise ConflictError("У пакеті виявлено дублікати коду (code).")

    with closing(get_connection()) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()

        for item in items:
            cursor.execute(
                "SELECT id FROM categories WHERE id = ?", (item["category_id"],)
            )
            if not cursor.fetchone():
                raise NotFoundError(
                    f"Категорію з id={item['category_id']} не знайдено у базі даних."
                )

        created_ids = []
        try:
            with connection:
                for item in items:
                    cursor.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            item["code"],
                            item["title"],
                            item["category_id"],
                            item["value"],
                            item["status"],
                        ),
                    )
                    created_ids.append(cursor.lastrowid)
        except sqlite3.IntegrityError as err:
            raise ConflictError(
                "Помилка цілісності даних при пакетному додаванні."
            ) from err

    result = []
    for rec_id in created_ids:
        rec = get_record_by_id(rec_id)
        if rec:
            result.append(rec)
    return result
