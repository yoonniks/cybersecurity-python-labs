from fastapi import APIRouter, HTTPException, Query, status

from labs.lab03.repository import (
    ConflictError,
    NotFoundError,
    bulk_create_records,
    create_record,
    delete_record,
    get_record_by_id,
    get_records,
    update_record,
)
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=list[RecordRead])
def read_records(
    category_id: int | None = Query(None, gt=0),
    status_param: str | None = Query(None, alias="status"),
    min_value: float | None = Query(None, ge=0.0, le=10.0),
    q: str | None = Query(None, min_length=1, max_length=120),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return get_records(
        category_id=category_id,
        status=status_param,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get("/{record_id}", response_model=RecordRead)
def read_record(record_id: int):
    if record_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Ідентифікатор повинен бути додатним числом.",
        )
    record = get_record_by_id(record_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Запис з id={record_id} не знайдено.",
        )
    return record


@router.post("", response_model=RecordRead, status_code=status.HTTP_201_CREATED)
def add_record(record: RecordCreate):
    try:
        return create_record(
            code=record.code,
            title=record.title,
            category_id=record.category_id,
            value=record.value,
            status=record.status,
        )
    except NotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))
    except ConflictError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err))


@router.put("/{record_id}", response_model=RecordRead)
def replace_record(record_id: int, record: RecordReplace):
    if record_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Ідентифікатор повинен бути додатним числом.",
        )
    try:
        return update_record(
            record_id=record_id,
            code=record.code,
            title=record.title,
            category_id=record.category_id,
            value=record.value,
            status=record.status,
        )
    except NotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))
    except ConflictError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err))


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_record(record_id: int):
    if record_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Ідентифікатор повинен бути додатним числом.",
        )
    try:
        delete_record(record_id)
    except NotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))


@router.post(
    "/bulk", response_model=list[RecordRead], status_code=status.HTTP_201_CREATED
)
def add_records_bulk(items: list[RecordCreate]):
    if not items or len(items) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Кількість елементів у пакеті повинна бути від 1 до 100.",
        )
    data = [item.model_dump() for item in items]
    try:
        return bulk_create_records(data)
    except NotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))
    except ConflictError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err))
