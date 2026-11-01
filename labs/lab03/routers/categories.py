from fastapi import APIRouter, HTTPException, status

from labs.lab03.repository import (
    ConflictError,
    NotFoundError,
    create_category,
    delete_category,
    get_all_categories,
)
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Categories"])


@router.get("", response_model=list[CategoryRead])
def read_categories():
    return get_all_categories()


@router.post("", response_model=CategoryRead, status_code=status.HTTP_201_CREATED)
def add_category(category: CategoryCreate):
    try:
        return create_category(category.name)
    except ConflictError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err))


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_category(category_id: int):
    if category_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Ідентифікатор повинен бути додатним числом.",
        )
    try:
        delete_category(category_id)
    except NotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))
    except ConflictError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err))
