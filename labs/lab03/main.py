from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.config import DOMAIN_NAME, THRESHOLD, UNIT
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title=DOMAIN_NAME,
    description=f"Предметна область: {DOMAIN_NAME}. Одиниця вимірювання: {UNIT}. Поріг: {THRESHOLD}.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.get("/student")
def get_student_info():
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
