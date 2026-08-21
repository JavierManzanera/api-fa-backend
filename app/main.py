from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.config import settings
from app.api.v1.router import api_router
from app.core.database import engine, Base
from app.models import user, verification, rate_limit
import uvicorn


@asynccontextmanager
async def lifespan(app: FastAPI):
    # In production, use Alembic. For quick start, this works.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
def read_root():
    return {"msg": "Welcome to FastAPI Headless Auth API"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
