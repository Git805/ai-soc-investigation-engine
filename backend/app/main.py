from fastapi import FastAPI

from app.db import Base, engine
from app.routes.events import router as events_router

app = FastAPI(title="AI SOC Investigation Engine", version="0.2.0")

Base.metadata.create_all(bind=engine)
app.include_router(events_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "phase": "2"}
