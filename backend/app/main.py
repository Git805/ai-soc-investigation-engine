from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app.db import Base, engine
from app.routes.events import router as events_router
from app.routes.investigations import router as investigations_router

app = FastAPI(title="AI SOC Investigation Engine", version="1.0.0")
Base.metadata.create_all(bind=engine)
app.include_router(events_router)
app.include_router(investigations_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "phase": "12", "service": "soc-investigation-engine"}


@app.get("/", include_in_schema=False)
def console():
    return FileResponse(Path(__file__).resolve().parents[2] / "frontend" / "index.html")
