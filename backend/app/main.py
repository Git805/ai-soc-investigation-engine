from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app.db import Base, engine
from app.routes.alerts import router as alerts_router
from app.routes.attack import router as attack_router
from app.routes.demo import router as demo_router
from app.routes.events import router as events_router
from app.routes.evidence import router as evidence_router
from app.routes.intelligence import router as intelligence_router
from app.routes.investigations import router as investigations_router

app = FastAPI(title="AI SOC Investigation Engine", version="1.0.0")
Base.metadata.create_all(bind=engine)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(investigations_router)
app.include_router(evidence_router)
app.include_router(intelligence_router)
app.include_router(attack_router)
app.include_router(demo_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "phase": "12", "service": "soc-investigation-engine"}


@app.get("/", include_in_schema=False)
def console():
    return FileResponse(Path(__file__).resolve().parents[2] / "frontend" / "index.html")
