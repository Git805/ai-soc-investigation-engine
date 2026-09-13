from fastapi import FastAPI

app = FastAPI(title="AI SOC Investigation Engine", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "phase": "1"}
