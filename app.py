from fastapi import FastAPI
from datetime import datetime
from db import init_db

app = FastAPI(title="Clink Lab", version="0.0.1")

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/health")
def health():
    return{"status": "ok", "ts": datetime.utcnow().isoformat() + "Z"}
