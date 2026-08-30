from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.models import SafetyLog
from app.routes import chat, dashboard


# ==========================================
# CREATE FASTAPI APPLICATION
# ==========================================

app = FastAPI(
    title="AI Child Digital Safety Platform",
    description="Universal AI Safety Layer protecting children interacting with LLMs.",
    version="1.0.0"
)


# ==========================================
# ENABLE CORS
# ==========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# REGISTER ROUTES
# ==========================================

app.include_router(chat.router)
app.include_router(dashboard.router)


# ==========================================
# CREATE DATABASE TABLES
# ==========================================

Base.metadata.create_all(bind=engine)


# ==========================================
# ROOT ENDPOINT
# ==========================================

@app.get("/")
def read_root():
    return {
        "status": "Safety Engine Running"
    }

