# ============================================================
# AI CHILD DIGITAL SAFETY PLATFORM
# MAIN FASTAPI APPLICATION
# ============================================================

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.routes import chat, dashboard, profile


# ============================================================
# CREATE DATABASE TABLES
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# CREATE FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="AI Child Digital Safety Platform",
    description=(
        "Universal AI Safety Layer protecting users "
        "interacting with external AI systems."
    ),
    version="1.0.0",
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

ALLOWED_ORIGINS = [

    # --------------------------------------------------------
    # Localhost
    # --------------------------------------------------------

    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",

    # --------------------------------------------------------
    # 127.0.0.1
    # --------------------------------------------------------

    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",

    # --------------------------------------------------------
    # Your current LAN React address
    # --------------------------------------------------------

    "http://192.168.0.101:3000",
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_private_network=True,
    max_age=600,
)


# ============================================================
# REGISTER ROUTES
# ============================================================

app.include_router(chat.router)
app.include_router(dashboard.router)
app.include_router(profile.router)


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def read_root():
    return {
        "status": "Safety Engine Running"
    }