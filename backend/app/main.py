from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import chat
from app.database import engine, Base
from app.models import SafetyLog  # Imports your models so tables can be created

# Automatically create database tables in MySQL if they do not exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Child Digital Safety Platform",
    description="Universal AI Safety Layer protecting children interacting with LLMs.",
    version="1.0.0"
)

# Enable CORS for React frontend (running on localhost:3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register chat routes
app.include_router(chat.router)

@app.get("/")
def read_root():
    return {"status": "Safety Engine Running"}