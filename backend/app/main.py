from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.routes import chat

# Initialize MySQL Tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI Child Digital Safety Platform")

# CORS Setup to allow React Frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for React frontend host in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat.router, prefix="/api/v1")

@app.get("/")
def root():
    return {"status": "Safety Engine Running"}