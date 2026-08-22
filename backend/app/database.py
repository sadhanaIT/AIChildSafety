import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

# MySQL connection string format: mysql+pymysql://user:password@host:port/database_name
# Default local XAMPP/WAMP or local MySQL setup example:
MYSQL_USER = os.getenv("DB_USER", "root")
MYSQL_PASSWORD = os.getenv("DB_PASSWORD", "")
MYSQL_HOST = os.getenv("DB_HOST", "localhost")
MYSQL_PORT = os.getenv("DB_PORT", "3306")
MYSQL_DB = os.getenv("DB_NAME", "child_safety_db")

DATABASE_URL = f"mysql+pymysql://root:sadhanarajak_13@localhost:3306/child_safety_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency to get database session in FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()