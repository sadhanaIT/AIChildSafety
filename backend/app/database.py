import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Update 'password' to your MySQL root password
MYSQL_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:sadhanarajak_13@localhost:3306/child_safety_db")

engine = create_engine(MYSQL_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()