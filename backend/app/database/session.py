from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.database.base import Base
# Import models to ensure metadata registration
import app.models  # noqa: F401

engine_kwargs = {"echo": settings.DEBUG}

if settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs.update({
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
    })

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """
    Initializes database schema by creating all tables defined in Base.metadata.
    Automatically creates SQLite database file if it does not exist.
    """
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            columns = [col[1] for col in conn.exec_driver_sql("PRAGMA table_info(email_messages)").fetchall()]
            if "raw_headers" not in columns:
                conn.exec_driver_sql("ALTER TABLE email_messages ADD COLUMN raw_headers JSON DEFAULT '[]'")
                conn.commit()
    except Exception as e:
        print(f"Notice during init_db column check: {e}")


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a transactional database session per request.
    Automatically closes the session after the request finishes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
