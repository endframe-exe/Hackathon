import logging
from typing import Generator, Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

logger = logging.getLogger("phishguard.database")

Base = declarative_base()

_engine = None
_SessionLocal = None
is_db_connected: bool = False


def get_engine():
    global _engine
    if _engine is None:
        db_url = settings.DATABASE_URL
        if db_url.startswith("sqlite"):
            _engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False}
            )
        else:
            _engine = create_engine(
                db_url,
                pool_pre_ping=True,
                pool_recycle=3600,
                connect_args={"connect_timeout": 3}
            )
    return _engine


def get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=get_engine()
        )
    return _SessionLocal


def init_db() -> bool:
    """
    Initializes the database schema if ENABLE_HISTORY is true.
    Catches connection failures gracefully so that FastAPI continues to start
    even if MySQL is not currently running or credentials are unconfigured.
    """
    global is_db_connected
    if not settings.ENABLE_HISTORY:
        logger.info("Database persistence is disabled (ENABLE_HISTORY=false).")
        is_db_connected = False
        return False

    try:
        engine = get_engine()
        # Test connection quickly
        with engine.connect() as conn:
            pass
        Base.metadata.create_all(bind=engine)
        is_db_connected = True
        logger.info("Database tables verified/created successfully.")
        return True
    except Exception as e:
        is_db_connected = False
        logger.warning(
            "Could not connect to MySQL database at %s:%s. "
            "Analysis endpoints will function in stateless mode. Error: %s",
            settings.MYSQL_HOST,
            settings.MYSQL_PORT,
            str(e)
        )
        return False


def get_db() -> Generator[Optional[Session], None, None]:
    """
    FastAPI dependency that yields a database session or None if DB is unavailable.
    """
    if not settings.ENABLE_HISTORY:
        yield None
        return

    try:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            yield db
        finally:
            db.close()
    except Exception as e:
        logger.warning("Database session acquisition failed: %s", str(e))
        yield None
