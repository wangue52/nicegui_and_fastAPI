# db.py
import os
import logging
from datetime import datetime
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, BigInteger, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

logger = logging.getLogger(__name__)

# Database configuration
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secure_vault.db')
DB_URL = f"sqlite:///{DB_PATH}"

# Create engine and base
engine = create_engine(DB_URL)
Base = declarative_base()


# Define models
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    files = relationship("File", back_populates="user", cascade="all, delete-orphan")
    activities = relationship("Activity", back_populates="user", cascade="all, delete-orphan")


class File(Base):
    __tablename__ = 'files'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    filename = Column(String(255), nullable=False)
    path = Column(String(512), nullable=False)
    size = Column(BigInteger, nullable=False)
    is_encrypted = Column(Boolean, default=False)
    uploaded_at = Column(DateTime, default=datetime.now)
    encrypted_at = Column(DateTime, nullable=True)
    original_filename=Column(String(255), nullable=False)
    # Relationships
    user = relationship("User", back_populates="files")


class Activity(Base):
    __tablename__ = 'activities'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    activity_type = Column(String(50), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.now)
    
    # Relationships
    user = relationship("User", back_populates="activities")


# Session management
SessionLocal = sessionmaker(bind=engine)


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context manager for database sessions."""
    session = SessionLocal()
    try:
        yield session
    except Exception as e:
        session.rollback()
        logger.error(f"Database error: {str(e)}")
        raise
    finally:
        session.close()


def init_db() -> None:
    """Initialize the database."""
    try:
        Base.metadata.create_all(engine)
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise
