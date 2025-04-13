# auth.py
import os
import json
import uuid
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Union

from passlib.hash import bcrypt

from db import User, get_db_session

logger = logging.getLogger(__name__)

# Default admin credentials (should be changed in production)
DEFAULT_ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@secureapp.com')
DEFAULT_ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'AdminPassword123!')

# Session storage
SESSION_EXPIRY = 3600  # 1 hour in seconds

# Key storage location
KEY_STORAGE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')
os.makedirs(KEY_STORAGE_PATH, exist_ok=True)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash."""
    return bcrypt.verify(plain_password, hashed_password)


def register_user(email: str, password: str, is_admin: bool = False):
    try:
        # Check if user already exists
        with get_db_session() as session:
            existing_user = session.query(User).filter(User.email == email).first()
            if existing_user:
                raise ValueError("User with this email already exists")
        
            # Create new user
            hashed_password = hash_password(password)
            new_user = User(
                email=email,
                password_hash=hashed_password,
                is_admin=is_admin,
                created_at=datetime.now()
            )
            
            session.add(new_user)
            session.commit()
            
            # Important: Make a copy of the user ID before session closes
            user_id = new_user.id
            
        # Return just the user ID or fetch a fresh user object in a new session if needed
        with get_db_session() as session:
            user = session.query(User).filter(User.id == user_id).first()
            return user
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise


def verify_user(email: str, password: str) -> Optional[User]:
    """Verify user credentials and return user if valid."""
    try:
        with get_db_session() as session:
            user = session.query(User).filter(User.email == email).first()
            
            if not user:
                logger.warning(f"Login failed: User {email} not found")
                return None
            
            if not verify_password(password, user.password_hash):
                logger.warning(f"Login failed: Invalid password for {email}")
                return None
            
            logger.info(f"User {email} authenticated successfully")
            return user
    except Exception as e:
        logger.error(f"User authentication error: {str(e)}")
        raise


# Modifier la fonction get_current_user dans auth.py
def get_current_user() -> Optional[User]:
    from nicegui import app
    """Get the current logged-in user from session."""
    try:
        user_id = app.storage.user.get('id')  # Modification ici
        if not user_id:
            return None
        
        with get_db_session() as session:
            return session.query(User).filter(User.id == user_id).first()
    except Exception as e:
        logger.error(f"Get current user error: {str(e)}")
        return None
           

def create_user_key(user_id: int, key: bytes, password: str) -> bool:
    """Create a new encryption key for a user."""
    try:
        # Vérification préalable du mot de passe
        with get_db_session() as session:
            user = session.query(User).filter(User.id == user_id).first()
            if not user or not verify_password(password, user.password_hash):
                logger.error("Invalid credentials for key creation")
                return False
                
        return store_user_key(user_id, key, password)
        
    except Exception as e:
        logger.error(f"Create user key error: {str(e)}")
        return False


def store_user_key(user_id: int, key: bytes, password: str) -> bool:
    """Store a user's encryption key."""
    try:
        key_file = os.path.join(KEY_STORAGE_PATH, f"user_{user_id}.key")
        
        # Encrypt the key before storage
        from crypto import encrypt_key
        encrypted_key = encrypt_key(key, password)
        
        # Store key metadata
        metadata = {
            "user_id": user_id,
            "created_at": datetime.now().isoformat(),
            "last_used": None
        }
        
        # Write encrypted key to file
        with open(key_file, 'wb') as f:
            f.write(encrypted_key)
        
        # Write metadata
        metadata_file = os.path.join(KEY_STORAGE_PATH, f"user_{user_id}.meta")
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f)
        
        logger.info(f"Encryption key stored for user {user_id}")
        return True
        
    except Exception as e:
        logger.error(f"Store user key error: {str(e)}")
        return False


def get_user_key(user_id: int) -> Optional[bytes]:
    """Get a user's encryption key."""
    try:
        key_file = os.path.join(KEY_STORAGE_PATH, f"user_{user_id}.key")
        
        if not os.path.exists(key_file):
            logger.warning(f"No key found for user {user_id}")
            return None
        
        # Read key from file
        with open(key_file, 'rb') as f:
            key = f.read()
        
        # Update last used timestamp
        update_key_usage(user_id)
        
        return key
    except Exception as e:
        logger.error(f"Get user key error: {str(e)}")
        return None


def update_key_usage(user_id: int) -> None:
    """Update the last used timestamp for a key."""
    try:
        metadata_file = os.path.join(KEY_STORAGE_PATH, f"user_{user_id}.meta")
        
        if os.path.exists(metadata_file):
            # Read metadata
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Update last used
            metadata["last_used"] = datetime.now().isoformat()
            
            # Write back
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f)
    except Exception as e:
        logger.error(f"Update key usage error: {str(e)}")
