# crypto.py
import os
import base64
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Union, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken

from auth import get_user_key, update_key_usage

logger = logging.getLogger(__name__)

# Constants
SALT_SIZE = 16  # 128 bits
ITERATIONS = 100000  # PBKDF2 iterations


def generate_key() -> bytes:
    """Generate a new encryption key."""
    return Fernet.generate_key()


def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Derive a key from a password using PBKDF2."""
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_key(key: bytes, password: str) -> bytes:
    """Encrypt a key with a password."""
    password_key, salt = derive_key_from_password(password)
    fernet = Fernet(password_key)
    encrypted_key = fernet.encrypt(key)
    
    # Combine salt and encrypted key
    return salt + encrypted_key


def decrypt_key(encrypted_data: bytes, password: str) -> Optional[bytes]:
    """Decrypt a key with a password."""
    try:
        # Split salt and encrypted key
        salt = encrypted_data[:SALT_SIZE]
        encrypted_key = encrypted_data[SALT_SIZE:]
        
        # Derive key from password
        password_key, _ = derive_key_from_password(password, salt)
        
        # Decrypt
        fernet = Fernet(password_key)
        return fernet.decrypt(encrypted_key)
    except (InvalidToken, Exception) as e:
        logger.error(f"Decrypt key error: {str(e)}")
        return None


def encrypt_file(file_path: str, user_id: int, password: str) -> bool:
    """Encrypt a file using the user's key."""
    try:
        # Get the encrypted user key
        encrypted_key = get_user_key(user_id)
        if not encrypted_key:
            logger.error(f"No encryption key found for user {user_id}")
            return False
        
        # Decrypt the user key
        key = decrypt_key(encrypted_key, password)
        if not key:
            logger.error(f"Failed to decrypt key for user {user_id}")
            return False
        
        # Create fernet with key
        fernet = Fernet(key)
        
        # Read the file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Encrypt the data
        encrypted_data = fernet.encrypt(file_data)
        
        # Write the encrypted data back
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Update key usage
        update_key_usage(user_id)
        
        logger.info(f"File encrypted: {file_path}")
        return True
    except Exception as e:
        logger.error(f"File encryption error: {str(e)}")
        return False


def decrypt_file(file_path: str, user_id: int, password: str) -> bool:
    """Decrypt a file using the user's key."""
    try:
        # Get the encrypted user key
        encrypted_key = get_user_key(user_id)
        if not encrypted_key:
            logger.error(f"No encryption key found for user {user_id}")
            return False
        
        # Decrypt the user key
        key = decrypt_key(encrypted_key, password)
        if not key:
            logger.error(f"Failed to decrypt key for user {user_id}")
            return False
        
        # Create fernet with key
        fernet = Fernet(key)
        
        # Read the file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        try:
            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Write the decrypted data back
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Update key usage
            update_key_usage(user_id)
            
            logger.info(f"File decrypted: {file_path}")
            return True
        except InvalidToken:
            logger.error(f"Invalid token - file may not be encrypted with this key")
            return False
    except Exception as e:
        logger.error(f"File decryption error: {str(e)}")
        return False


def export_key(user_id: int, password: str) -> Optional[bytes]:
    """Export a user's key for backup."""
    try:
        # Get the encrypted user key
        encrypted_key = get_user_key(user_id)
        if not encrypted_key:
            logger.error(f"No encryption key found for user {user_id}")
            return None
        
        # Decrypt the user key to verify password
        key = decrypt_key(encrypted_key, password)
        if not key:
            logger.error(f"Failed to decrypt key for user {user_id}")
            return None
        
        # Re-encrypt with a marker to identify it as a backup
        backup_marker = b'SECVAULT_BACKUP_v1:'
        marked_key = backup_marker + key
        
        # Encrypt with password for security during transfer
        salt = os.urandom(SALT_SIZE)
        password_key, _ = derive_key_from_password(password, salt)
        fernet = Fernet(password_key)
        backup_data = fernet.encrypt(marked_key)
        
        # Combine salt and backup data
        export_data = salt + backup_data
        
        logger.info(f"Key exported for user {user_id}")
        return export_data
    except Exception as e:
        logger.error(f"Key export error: {str(e)}")
        return None


def import_key(user_id: int, key_data: bytes, password: str) -> bool:
    """Import a user's key from backup."""
    try:
        # Split salt and encrypted backup
        salt = key_data[:SALT_SIZE]
        backup_data = key_data[SALT_SIZE:]
        
        # Derive key from password
        password_key, _ = derive_key_from_password(password, salt)
        
        try:
            # Decrypt backup
            fernet = Fernet(password_key)
            decrypted_data = fernet.decrypt(backup_data)
            
            # Check for backup marker
            backup_marker = b'SECVAULT_BACKUP_v1:'
            if not decrypted_data.startswith(backup_marker):
                logger.error("Invalid backup format")
                return False
            
            # Extract key
            key = decrypted_data[len(backup_marker):]
            
            # Store key
            from auth import store_user_key
            if store_user_key(user_id, encrypt_key(key, password), password):
                logger.info(f"Key imported for user {user_id}")
                return True
            else:
                logger.error(f"Failed to store imported key for user {user_id}")
                return False
        except InvalidToken:
            logger.error("Invalid password or corrupt backup")
            return False
    except Exception as e:
        logger.error(f"Key import error: {str(e)}")
        return False


def get_key_info(user_id: int) -> Optional[Dict[str, Any]]:
    """Get information about a user's key."""
    try:
        metadata_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                     'keys', f"user_{user_id}.meta")
        
        if not os.path.exists(metadata_file):
            return None
        
        import json
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        # Convert string timestamps to datetime objects
        if metadata.get("created_at"):
            metadata["created_at"] = datetime.fromisoformat(metadata["created_at"])
        
        if metadata.get("last_used"):
            metadata["last_used"] = datetime.fromisoformat(metadata["last_used"])
        
        return metadata
    except Exception as e:
        logger.error(f"Get key info error: {str(e)}")
        return None
