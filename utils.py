# utils.py
import os
import re
import logging
from typing import Set, Union
import uuid

logger = logging.getLogger(__name__)

# Définir les constantes ici
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
TEMP_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp')
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'odt', 'rtf', 'md',
    'xls', 'xlsx', 'csv', 'ods', 'ppt', 'pptx', 'odp',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp',
    'zip', 'tar', 'gz', '7z', 'rar', 'json', 'xml',
    'yaml', 'yml', 'py', 'js', 'html', 'css', 'java',
    'c', 'cpp', 'cs', 'php', 'rb', 'go'
}

def sanitize_filename(filename: str) -> str:
    """Nettoie le nom de fichier tout en conservant l'extension"""
    if not filename:
        return ""
    
    # Séparer le nom et l'extension
    base, ext = os.path.splitext(filename)
    
    # Nettoyer le nom de base
    base = "".join(c for c in base if c.isalnum() or c in (' ', '-', '_'))
    base = base.strip()
    
    # Si le nom est vide après nettoyage, générer un UUID
    if not base:
        base = f"file_{uuid.uuid4().hex[:6]}"
    
    # Recombiner avec l'extension
    return f"{base}{ext}"

def get_user_folder(user_id: int) -> str:
    """Get the path to a user's folder."""
    user_folder = os.path.join(UPLOAD_FOLDER, f"user_{user_id}")
    os.makedirs(user_folder, exist_ok=True)
    return user_folder

def get_file_extension(filename: str) -> str:
    """Get the file extension from a filename."""
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else ''


def allowed_file(filename: str) -> bool:
    """Check if a file has an allowed extension."""
    return get_file_extension(filename) in ALLOWED_EXTENSIONS





def get_file_size_str(size_in_bytes: int) -> str:
    """Convert file size in bytes to a human-readable string."""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} bytes"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.1f} KB"
    elif size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_in_bytes / (1024 * 1024 * 1024):.1f} GB"


def create_user_folder(user_id: int) -> str:
    """Create a folder for a user's files."""
    user_folder = get_user_folder(user_id)
    os.makedirs(user_folder, exist_ok=True)
    return user_folder
