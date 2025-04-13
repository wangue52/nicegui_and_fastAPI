# main.py
import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any 
from functools import partial
from nicegui import ui, app
from nicegui.events import UploadEventArguments
from fastapi import Request, HTTPException,Query
from starlette.middleware.sessions import SessionMiddleware
import functools
# Import our modules
from db import init_db, User, File, Activity, get_db_session
from auth import (
    register_user, verify_user, get_current_user, hash_password,
    create_user_key, get_user_key, store_user_key, DEFAULT_ADMIN_EMAIL,
    DEFAULT_ADMIN_PASSWORD
)
from crypto import (
    encrypt_file, decrypt_file, generate_key, export_key,
    import_key, get_key_info
)
from utils import (
    sanitize_filename, get_file_size_str, allowed_file,
    create_user_folder, get_user_folder, MAX_UPLOAD_SIZE,get_file_extension,
    UPLOAD_FOLDER, TEMP_FOLDER  # Importer depuis utils
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# App configuration
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(TEMP_FOLDER, exist_ok=True)

# Initialize appCL
app.session_secret = os.environ.get('SESSION_SECRET', str(uuid.uuid4()))
app.add_static_files('/uploads', UPLOAD_FOLDER)

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key=app.session_secret)

# Initialize the database
init_db()

# Create admin user if doesn't exist
with get_db_session() as session:
    admin = session.query(User).filter(User.email == DEFAULT_ADMIN_EMAIL).first()
    if not admin:
        register_user(DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD, is_admin=True)
        logger.info(f"Admin user created: {DEFAULT_ADMIN_EMAIL}")


# Authentication decorator
# Dans main.py
def require_auth(func):
    @functools.wraps(func)
    async def wrapper(request: Request):
        user = get_current_user()
        if not user or not user.id:
            app.storage.user.clear()
            ui.notify('Session expired', color='negative')
            return ui.navigate.to('/login')
        return await func(request)
    return wrapper

# Custom error handler
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    ui.notify(f"Error: {exc.detail}", color='negative')
    return {"error": exc.detail}


# Log activity
def log_activity(activity_type: str, details: str):
    user = get_current_user()
    if user:
        with get_db_session() as session:
            activity = Activity(
                user_id=user.id,
                activity_type=activity_type,
                details=details,
                timestamp=datetime.now()
            )
            session.add(activity)
            session.commit()
            logger.info(f"Activity logged: {user.email} - {activity_type} - {details}")


# Login page
@ui.page('/')
@ui.page('/login')
def login_page():
    ui.page_title('SecureVault - Login')
    
    with ui.card().classes('max-w-md mx-auto mt-12'):
        ui.label('SecureVault').classes('text-2xl text-center')
        ui.label('Secure File Encryption').classes('text-center mb-4')
        
        email = ui.input('Email').classes('w-full')
        password = ui.input('Password', password=True).classes('w-full')
        
        with ui.row().classes('justify-between w-full'):
            ui.button('Login', on_click=lambda: perform_login(email.value, password.value))
            ui.button('Register', on_click=lambda: ui.navigate.to('/register'))
            
    # Check if user is already logged in
    user = get_current_user()
    if user:
        ui.navigate.to('/dashboard')


def perform_login(email: str, password: str):
    try:
        if not email or not password:
            ui.notify('Email and password are required', color='negative')
            return
        
        user = verify_user(email, password)
        if user:
            # Set user in session
            app.storage.user['id'] = user.id
            
            # Check if user has encryption key
            has_key = get_user_key(user.id)
            
            # Log activity
            log_activity('login', f'User logged in from {ui.context.client.ip}')
            
            # Redirect based on key status
            if not has_key:
                ui.navigate.to('/generate-key')
            else:
                ui.navigate.to('/dashboard')
        else:
            ui.notify('Invalid email or password', color='negative')
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        ui.notify(f'Login error: {str(e)}', color='negative')


# Register page
@ui.page('/register')
def register_page():
    ui.page_title('SecureVault - Register')
    
    with ui.card().classes('max-w-md mx-auto mt-12'):
        ui.label('Create an Account').classes('text-2xl text-center')
        
        email = ui.input('Email').classes('w-full')
        password = ui.input('Password', password=True).classes('w-full')
        confirm_password = ui.input('Confirm Password', password=True).classes('w-full')
        
        with ui.row().classes('justify-between w-full'):
            ui.button('Register', on_click=lambda: perform_register(
                email.value, password.value, confirm_password.value))
            ui.button('Back to Login', on_click=lambda: ui.navigate.to('/login'))


def perform_register(email: str, password: str, confirm_password: str):
    try:
        if password != confirm_password:
            ui.notify('Passwords do not match', color='negative')
            return
            
        if len(password) < 8:
            ui.notify('Password must be at least 8 characters', color='negative')
            return
            
        user_id = register_user(email, password)
        if user_id:
            # Create user folder
            create_user_folder(user_id)
            
            # Log activity (you might need to adjust this)
            with get_db_session() as session:
                activity = Activity(
                    user_id=user_id,
                    activity_type='register',
                    details=f'New user registered from {ui.client.ip}',
                    timestamp=datetime.now()
                )
                session.add(activity)
                session.commit()
            
            ui.notify('Registration successful! Please log in.', color='positive')
            ui.navigate.to('/login')
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        ui.notify(f'Registration error: {str(e)}', color='negative')

# Key generation page
@ui.page('/generate-key')
@require_auth
async def generate_key_page(request: Request):
    user = get_current_user()
    ui.page_title('SecureVault - Generate Key')
    
    with ui.card().classes('max-w-md mx-auto mt-12'):
        ui.label('Generate Encryption Key').classes('text-2xl text-center')
        ui.label('You need to create an encryption key before using the system.').classes('text-center mb-4')
        
        password_input = ui.input('Password for Key Protection', password=True).classes('w-full')
        confirm_input = ui.input('Confirm Password', password=True).classes('w-full')
        ui.label('Important: This password protects your encryption key. If you lose it, you won\'t be able to decrypt your files.')
        ui.label('We recommend using a password manager and storing this separately from your login password.')
        
        ui.button('Generate Key', on_click=lambda: perform_key_generation(
           user.id, 
           password_input.value, 
           confirm_input.value
        )).classes('mt-4')


def perform_key_generation(user_id: int, password: str, confirm_password: str):
    try:
        if not password or not confirm_password:
            ui.notify('Both password fields are required', color='negative')
            return

        if password != confirm_password:
            ui.notify('Passwords do not match', color='negative')
            return

        if len(password) < 12:
            ui.notify('Password must be at least 12 characters', color='warning')

        # Génération de la clé
        key = generate_key()
        
        # Stockage avec vérification
        if store_user_key(user_id, key, password):
            ui.notify('Key generated successfully!', color='positive')
            ui.navigate.to('/key-backup')
        else:
            ui.notify('Failed to store encryption key', color='negative')

    except Exception as e:
        logger.error(f"Key generation error: {str(e)}")
        ui.notify(f'Critical error: {str(e)}', color='negative')


# Key backup page
@ui.page('/key-backup')
@require_auth
async def key_backup_page(request: Request):
    user = get_current_user()
    ui.page_title('SecureVault - Backup Key')
    
    with ui.card().classes('max-w-md mx-auto mt-12'):
        ui.label('Backup Your Encryption Key').classes('text-2xl text-center')
        ui.label('This is critical for recovering your encrypted files if you lose access to your account.').classes('text-center mb-4')
        
        password = ui.input('Enter Key Password', password=True).classes('w-full')
        
        ui.button('Download Key Backup', on_click=lambda: download_key_backup(user.id, password.value)).classes('mt-4')
        ui.button('Skip (Not Recommended)', on_click=lambda: ui.navigate.to('/dashboard')).classes('mt-2')
        
        ui.label('WARNING: If you skip this step and lose your key, your encrypted files will be PERMANENTLY inaccessible.')


def download_key_backup(user_id: int, password: str):
    try:
        # Export the key
        key_data = export_key(user_id, password)
        
        if not key_data:
            ui.notify('Invalid password or key not found', color='negative')
            return
            
        # Create a temp file for download
        temp_file = os.path.join(TEMP_FOLDER, f'key_backup_{user_id}_{uuid.uuid4()}.key')
        with open(temp_file, 'wb') as f:
            f.write(key_data)
            
        # Set up download
        ui.download(temp_file, filename=f'secureVault_key_backup_{datetime.now().strftime("%Y%m%d")}.key')
        
        # Log activity
        log_activity('key_backup', 'Encryption key backup downloaded')
        
        # Schedule file deletion
        def delete_temp_file():
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                logger.error(f"Error deleting temp file: {str(e)}")
                
        ui.timer(10, delete_temp_file, once=True)
        
        ui.notify('Key backup ready for download', color='positive')
        ui.navigate.to('/dashboard')
    except Exception as e:
        logger.error(f"Key backup error: {str(e)}")
        ui.notify(f'Key backup error: {str(e)}', color='negative')

# Dashboard page
@ui.page('/dashboard')
@require_auth
async def dashboard_page(request: Request):
    user = get_current_user()
    ui.page_title('SecureVault - Dashboard')
    
    # Create the layout
    with ui.header().classes('bg-primary text-white'):
        with ui.row().classes('w-full items-center justify-between'):
            ui.label('SecureVault').classes('text-xl')
            with ui.row():
                ui.button('Dashboard', on_click=lambda: ui.navigate.to('/dashboard')).classes('text-white')
                ui.button('Files', on_click=lambda: ui.navigate.to('/files')).classes('text-white')
                ui.button('Settings', on_click=lambda: ui.navigate.to('/settings')).classes('text-white')
                ui.button('Logout', on_click=logout).classes('text-white')
    
    # Main content
    with ui.column().classes('w-full max-w-6xl mx-auto p-4'):
        ui.label(f'Welcome, {user.email}').classes('text-2xl')
        
        # Stats cards
        with ui.row().classes('w-full gap-4 mt-4'):
            with get_db_session() as session:
                total_files = session.query(File).filter(File.user_id == user.id).count()
                encrypted_files = session.query(File).filter(File.user_id == user.id, File.is_encrypted == True).count()
                recent_activities = session.query(Activity).filter(Activity.user_id == user.id).order_by(Activity.timestamp.desc()).limit(5).all()
            
            # Cards
            stats = [
                ('Total Files', total_files),
                ('Encrypted Files', encrypted_files),
                ('Decrypted Files', total_files - encrypted_files)
            ]
            
            for title, value in stats:
                with ui.card().classes('w-1/3'):
                    ui.label(title).classes('text-lg')
                    ui.label(str(value)).classes('text-3xl')
                
        # Recent activity
        with ui.card().classes('w-full mt-4'):
            ui.label('Recent Activity').classes('text-xl mb-2')
            
            if recent_activities:
                # Préparer les données pour la table
                columns = [
                    {'name': 'Time', 'label': 'Time', 'field': 'time'},
                    {'name': 'Activity', 'label': 'Activity', 'field': 'activity'},
                    {'name': 'Details', 'label': 'Details', 'field': 'details'}
                ]
                
                rows = [
                    {
                        'time': activity.timestamp.strftime('%Y-%m-%d %H:%M'),
                        'activity': activity.activity_type,
                        'details': activity.details
                    }
                    for activity in recent_activities
                ]
                
                # Nouvelle syntaxe de table
                
                with ui.element('div').classes('w-full').style('max-height: 300px; overflow: auto'):
                     ui.table(
                        columns=columns,
                        rows=rows,
                        row_key='time',
                            # Ajouter le style natif si nécessaire
                        pagination={'rowsPerPage': 5},
                        on_select=lambda e: ui.notify(f"Selected row: {e.args}")
                        )
            else:
                ui.label('No recent activity').classes('text-gray-500')
        
        # Quick actions
        with ui.card().classes('w-full mt-4'):
            ui.label('Quick Actions').classes('text-xl mb-2')
            with ui.row().classes('gap-2'):
                ui.button('Upload Files', icon='upload', on_click=lambda: ui.navigate.to('/files')).classes('primary')
                ui.button('Backup Key', icon='security', on_click=lambda: ui.navigate.to('/key-backup')).classes('secondary')
                ui.button('Settings', icon='settings', on_click=lambda: ui.navigate.to('/settings')).classes('secondary')
# Files page





@ui.page('/files')
@require_auth
async def files_page(request: Request):
    user = get_current_user()
    ui.page_title('SecureVault - Files')

    # Header amélioré
    with ui.header().classes('bg-primary text-white shadow-lg'):
        with ui.row().classes('w-full items-center justify-between p-4'):
            ui.label('SecureVault').classes('text-2xl font-bold')
            with ui.row().classes('gap-4'):
                nav_buttons = [
                    ('Dashboard', '/dashboard', 'primary-dark'),
                    ('Files', '/files', 'secondary'),
                    ('Settings', '/settings', 'primary-dark'),
                    ('Logout', None, 'red-600')
                ]
                for text, target, color in nav_buttons:
                    ui.button(text, 
                              on_click=lambda t=target: ui.navigate.to(t) if t else logout(),
                              color=color).classes('px-4 py-2 rounded-lg')

    with ui.column().classes('w-full max-w-6xl mx-auto p-6 space-y-6'):
        # Section titre et bouton refresh
        with ui.row().classes('items-center justify-between'):
            ui.label('File Manager').classes('text-3xl font-bold text-gray-800')
            refresh_button = ui.button('Refresh', icon='refresh', color='blue').classes('px-4 py-2')

        # Section Upload
        with ui.card().classes('w-full shadow-md border-l-4 border-blue-500'):
            ui.label('Upload Files').classes('text-xl font-bold text-blue-800 p-4 bg-blue-50')
            with ui.card_section().classes('p-6'):
                file_upload = ui.upload(
                    label='Drop files here or click to upload',
                    max_file_size=MAX_UPLOAD_SIZE,
                    auto_upload=True,
                    on_upload=lambda e: handle_file_upload(e, user.id)
                ).classes('w-full border-2 border-dashed border-blue-300 rounded-lg p-4')
                ui.label(f'Maximum file size: {get_file_size_str(MAX_UPLOAD_SIZE)}').classes('text-gray-600 mt-2')

        # Section Table - Version corrigée
        with ui.card().classes('w-full shadow-md border-l-4 border-green-500'):
            ui.label('Your Files').classes('text-xl font-bold text-green-800 p-4 bg-green-50')
            with ui.card_section().classes('p-6'):
                # Filtres et recherche
                with ui.row().classes('w-full gap-4 mb-4'):
                    file_filter = ui.select(
                        ['All Files', 'Encrypted', 'Decrypted'],
                        value='All Files',
                        label='Filter'
                    ).classes('w-1/3')
                    search_input = ui.input(label='Search files').classes('w-2/3')

                # Configuration de la table
                columns = [
                    {'name': 'filename', 'label': 'Filename', 'field': 'filename', 'sortable': True, 'align': 'left'},
                    {'name': 'size', 'label': 'Size', 'field': 'size', 'align': 'left'},
                    {'name': 'status', 'label': 'Status', 'field': 'status', 'align': 'center'},
                    {'name': 'uploaded', 'label': 'Uploaded', 'field': 'uploaded', 'sortable': True, 'align': 'left'},
                    {'name': 'actions', 'label': 'Actions', 'field': 'actions', 'align': 'center'}
                ]

                table = ui.table(columns=columns, rows=[]).classes('w-full')

                # Définir le template pour les boutons d'action
                table.add_slot('body-cell-actions', r'''
                    <q-td :props="props">
                        <q-btn-group flat>
                            <q-btn 
                                icon="download" 
                                size="sm" 
                                color="primary"
                                @click="() => $parent.$emit('download', props.row.id)"
                            />
                            <q-btn 
                                v-if="props.row.status === 'Encrypted'"
                                icon="lock_open" 
                                size="sm" 
                                color="warning"
                                @click="() => $parent.$emit('decrypt', props.row.id)"
                            />
                            <q-btn 
                                v-else
                                icon="lock" 
                                size="sm" 
                                color="positive"
                                @click="() => $parent.$emit('encrypt', props.row.id)"
                            />
                            <q-btn 
                                icon="delete" 
                                size="sm" 
                                color="negative"
                                @click="() => $parent.$emit('delete', props.row.id)"
                            />
                        </q-btn-group>
                    </q-td>
                ''')

        # Gestion des événements de la table
        async def handle_table_event(event_type, event_args):
            file_id = event_args.args  # Extraire l'ID du fichier depuis les arguments de l'événement
            if event_type == 'download':
                await download_file(file_id, user.id)
            elif event_type == 'encrypt':
                await encrypt_user_file(file_id, user.id)
            elif event_type == 'decrypt':
                await decrypt_user_file(file_id, user.id)
            elif event_type == 'delete':
                await delete_file(file_id, user.id)

        table.on('download', partial(handle_table_event, 'download'))
        table.on('encrypt', partial(handle_table_event, 'encrypt'))
        table.on('decrypt', partial(handle_table_event, 'decrypt'))
        table.on('delete', partial(handle_table_event, 'delete'))

        # Fonction de rafraîchissement améliorée
        async def refresh_file_table():
            with get_db_session() as session:
                query = session.query(File).filter(File.user_id == user.id)

                if file_filter.value == 'Encrypted':
                    query = query.filter(File.is_encrypted == True)
                elif file_filter.value == 'Decrypted':
                    query = query.filter(File.is_encrypted == False)

                if search_input.value:
                    query = query.filter(File.filename.contains(search_input.value))

                files = query.order_by(File.uploaded_at.desc()).all()

                table.rows = [{
                    'id': file.id,
                    'filename': file.filename,
                    'size': get_file_size_str(file.size),
                    'status': 'Encrypted' if file.is_encrypted else 'Decrypted',
                    'uploaded': file.uploaded_at.strftime('%Y-%m-%d %H:%M'),
                } for file in files]

                if not files:
                    ui.notify("No files found", color='info', timeout=2000)
                else:
                    ui.notify(f"Loaded {len(files)} files", color='positive', timeout=1000)

        # Configuration des événements
        file_filter.on('change', refresh_file_table)
        search_input.on('change', refresh_file_table)
        refresh_button.on('click', refresh_file_table)

        # Chargement initial
        await refresh_file_table()
# Dans main.py
def handle_file_upload(e: UploadEventArguments, user_id: int):
    try:
        logger.info("=== DÉBUT TRAITEMENT UPLOAD ===")
        success_count = 0
        error_messages = []
        
        # Vérifier si e.content est une liste ou un seul fichier
        files_to_process = e.files if hasattr(e, 'files') else ([e.content] if not isinstance(e.content, list) else e.content)
        
        for file_data in files_to_process:
            temp_path = None
            try:
                logger.info(f"Traitement du fichier - Type: {type(file_data)}")
                
                # Initialisation des variables
                content = None
                original_filename = None
                
                # Gestion différente selon le type de fichier
                if hasattr(file_data, 'name') and hasattr(file_data, 'read'):  # Cas SpooledTemporaryFile
                    file_data.seek(0)
                    content = file_data.read()
                    original_filename = getattr(file_data, 'name', None)
                
                # Si aucun nom de fichier n'est trouvé, générer un nom par défaut
                if not original_filename:
                    original_filename = f"file_{uuid.uuid4().hex[:6]}"
                    logger.warning(f"Nom de fichier généré: {original_filename}")
                
                logger.info(f"Fichier extrait - Nom original: {original_filename}, Taille: {len(content) if content else 0} bytes")
                
                # Validation du contenu
                if not content:
                    msg = "Fichier vide détecté"
                    logger.warning(msg)
                    error_messages.append(msg)
                    continue

                # Extraction de l'extension (même si le nom est généré)
                base, ext = os.path.splitext(original_filename)
                if not ext:  # Si pas d'extension, essayer de la deviner
                    try:
                        import filetype
                        kind = filetype.guess(content)
                        if kind:
                            ext = f".{kind.extension}"
                    except ImportError:
                        pass
                
                # Nettoyage du nom de base
                clean_base = sanitize_filename(base) if base else f"file_{uuid.uuid4().hex[:6]}"
                clean_name = f"{clean_base}{ext}"
                
                # Vérification de la taille
                if len(content) > MAX_UPLOAD_SIZE:
                    msg = f"Fichier trop volumineux ({get_file_size_str(len(content))})"
                    logger.warning(msg)
                    error_messages.append(msg)
                    continue

                # Création du dossier utilisateur
                user_dir = get_user_folder(user_id)
                os.makedirs(user_dir, exist_ok=True)
                logger.info(f"Dossier utilisateur vérifié: {user_dir}")

                # Écriture sécurisée du fichier
                temp_path = os.path.join(user_dir, f".tmp_{uuid.uuid4()}")
                final_path = os.path.join(user_dir, clean_name)
                
                with open(temp_path, 'wb') as f:
                    f.write(content)
                
                os.replace(temp_path, final_path)
                logger.info(f"Fichier enregistré avec succès: {final_path}")

                # Enregistrement en base de données
                with get_db_session() as session:
                    new_file = File(
                        user_id=user_id,
                        filename=clean_name,
                        original_filename=original_filename,
                        path=final_path,
                        size=len(content),
                        is_encrypted=False,
                        uploaded_at=datetime.now()
                    )
                    session.add(new_file)
                    session.commit()
                    success_count += 1
                    logger.info(f"Enregistrement DB réussi pour: {clean_name}")

            except IOError as ioe:
                error_msg = f"Erreur disque: {str(ioe)}"
                logger.error(error_msg, exc_info=True)
                error_messages.append("Erreur système - stockage")
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)
            
            except Exception as ex:
                error_msg = f"Erreur traitement: {str(ex)}"
                logger.error(error_msg, exc_info=True)
                error_messages.append("Erreur traitement fichier")
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)

        # Notification finale
        logger.info(f"=== RÉSULTAT UPLOAD === Succès: {success_count}, Échecs: {len(error_messages)}")
        
        if success_count > 0:
            ui.notify(f"{success_count} fichier(s) sauvegardé(s) avec succès", color='positive')
        
        if error_messages:
            ui.notify("\n".join(error_messages[:3]), color='warning')

        # Journalisation d'activité
        log_activity('file_upload', f"Succès: {success_count} | Échecs: {len(error_messages)}")

    except Exception as ex:
        logger.critical("ERREUR GLOBALE UPLOAD", exc_info=True)
        ui.notify("Erreur critique du système d'upload", color='negative')
        raise
def debug_upload_structure(e: UploadEventArguments):
    """Analyser et journaliser la structure des données d'upload pour débogage"""
    logger.info("=== DÉBUT ANALYSE UPLOAD ===")
    
    # Information générale
    logger.info(f"Type de l'événement: {type(e)}")
    
    # Examiner e.content
    if hasattr(e, 'content'):
        logger.info(f"Type de e.content: {type(e.content)}")
        if isinstance(e.content, list):
            logger.info(f"Longueur de e.content: {len(e.content)}")
            # Analyser le premier élément s'il existe
            if e.content:
                first_item = e.content[0]
                logger.info(f"Type du premier élément: {type(first_item)}")
                # Lister les attributs/méthodes
                if hasattr(first_item, '__dict__'):
                    logger.info(f"Attributs: {dir(first_item)}")
                # Si c'est un dict
                if isinstance(first_item, dict):
                    logger.info(f"Clés disponibles: {first_item.keys()}")
    else:
        logger.warning("e.content n'existe pas!")
    
    # Examiner d'autres attributs possibles
    for attr in ['args', 'handler', 'data', 'files']:
        if hasattr(e, attr):
            logger.info(f"e.{attr} existe, type: {type(getattr(e, attr))}")
            
    logger.info("=== FIN ANALYSE UPLOAD ===")


def download_file(file_id: int, user_id: int):
    try:
        with get_db_session() as session:
            file = session.query(File).filter(File.id == file_id, File.user_id == user_id).first()
            
            if not file:
                ui.notify('File not found', color='negative')
                return
                
            if not os.path.exists(file.path):
                ui.notify('File not found on disk', color='negative')
                
                # Remove from database
                session.delete(file)
                session.commit()
                return
                
            # Create activity log
            activity = Activity(
                user_id=user_id,
                activity_type='file_download',
                details=f'File downloaded: {file.filename}',
                timestamp=datetime.now()
            )
            session.add(activity)
            session.commit()
            
            # Initiate download
            ui.download(file.path, filename=file.filename)
            ui.notify(f'Downloading {file.filename}', color='positive')
    except Exception as e:
        logger.error(f"File download error: {str(e)}")
        ui.notify(f'File download error: {str(e)}', color='negative')


def encrypt_user_file(file_id: int, user_id: int):
    # Show password dialog
    with ui.dialog() as dialog, ui.card().classes('p-4'):
        ui.label('Enter Key Password').classes('text-xl')
        password = ui.input('Password', password=True).classes('w-full')
        
        with ui.row().classes('w-full justify-end gap-2 mt-4'):
            ui.button('Cancel', on_click=dialog.close)
            ui.button('Encrypt', on_click=lambda: process_encryption(file_id, user_id, password.value, dialog))
    
    dialog.open()


def process_encryption(file_id: int, user_id: int, password: str, dialog):
    try:
        dialog.close()
        
        with get_db_session() as session:
            file = session.query(File).filter(File.id == file_id, File.user_id == user_id).first()
            
            if not file:
                ui.notify('File not found', color='negative')
                return
                
            if file.is_encrypted:
                ui.notify('File is already encrypted', color='warning')
                return
                
            # Encrypt the file
            success = encrypt_file(file.path, user_id, password)
            
            if success:
                # Update database
                file.is_encrypted = True
                file.encrypted_at = datetime.now()
                
                # Log activity
                activity = Activity(
                    user_id=user_id,
                    activity_type='file_encrypt',
                    details=f'File encrypted: {file.filename}',
                    timestamp=datetime.now()
                )
                session.add(activity)
                session.commit()
                
                ui.notify(f'File {file.filename} encrypted successfully', color='positive')
                ui.navigate.to('/files')
            else:
                ui.notify('Failed to encrypt file. Check your password.', color='negative')
    except Exception as e:
        logger.error(f"File encryption error: {str(e)}")
        ui.notify(f'File encryption error: {str(e)}', color='negative')


def decrypt_user_file(file_id: int, user_id: int):
    # Show password dialog
    with ui.dialog() as dialog, ui.card().classes('p-4'):
        ui.label('Enter Key Password').classes('text-xl')
        password = ui.input('Password', password=True).classes('w-full')
        
        with ui.row().classes('w-full justify-end gap-2 mt-4'):
            ui.button('Cancel', on_click=dialog.close)
            ui.button('Decrypt', on_click=lambda: process_decryption(file_id, user_id, password.value, dialog))
    
    dialog.open()


def process_decryption(file_id: int, user_id: int, password: str, dialog):
    try:
        dialog.close()
        
        with get_db_session() as session:
            file = session.query(File).filter(File.id == file_id, File.user_id == user_id).first()
            
            if not file:
                ui.notify('File not found', color='negative')
                return
                
            if not file.is_encrypted:
                ui.notify('File is not encrypted', color='warning')
                return
                
            # Decrypt the file
            success = decrypt_file(file.path, user_id, password)
            
            if success:
                # Update database
                file.is_encrypted = False
                
                # Log activity
                activity = Activity(
                    user_id=user_id,
                    activity_type='file_decrypt',
                    details=f'File decrypted: {file.filename}',
                    timestamp=datetime.now()
                )
                session.add(activity)
                session.commit()
                
                ui.notify(f'File {file.filename} decrypted successfully', color='positive')
                ui.navigate.to('/files')
            else:
                ui.notify('Failed to decrypt file. Check your password.', color='negative')
    except Exception as e:
        logger.error(f"File decryption error: {str(e)}")
        ui.notify(f'File decryption error: {str(e)}', color='negative')


def delete_file(file_id: int, user_id: int):
    # Show confirmation dialog
    with ui.dialog() as dialog, ui.card().classes('p-4'):
        ui.label('Confirm Deletion').classes('text-xl')
        ui.label('Are you sure you want to delete this file? This action cannot be undone.')
        
        with ui.row().classes('w-full justify-end gap-2 mt-4'):
            ui.button('Cancel', on_click=dialog.close)
            ui.button('Delete', on_click=lambda: process_deletion(file_id, user_id, dialog)).classes('bg-red-500 text-white')
    
    dialog.open()


def process_deletion(file_id: int, user_id: int, dialog):
    try:
        dialog.close()
        
        with get_db_session() as session:
            file = session.query(File).filter(File.id == file_id, File.user_id == user_id).first()
            
            if not file:
                ui.notify('File not found', color='negative')
                return
                
            # Delete file from disk
            if os.path.exists(file.path):
                os.remove(file.path)
                
            # Log activity
            activity = Activity(
                user_id=user_id,
                activity_type='file_delete',
                details=f'File deleted: {file.filename}',
                timestamp=datetime.now()
            )
            session.add(activity)
            
            # Delete from database
            session.delete(file)
            session.commit()
            
            ui.notify(f'File {file.filename} deleted successfully', color='positive')
            ui.navigate.to('/files')
    except Exception as e:
        logger.error(f"File deletion error: {str(e)}")
        ui.notify(f'File deletion error: {str(e)}', color='negative')


# Settings page
@ui.page('/settings')
@require_auth
async def settings_page(request: Request):
    user = get_current_user()
    ui.page_title('SecureVault - Settings')  # Corrigé le titre de la page
    
    # Create the layout
    with ui.header().classes('bg-primary text-white'):
        with ui.row().classes('w-full items-center justify-between'):
            ui.label('SecureVault').classes('text-xl')
            with ui.row():
                ui.button('Dashboard', on_click=lambda: ui.navigate.to('/dashboard')).classes('text-white')
                ui.button('Files', on_click=lambda: ui.navigate.to('/files')).classes('text-white')
                ui.button('Settings', on_click=lambda: ui.navigate.to('/settings')).classes('text-white')
                ui.button('Logout', on_click=logout).classes('text-white')
    
    # Main content
    with ui.column().classes('w-full max-w-6xl mx-auto p-4'):
        ui.label('Account Settings').classes('text-2xl')
        
        # Account section
        with ui.card().classes('w-full mt-4'):
            ui.label('Account Information').classes('text-xl mb-2')
            
            with ui.row().classes('w-full'):
                ui.label(f'Email: {user.email}')
            
            with ui.row().classes('w-full'):
                ui.label(f'Account created: {user.created_at.strftime("%Y-%m-%d")}')
            
            ui.button('Change Password', on_click=lambda: change_password_dialog(user.id)).classes('mt-2')
        
        # Key management section
        with ui.card().classes('w-full mt-4'):
            ui.label('Encryption Key Management').classes('text-xl mb-2')
            
            # Get key info
            key_info = get_key_info(user.id)
            
            if key_info:
                ui.label(f'Key created: {key_info["created_at"].strftime("%Y-%m-%d %H:%M")}')
                ui.label(f'Key last used: {key_info["last_used"].strftime("%Y-%m-%d %H:%M") if key_info["last_used"] else "Never"}')
                
                with ui.row().classes('gap-2 mt-2'):
                    ui.button('Backup Key', on_click=lambda: ui.navigate.to('/key-backup')).classes('primary')
                    ui.button('Import New Key', on_click=import_key_dialog).classes('secondary')
            else:
                ui.label('No encryption key found').classes('text-red-500')
                ui.button('Generate New Key', on_click=lambda: ui.navigate.to('/generate-key')).classes('mt-2 primary')
        
        # Activity Log section - VERSION CORRIGÉE
        with ui.card().classes('w-full mt-4'):
            ui.label('Activity Log').classes('text-xl mb-2')
            
            with get_db_session() as session:
                activities = session.query(Activity).filter(Activity.user_id == user.id).order_by(Activity.timestamp.desc()).limit(100).all()
                
                if activities:
                    # Préparer les données pour la table
                    columns = [
                        {'name': 'time', 'label': 'Time', 'field': 'time', 'sortable': True},
                        {'name': 'activity', 'label': 'Activity', 'field': 'activity', 'sortable': True},
                        {'name': 'details', 'label': 'Details', 'field': 'details'}
                    ]
                    
                    rows = [
                        {
                            'time': activity.timestamp.strftime('%Y-%m-%d %H:%M'),
                            'activity': activity.activity_type,
                            'details': activity.details
                        }
                        for activity in activities
                    ]
                    
                    # Créer la table avec colonnes et données
                    ui.table(
                        columns=columns,
                        rows=rows,
                        row_key='time',
                        pagination={'rowsPerPage': 10}
                    ).classes('w-full').style('max-height: 400px')
                else:
                    ui.label('No activity recorded').classes('text-gray-500')
def change_password_dialog(user_id: int):
    with ui.dialog() as dialog, ui.card().classes('p-4'):
        ui.label('Change Password').classes('text-xl')
        
        current_password = ui.input('Current Password', password=True).classes('w-full')
        new_password = ui.input('New Password', password=True).classes('w-full')
        confirm_password = ui.input('Confirm New Password', password=True).classes('w-full')
        
        with ui.row().classes('w-full justify-end gap-2 mt-4'):
            ui.button('Cancel', on_click=dialog.close)
            ui.button('Change Password', on_click=lambda: process_password_change(
                user_id, current_password.value, new_password.value, confirm_password.value, dialog))
    
    dialog.open()


def process_password_change(user_id: int, current_password: str, new_password: str, confirm_password: str, dialog):
    try:
        dialog.close()
        
        if not current_password or not new_password:
            ui.notify('All fields are required', color='negative')
            return
            
        if new_password != confirm_password:
            ui.notify('New passwords do not match', color='negative')
            return
            
        if len(new_password) < 8:
            ui.notify('Password must be at least 8 characters', color='negative')
            return
            
        with get_db_session() as session:
            user = session.query(User).filter(User.id == user_id).first()
            
            if not user:
                ui.notify('User not found', color='negative')
                return
                
            # Verify current password
            from passlib.hash import bcrypt
            if not bcrypt.verify(current_password, user.password_hash):
                ui.notify('Current password is incorrect', color='negative')
                return
                
            # Update password
            user.password_hash = hash_password(new_password)
            
            # Log activity
            activity = Activity(
                user_id=user_id,
                activity_type='password_change',
                details='Password changed',
                timestamp=datetime.now()
            )
            session.add(activity)
            session.commit()
            
            ui.notify('Password changed successfully', color='positive')
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        ui.notify(f'Password change error: {str(e)}', color='negative')


def import_key_dialog():
    with ui.dialog() as dialog, ui.card().classes('p-4'):
        ui.label('Import Encryption Key').classes('text-xl')
        ui.label('This will replace your current encryption key. Make sure you have decrypted all files first.')
        
        new_key_password = ui.input('New Key Password', password=True).classes('w-full')
        key_upload = ui.upload(label='Upload Key File', auto_upload=True).classes('w-full')
        
        with ui.row().classes('w-full justify-end gap-2 mt-4'):
            ui.button('Cancel', on_click=dialog.close)
            ui.button('Import Key', on_click=lambda: process_key_import(
                key_upload,  # Passer l'objet upload directement
                new_key_password.value,
                dialog
            ))
    
    dialog.open()


def process_key_import(key_upload, password: str, dialog):
    try:
        dialog.close()
        
        if not password:
            ui.notify('Password is required', color='negative')
            return
        
        user = get_current_user()
        
        # Vérifier qu'un fichier a été uploadé
        if not key_upload.files:
            ui.notify('Please upload a key file', color='negative')
            return
        
        # Obtenir le premier fichier uploadé
        key_file = key_upload.files[0]
        
        # Lire le contenu du fichier
        key_data = key_file.content
        
        # Importer la clé
        success = import_key(user.id, key_data, password)
        
        if success:
            # Journaliser l'activité
            with get_db_session() as session:
                activity = Activity(
                    user_id=user.id,
                    activity_type='key_import',
                    details='New encryption key imported',
                    timestamp=datetime.now()
                )
                session.add(activity)
                session.commit()
                
            ui.notify('Encryption key imported successfully', color='positive')
            ui.navigate.to('/settings')
        else:
            ui.notify('Failed to import key. Check the key file and password.', color='negative')
            
    except Exception as e:
        logger.error(f"Key import error: {str(e)}", exc_info=True)
        ui.notify(f'Key import error: {str(e)}', color='negative')


def logout():
    app.storage.user.clear()
    ui.notify('Logged out successfully', color='positive')
    ui.navigate.to('/login')


# Run the app
ui.run(port=8080, title='SecureVault')
