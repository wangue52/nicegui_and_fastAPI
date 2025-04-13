# SecureVault - Encrypted File Storage Application

A secure web application for encrypting and managing files with user authentication and encryption key management, built with Python and NiceGUI.

## Features

- **User Authentication**: Registration, login, password hashing with bcrypt
- **File Management**: Upload, download, encryption, and decryption
- **Encryption**: AES encryption using Fernet (from the cryptography library)
- **Key Management**: Generate, backup, and import encryption keys
- **User Dashboard**: View files and activity history
- **Security**: File size limits, filename sanitation, secure session management

## Project Structure

```
secure_vault/
├── main.py         # Main application entry point
├── auth.py         # Authentication module
├── crypto.py       # Cryptography module
├── db.py           # Database models and connections
├── utils