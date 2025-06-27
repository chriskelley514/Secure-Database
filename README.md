# Secure-Database
Database with Security

Encrypted User Management System (Python)

This project is a secure user management application that stores user data encrypted in a SQLite database. It demonstrates the use of symmetric encryption (Fernet), data integrity verification, brute-force login protection, and a simple command-line interface.

Features:
- Stores user data (name, age, username, password) encrypted with Fernet symmetric encryption
- Protects data integrity using SHA-256 hashes
- Prevents duplicate usernames
- Provides secure login with brute-force protection (3 attempts, 30-second lockout)
- Supports returning to the main menu by typing 'back' during inputs
- Uses a local file "secret.key" to persist encryption key securely
- SQLite database "encrypted_database.db" stores encrypted records with integrity hashes

Technologies:
- Python 3.x
- cryptography library (Fernet symmetric encryption)
- SQLite3 for database storage
- hashlib for SHA-256 hashing

Usage:
1. Run the script to create the database and interact with the menu.
2. Choose from adding new users, logging in, or exiting.
3. When adding users, data is encrypted before saving.
4. During login, encrypted data is decrypted and integrity-verified before granting access.
5. Type 'back' at any prompt to return to the main menu.

Security Notes:
- The encryption key is generated once and stored in "secret.key". Protect this file.
- User data is encrypted and accompanied by a SHA-256 hash to detect tampering.
- Passwords are stored encrypted (no hashing), so consider adding hashing if needed.
- The brute-force protection locks login attempts for 30 seconds after 3 failed tries.

File Structure:
- The main script (this Python file)
- secret.key (auto-generated symmetric key file)
- encrypted_database.db (SQLite database file)

Requirements:
- Python 3.x
- cryptography library (`pip install cryptography`)

To run:
python your_script_name.py

makefile
Copy
Edit

License:
MIT License

Author:
Christopher Kelley
