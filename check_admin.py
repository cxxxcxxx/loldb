# check_admin.py
import sqlite3
from werkzeug.security import check_password_hash

DB_NAME = "wiki.db"
USERNAME = "admin"
PASSWORD = "admin123"  # zum Testen

def get_user(username):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()
    return user

user = get_user(USERNAME)

if not user:
    print(f"Benutzer '{USERNAME}' existiert nicht in der DB.")
else:
    print(f"Benutzer '{USERNAME}' gefunden.")
    print(f"Password-Hash: {user['password_hash']}")
    if check_password_hash(user['password_hash'], PASSWORD):
        print("Passwort korrekt! Login sollte funktionieren.")
    else:
        print("Passwort falsch! Bitte checke den Hash oder das Passwort.")
