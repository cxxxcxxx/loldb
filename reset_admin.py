import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = "wiki.db"
USERNAME = "admin"
NEW_PASSWORD = "admin123"

def reset_password(username, new_password):
    password_hash = generate_password_hash(new_password)
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash=? WHERE username=?", (password_hash, username))
    conn.commit()
    conn.close()
    print(f"Passwort für '{username}' wurde auf '{NEW_PASSWORD}' gesetzt.")

reset_password(USERNAME, NEW_PASSWORD)
