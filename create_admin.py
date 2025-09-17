import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = "wiki.db"
username = "admin"       # gewünschter Admin-Username
password = "admin123"    # gewünschtes Testpasswort
is_admin = 1             # 1 = Admin, 0 = normaler Benutzer

conn = sqlite3.connect(DB_NAME)
c = conn.cursor()

# Prüfen, ob Benutzer existiert
c.execute("SELECT id FROM users WHERE username=?", (username,))
if c.fetchone():
    print(f"Benutzer '{username}' existiert bereits.")
else:
    password_hash = generate_password_hash(password)
    c.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
        (username, password_hash, is_admin)
    )
    conn.commit()
    print(f"Admin-Benutzer '{username}' mit Passwort '{password}' wurde angelegt.")

conn.close()
