# =============================================================
# USER AUTHENTICATION — SQLite-backed profiles
# =============================================================

import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    ''')
    conn.commit()
    conn.close()


def create_user(username, password, display_name):
    username = username.strip().lower()
    if not username or not password or not display_name:
        return {"error": "All fields are required"}
    if len(password) < 6:
        return {"error": "Password must be at least 6 characters"}

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    if c.fetchone():
        conn.close()
        return {"error": "Username already taken"}

    password_hash = generate_password_hash(password)
    now = datetime.now().isoformat()
    c.execute(
        'INSERT INTO users (username, password_hash, display_name, created_at, last_login) VALUES (?, ?, ?, ?, ?)',
        (username, password_hash, display_name, now, now)
    )
    conn.commit()
    user_id = c.lastrowid
    conn.close()
    return {"id": user_id, "username": username, "display_name": display_name}


def verify_user(username, password):
    username = username.strip().lower()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, password_hash, display_name FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"error": "Invalid username or password"}
    user_id, uname, password_hash, display_name = row
    if not check_password_hash(password_hash, password):
        conn.close()
        return {"error": "Invalid username or password"}
    c.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now().isoformat(), user_id))
    conn.commit()
    conn.close()
    return {"id": user_id, "username": uname, "display_name": display_name}


def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, display_name, created_at, last_login FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "username": row[1], "display_name": row[2], "created_at": row[3], "last_login": row[4]}


init_db()

if __name__ == '__main__':
    print("Testing auth module...")
    result = create_user("azin", "test123", "Azin Iftikhar")
    print("Create user:", result)
    result2 = verify_user("azin", "test123")
    print("Verify correct password:", result2)
    result3 = verify_user("azin", "wrongpass")
    print("Verify wrong password:", result3)
