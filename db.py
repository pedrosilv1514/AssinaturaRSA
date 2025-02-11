import sqlite3
from config import db_path

def init_db():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        public_key TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def get_user(username: str):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, public_key FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        conn.close()
        return user if user else None
    except sqlite3.Error as e:
        print(f"Erro ao consultar usuário: {e}")
        return None

def list_users():
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, public_key FROM users")
        users = cursor.fetchall()
        
        conn.close()
        return users
    except sqlite3.Error as e:
        print(f"Erro ao listar usuários: {e}")
        return []
    
usuarios = list_users()
for user in usuarios:
    print(f"ID: {user[0]}, Username: {user[1]}, Chave Pública: {user[2]}")
