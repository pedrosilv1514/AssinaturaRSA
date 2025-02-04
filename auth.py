import sqlite3
import hashlib
import os
from db import init_db
from config import db_path, keys_dir
#from crypto_utils import generate_rsa
from crypto_utils import generate_rsa_keys

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    if not username or not password:
        print("Usuário e senha são obrigatórios!")
        return False
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            print("Usuário já existe!")
            return False
        
        public_key = generate_rsa_keys(username)
        
        print(f"Verificando geração de chave para {username}...")
        private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
        public_key_path = os.path.join(keys_dir, f"{username}_public.pem")

        if os.path.exists(private_key_path):
            print(f"Chave privada criada: {private_key_path}")
        else:
            print("Erro: Chave privada não foi criada!")

        if os.path.exists(public_key_path):
            print(f"Chave pública criada: {public_key_path}")
        else:
            print("Erro: Chave pública não foi criada!")

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute(
            "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
            (username, password_hash, public_key)
        )
        conn.commit()
        print("Usuário registrado com sucesso!")
        return True
        
    except Exception as e:
        print(f"Erro ao registrar usuário: {e}")
        return False
    finally:
        conn.close()


def login_user(username: str, password: str):
    hashed_password = hash_password(password)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0] == hashed_password:
        print("Login bem-sucedido!")
        return True
    else:
        print("Credenciais inválidas!")
        return False
    
def get_user_public_key(username):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None
