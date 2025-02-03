import sqlite3
import hashlib
from db import init_db
from config import db_path
#from crypto_utils import generate_rsa
from signature import generate_rsa_keys

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    """
    Registra um novo usuário com um par de chaves RSA
    """
    if not username or not password:
        print("Usuário e senha são obrigatórios!")
        return False
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Verifica se o usuário já existe
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            print("Usuário já existe!")
            return False
            
        # Gera o par de chaves RSA
        public_key = generate_rsa_keys(username)
        
        # Hash da senha
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Insere o usuário
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