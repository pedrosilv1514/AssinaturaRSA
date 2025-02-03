## Estrutura de diretórios

/rsa_signing_app
│── main.py                 # Ponto de entrada do programa
│── db.py                   # Gerenciamento do banco de dados SQLite
│── auth.py                 # Funções de autenticação (registro e login)
│── crypto_utils.py         # Geração de chaves RSA e hashing
│── signature.py            # Assinatura e verificação de arquivos
│── config.py               # Configurações globais (ex.: caminho do BD e das chaves)
│── requirements.txt        # Dependências do projeto
└── rsa_keys/               # Diretório onde as chaves privadas serão armazenadas (dentro do sistema)

## Arquivo: config.py

import os

db_path = "users.db"
keys_dir = os.path.expanduser("~/.rsa_keys")
os.makedirs(keys_dir, exist_ok=True)

## Arquivo: db.py

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

## Arquivo: auth.py

import sqlite3
import hashlib
from db import init_db
from config import db_path
from crypto_utils import generate_keys

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username: str, password: str):
    hashed_password = hash_password(password)
    public_key = generate_keys(username)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
                       (username, hashed_password, public_key))
        conn.commit()
        print("Usuário cadastrado com sucesso!")
    except sqlite3.IntegrityError:
        print("Erro: Nome de usuário já existe!")
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

## Arquivo: crypto_utils.py

import os
from Crypto.PublicKey import RSA
from config import keys_dir

def generate_keys(username: str):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(private_key)
    
    return public_key.decode()

## Arquivo: signature.py

import os
import base64
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256
from config import keys_dir, db_path

def sign_file(username: str, file_path: str):
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    if not os.path.exists(private_key_path):
        print("Erro: Chave privada não encontrada!")
        return
    
    with open(private_key_path, "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    
    with open(file_path, "rb") as file:
        file_data = file.read()
    
    hash_obj = SHA3_256.new(file_data)
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    signature_b64 = base64.b64encode(signature).decode()
    
    with open(file_path, "a") as file:
        file.write(f"\n---SIGNATURE---\n{username}\n{signature_b64}")
    print("Arquivo assinado com sucesso!")

def verify_signature(file_path: str):
    with open(file_path, "r") as file:
        lines = file.readlines()
    
    try:
        signature_index = lines.index("---SIGNATURE---\n")
        file_data = "".join(lines[:signature_index]).encode()
        signer_username = lines[signature_index + 1].strip()
        signature_b64 = lines[signature_index + 2].strip()
        signature = base64.b64decode(signature_b64)
    except ValueError:
        print("Erro: Assinatura não encontrada no arquivo!")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE username = ?", (signer_username,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        print("Erro: Usuário não encontrado!")
        return
    
    public_key = RSA.import_key(result[0].encode())
    hash_obj = SHA3_256.new(file_data)
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        print(f"Assinatura válida! O arquivo foi assinado por {signer_username}.")
    except (ValueError, TypeError):
        print("Assinatura inválida!")

## Arquivo: main.py

from db import init_db
from auth import register_user, login_user
from signature import sign_file, verify_signature

if __name__ == "__main__":
    init_db()
    logged_in_user = None
    
    while True:
        if not logged_in_user:
            choice = input("1 - Registrar\n2 - Login\nEscolha: ")
            if choice == "1":
                user = input("Usuário: ")
                pwd = input("Senha: ")
                register_user(user, pwd)
            elif choice == "2":
                user = input("Usuário: ")
                pwd = input("Senha: ")
                if login_user(user, pwd):
                    logged_in_user = user
        else:
            choice = input("1 - Assinar Arquivo\n2 - Verificar Assinatura\n3 - Logout\nEscolha: ")
            if choice == "1":
                file_path = input("Caminho do arquivo: ")
                sign_file(logged_in_user, file_path)
            elif choice == "2":
                file_path = input("Caminho do arquivo: ")
                verify_signature(file_path)
            elif choice == "3":
                logged_in_user = None
                print("Logout realizado!")
            else:
                print("Opção inválida!")
