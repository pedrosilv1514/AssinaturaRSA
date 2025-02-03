import sqlite3
from config import db_path
from db import init_db
from auth import register_user, login_user
from signature import sign_file, verify_signature, generate_rsa_keys

if __name__ == "__main__":
    init_db()
    logged_in_user = None
    
    while True:
        if not logged_in_user:
            choice = input("1 - Registrar\n2 - Login\n3 - Regenerar Chaves\nEscolha: ")
            if choice == "1":
                user = input("Usuário: ")
                pwd = input("Senha: ")
                register_user(user, pwd)
            elif choice == "2":
                user = input("Usuário: ")
                pwd = input("Senha: ")
                if login_user(user, pwd):
                    logged_in_user = user
            elif choice == "3":
                user = input("Usuário: ")
                # Regenera as chaves para um usuário existente
                public_key = generate_rsa_keys(user)
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET public_key = ? WHERE username = ?", 
                             (public_key, user))
                conn.commit()
                conn.close()
                print("Chaves regeneradas com sucesso!")
        else:
            choice = input("1 - Assinar Arquivo\n2 - Verificar Assinatura\n3 - Logout\nEscolha: ")
            if choice == "1":
                file_path = input("Caminho do arquivo: ")
                sign_file(logged_in_user, file_path)
            elif choice == "2":
                file_path = input("Caminho do arquivo: ")
                username = input("Nome do usuário que assinou: ")
                verify_signature(file_path, username)
            elif choice == "3":
                logged_in_user = None
                print("Logout realizado!")