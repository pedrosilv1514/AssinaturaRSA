import sqlite3
from config import db_path
from db import init_db
from db_helpers import get_user_public_key
from auth import register_user, login_user
from signature import sign_file, verify_signature, generate_rsa_keys, get_signers, debug_user_keys, test_key_pair_for_user

if __name__ == "__main__":
    init_db()
    logged_in_user = None
    
    while True:
        if not logged_in_user:
            choice = input("1 - Registrar\n2 - Login\n3 - Regenerar Chaves\n4 - Listar Assinaturas\n5 - Debug de Chaves\nEscolha: ")
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
                public_key = generate_rsa_keys(user)
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET public_key = ? WHERE username = ?", (public_key, user))
                conn.commit()
                conn.close()
                print("Chaves regeneradas com sucesso!")
            elif choice == "4":
                file_path = input("Caminho do arquivo: ")
                signers = get_signers(file_path)
                if signers:
                    print("Usuários que assinaram o documento: ")
                    for u in signers:
                        print(f'- {u}')
                else:
                    print("Nenhum usuário assinou o documento")
            elif choice == "5":
                # Exibe as chaves e testa o par de chaves do usuário informado
                user = input("Informe o nome do usuário para debug: ")
                debug_user_keys(user)
                test_key_pair_for_user(user)
        else:
            choice = input("1 - Assinar Arquivo\n2 - Verificar Assinatura\n3 - Debug de Chaves\n4 - Logout\nEscolha: ")
            if choice == "1":
                file_path = input("Caminho do arquivo: ")
                sign_file(logged_in_user, file_path)
            elif choice == "2":
                file_path = input("Caminho do arquivo: ")
                username = input("Nome do usuário que assinou: ")
                print(f"Chave pública do {username}: {get_user_public_key(username)}")
                verify_signature(file_path, username)

            elif choice == "3":
                debug_user_keys(logged_in_user)
                test_key_pair_for_user(logged_in_user)
            elif choice == "4":
                logged_in_user = None
                print("Logout realizado!")
