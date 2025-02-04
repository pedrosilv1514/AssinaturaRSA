import os
import base64
import sqlite3
import hashlib
from config import keys_dir, db_path

def rsa_encrypt(message, exp, n):
    message_int = int.from_bytes(message, byteorder='big')
    cipher_int = pow(message_int, exp, n)
    k = (n.bit_length() + 7) // 8
    return cipher_int.to_bytes(k, byteorder='big')

def rsa_decrypt(cipher, exp, n):
    cipher_int = int.from_bytes(cipher, byteorder='big')
    message_int = pow(cipher_int, exp, n)
    k = (n.bit_length() + 7) // 8
    return message_int.to_bytes(k, byteorder='big')

def get_original_file_data(lines):
    content = []
    for line in lines:
        if line.strip() == "---SIGNATURE---":
            break
        content.append(line)

    result = "".join(content).rstrip('\n') + "\n"
    return result.encode('utf-8')

def sign_file(username: str, file_path: str):
    if not os.path.exists(file_path):
        return False, f"Erro: Arquivo {file_path} não encontrado!"

    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
    except Exception as e:
        return False, f"Erro ao ler o arquivo: {e}"
    
    # Teste para assinaturas
    for i in range(len(lines)):
        if lines[i].strip() == "---SIGNATURE---":
            if i+1 < len(lines) and lines[i+1].strip() == username:
                return False, "Erro: Esse usuário já assinou esse documento!"


    original_data = get_original_file_data(lines)

    if not original_data.strip():
        return False, "Erro: O arquivo está vazio ou não contém conteúdo antes da assinatura!"

    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    if not os.path.exists(private_key_path):
        return False, "Erro: Chave privada não encontrada!"

    with open(private_key_path, "r") as priv_file:
        key_data = priv_file.read().strip()
        parts = [p for p in key_data.split(',') if p.strip() != '']
        if len(parts) < 2:
            return False, "Erro: Formato de chave privada inválido!"
        d, n = map(int, parts[:2])

    hash_bytes = hashlib.sha3_256(original_data).digest()

    #Assinatura do has
    try:
        signature = rsa_encrypt(hash_bytes, d, n)
        signature_b64 = base64.b64encode(signature).decode()
    except Exception as e:
        return False, f"Erro ao gerar assinatura: {e}"

    try:
        with open(file_path, "a") as file:
            file.write(f"\n---SIGNATURE---\n{username}\n{signature_b64}\n")

        with open(file_path + ".sig", "wb") as f:
            f.write(base64.b64decode(signature_b64))

        return True, "Arquivo assinado com sucesso!"
    except Exception as e:
        return False, f"Erro ao salvar assinatura: {e}"

def verify_signature(file_path: str, username: str):
    import io
    import sys

    output = io.StringIO()
    original_stdout = sys.stdout
    sys.stdout = output

    try:
        try:
            with open(file_path, "r", encoding='utf-8') as file:
                lines = file.readlines()
        except Exception as e:
            print(f"Erro ao ler o arquivo: {e}")
            sys.stdout = original_stdout
            return (False, output.getvalue().strip())

        original_data = get_original_file_data(lines)
        found_block = None
        i = 0
        while i < len(lines):
            if lines[i].strip() == "---SIGNATURE---":
                if i+2 < len(lines):
                    signer_username = lines[i+1].strip()
                    signature_b64 = lines[i+2].strip()
                    if signer_username == username:
                        found_block = (signer_username, signature_b64)
                        break
                i += 3
            else:
                i += 1

        if not found_block:
            print("Erro: Assinatura do usuário informado não encontrada no arquivo!")
            sys.stdout = original_stdout
            return (False, "Assinatura não encontrada para o usuário informado.")

        signer_username, signature_b64 = found_block

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT public_key FROM users WHERE username = ?", (signer_username,))
            result = cursor.fetchone()
            conn.close()

            if not result:
                print("Erro: Usuário não encontrado no banco de dados!")
                sys.stdout = original_stdout
                return (False, "Usuário não encontrado no banco de dados.")

            e_val, n_val = map(int, result[0].split(','))
        except Exception as e:
            print(f"Erro ao buscar chave pública: {e}")
            sys.stdout = original_stdout
            return (False, "Erro ao buscar chave pública.")

        # Calculo do hash - conteudo original
        hash_bytes = hashlib.sha3_256(original_data).digest()

        try:
            signature = base64.b64decode(signature_b64)
            decrypted_full = rsa_decrypt(signature, e_val, n_val)
            recovered_hash = decrypted_full[-32:]
            
            if recovered_hash == hash_bytes:
                sys.stdout = original_stdout
                
                return (True, f"Assinatura válida! O arquivo foi assinado por {signer_username}.")
            else:
                sys.stdout = original_stdout
                
                return (False, "Assinatura inválida.")
        except Exception as e:
            print(f"Erro ao verificar assinatura: {e}")
            sys.stdout = original_stdout
            
            return (False, "Erro ao verificar assinatura.")

    except Exception as e:
        sys.stdout = original_stdout
        return (False, str(e))