import os
import base64
import sqlite3
import hashlib
from db_helpers import get_user_public_key
from config import keys_dir, db_path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def rsa_encrypt(message, exp, n):
    message_int = int.from_bytes(message, byteorder='big')
    print(f"[DEBUG] Mensagem original como inteiro: {message_int}")
    print(f"[DEBUG] Expoente (d): {exp}")
    print(f"[DEBUG] Módulo (n): {n}")
    
    cipher_int = pow(message_int, exp, n)
    print(f"[DEBUG] Cifra como inteiro: {cipher_int}")
    
    k = (n.bit_length() + 7) // 8
    cipher_bytes = cipher_int.to_bytes(k, byteorder='big')
    print(f"[DEBUG] Cifra em bytes (hex): {cipher_bytes.hex()}")
    
    return cipher_bytes

def rsa_decrypt(cipher, exp, n):
    k = (n.bit_length() + 7) // 8
    cipher_int = int.from_bytes(cipher, byteorder='big')
    print(f"[DEBUG] Cifra como inteiro: {cipher_int}")
    print(f"[DEBUG] Expoente (e): {exp}")
    print(f"[DEBUG] Módulo (n): {n}")
    
    message_int = pow(cipher_int, exp, n)
    print(f"[DEBUG] Mensagem decriptada como inteiro: {message_int}")
    
    full_decrypted = message_int.to_bytes(k, byteorder='big')
    print(f"[DEBUG] Bloco de decriptação completo (hex): {full_decrypted.hex()}")
    
    return full_decrypted[-32:]
def get_original_file_data(lines):
    """
    Considera que o conteúdo original do arquivo é tudo antes da primeira ocorrência do marcador,
    preservando as quebras de linha originais.
    """
    content = []
    for line in lines:
        if line.strip() == "---SIGNATURE---":
            break
        content.append(line)
    
    # Usa rstrip para remover apenas o whitespace no final, mantendo newlines internos
    result = "".join(content).rstrip('\n') + "\n"
    return result.encode('utf-8')

def sign_file(username: str, file_path: str):
    """
    Assina um arquivo usando RSA e SHA3-256
    """
    # Verifica se o arquivo existe
    if not os.path.exists(file_path):
        print(f"Erro: Arquivo {file_path} não encontrado!")
        return False

    # Lê o conteúdo atual do arquivo
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
    except Exception as e:
        print("Erro ao ler o arquivo:", e)
        return False

    # Obtém o conteúdo original
    original_data = get_original_file_data(lines)
    
    # Verifica se há conteúdo para assinar
    if not original_data.strip():
        print("Erro: O arquivo está vazio ou não contém conteúdo antes da assinatura!")
        return False

    print(f"[DEBUG] Conteúdo a ser assinado: {original_data}")
    
    # Verifica se o usuário já assinou o documento
    i = 0
    while i < len(lines):
        if lines[i].strip() == "---SIGNATURE---":
            if i+1 < len(lines) and lines[i+1].strip() == username:
                print("Erro: Esse usuário já assinou esse documento!")
                return False
            i += 3
        else:
            i += 1

    # Lê a chave privada do usuário
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    if not os.path.exists(private_key_path):
        print("Erro: Chave privada não encontrada!")
        return False

    # Lê as chaves do usuário
    with open(private_key_path, "r") as priv_file:
        key_data = priv_file.read().strip()
        parts = [p for p in key_data.split(',') if p.strip() != '']
        if len(parts) < 2:
            print("Erro: Formato de chave privada inválido!")
            return False
        d, n = map(int, parts[:2])

    # Calcula o hash do conteúdo
    hash_bytes = hashlib.sha3_256(original_data).digest()
    print(f"[DEBUG] Hash original (hex): {hash_bytes.hex()}")
    print(f"[DEBUG] Tamanho do hash: {len(hash_bytes)} bytes")
    
    if len(hash_bytes) != 32:
        print(f"Erro: Hash tem tamanho inesperado: {len(hash_bytes)} bytes")
        return False

    # Assina o hash
    try:
        signature = rsa_encrypt(hash_bytes, d, n)
        signature_b64 = base64.b64encode(signature).decode()
    except Exception as e:
        print(f"Erro ao gerar assinatura: {e}")
        return False

    # Apende a assinatura ao arquivo
    try:
        # Save signature to file
        with open(file_path, "a") as file:
            file.write(f"\n---SIGNATURE---\n{username}\n{signature_b64}\n")

        # Save signature to .sig file
        with open(file_path + ".sig", "wb") as f:
            f.write(base64.b64decode(signature_b64))
        
        print("Arquivo assinado com sucesso!")
        return True
    except Exception as e:
        print(f"Erro ao salvar assinatura: {e}")
        return False 
    
def verify_signature(file_path: str, username: str):
    try:
        with open(file_path, "r", encoding='utf-8') as file:
            lines = file.readlines()
    except Exception as e:
        print(f"Erro ao ler o arquivo: {e}")
        return False

    # Obtém o conteúdo original
    original_data = get_original_file_data(lines)

    # Busca a assinatura do usuário
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
        return False

    signer_username, signature_b64 = found_block

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username = ?", (signer_username,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            print("Erro: Usuário não encontrado no banco de dados!")
            return False

        e_val, n_val = map(int, result[0].split(','))
    except Exception as e:
        print(f"Erro ao buscar chave pública: {e}")
        return False

    # Calcula o hash do conteúdo original
    hash_bytes = hashlib.sha3_256(original_data).digest()

    try:
        signature = base64.b64decode(signature_b64)
        
        # Obtem o bloco completo de decriptação
        decrypted_full = rsa_decrypt(signature, e_val, n_val)
        
        # Usa os últimos 32 bytes como hash recuperado
        recovered_hash = decrypted_full[-32:]
        
        if recovered_hash == hash_bytes:
            print(f"Assinatura válida! O arquivo foi assinado por {signer_username}.")
            return True
        else:
            print("Assinatura inválida!")
            print(f"Hash esperado : {hash_bytes.hex()}")
            print(f"Hash recebido : {recovered_hash.hex()}")
            return False
    except Exception as e:
        print(f"Erro ao verificar assinatura: {e}")
        return False

def test_key_pair(e, d, n):
    """
    Testa se um par de chaves RSA está funcionando corretamente
    """
    test_message = b"test"
    print("[DEBUG] Testando par de chaves...")
    
    try:
        encrypted = rsa_encrypt(test_message, e, n)
        decrypted = rsa_decrypt(encrypted, d, n)
        print(f"[DEBUG] Mensagem original: {test_message}")
        print(f"[DEBUG] Mensagem decriptada: {decrypted}")
        return test_message == decrypted
    except Exception as e:
        print(f"Erro no teste do par de chaves: {e}")
        return False
    
def generate_rsa_keys(username):
    """
    Gera um novo par de chaves RSA de 2048 bits
    """
    # Gera o par de chaves
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Extrai os componentes
    numbers = private_key.private_numbers()
    n = numbers.public_numbers.n
    e = numbers.public_numbers.e
    d = numbers.d
    
    # Salva a chave privada
    with open(os.path.join(keys_dir, f"{username}_private.pem"), "w") as f:
        f.write(f"{d},{n}")
    
    # Retorna a chave pública para salvar no banco
    return f"{e},{n}"

def get_signers(file_path: str):
    """
    Retorna uma lista dos nomes dos usuários que assinaram o documento.
    Cada bloco de assinatura é esperado no formato:
        ---SIGNATURE---
        <nome do usuário>
        <assinatura em base64>
    """
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
    except Exception as e:
        print(f"Erro ao ler o arquivo: {e}")
        return []
    
    signers = []
    i = 0
    while i < len(lines):
        if lines[i].strip() == "---SIGNATURE---":
            if i+1 < len(lines):
                signer = lines[i+1].strip()
                # Adiciona somente se não estiver na lista (para evitar duplicatas)
                if signer not in signers:
                    signers.append(signer)
            i += 3  # pula o bloco (marcador, nome, assinatura)
        else:
            i += 1
    return signers

def debug_user_keys(username: str):
    # Lê a chave privada do arquivo
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    if os.path.exists(private_key_path):
        with open(private_key_path, "r") as f:
            key_data = f.read().strip()
        try:
            d, n = map(int, key_data.split(','))
        except Exception as e:
            print(f"[DEBUG] Erro ao ler chave privada: {e}")
            return
        print(f"[DEBUG] Chave privada de {username}: d = {d}, n = {n}")
    else:
        print(f"[DEBUG] Chave privada para {username} não encontrada.")

    # Lê a chave pública do banco de dados
    import sqlite3
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        try:
            e_str, n_str = result[0].split(',')
            e_val, n_val = int(e_str), int(n_str)
            print(f"[DEBUG] Chave pública de {username}: e = {e_val}, n = {n_val}")
        except Exception as e:
            print(f"[DEBUG] Erro ao ler chave pública: {e}")
    else:
        print(f"[DEBUG] Chave pública para {username} não encontrada.")


def test_key_pair_for_user(username: str):
    """
    Testa o par de chaves RSA do usuário enviando uma mensagem de teste.
    Retorna True se o processo (assinatura e verificação) funcionar corretamente.
    """
    import os
    import sqlite3
    from config import keys_dir, db_path

    # Lê a chave privada do usuário
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    if not os.path.exists(private_key_path):
        print("Chave privada não encontrada!")
        return False
    with open(private_key_path, "r") as f:
        key_data = f.read().strip()
    try:
        d, n = map(int, key_data.split(','))
    except Exception as e:
        print("Erro ao interpretar a chave privada:", e)
        return False

    # Lê a chave pública do banco de dados
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        if not result:
            print("Chave pública não encontrada no banco!")
            return False
        e_val, n_val = map(int, result[0].split(','))
    except Exception as e:
        print("Erro ao ler a chave pública:", e)
        return False

    # Mensagem de teste
    test_message = b"Test"
    # Assinatura: assinatura = (test_message)^d mod n
    test_sig_int = pow(int.from_bytes(test_message, byteorder='big'), d, n)
    # Recuperação: (assinatura)^e mod n
    recovered_int = pow(test_sig_int, e_val, n_val)
    k = (n_val.bit_length() + 7) // 8
    recovered_bytes = recovered_int.to_bytes(k, byteorder='big')[-len(test_message):]
    
    print(f"[DEBUG] Mensagem de teste: {test_message}")
    print(f"[DEBUG] Mensagem recuperada: {recovered_bytes}")
    
    if recovered_bytes == test_message:
        print("Par de chaves está funcionando corretamente!")
        return True
    else:
        print("Falha no par de chaves!")
        return False
