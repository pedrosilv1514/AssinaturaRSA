import os
import random
from config import keys_dir

def is_prime(n, k=40):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    
    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=1024):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1  # Garante que o número tem o número correto de bits e é ímpar
        if is_prime(p):
            return p

def mod_inverse(e, phi):
    """Calcula o inverso modular de e mod phi usando o Algoritmo Estendido de Euclides"""
    a, b = e, phi
    x0, x1 = 1, 0
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
    if a != 1:
        raise ValueError("O inverso modular não existe")
    return x0 % phi  # Garante que o valor esteja no intervalo correto

def generate_keys(username: str):
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Valor comum para a chave pública
    d = mod_inverse(e, phi)
    
    # Formata a chave privada em uma única linha sem espaços extras
    private_key = f"{d},{n}"
    public_key = f"{e},{n}"
    
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    with open(private_key_path, "w") as priv_file:
        priv_file.write(private_key.strip())  # Garante que não haja quebras de linha ou espaços
    
    return public_key
