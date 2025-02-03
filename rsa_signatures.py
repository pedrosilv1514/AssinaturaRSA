import random
import base64
import hashlib
from sympy import randprime
from Crypto.Util.number import inverse

def generate_keys(bit_length=1024):
    """Gera chaves RSA com primos de no mínimo 1024 bits"""
    p = randprime(2**(bit_length-1), 2**bit_length)
    q = randprime(2**(bit_length-1), 2**bit_length)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Valor padrão para e
    d = inverse(e, phi)

    return (n, e), (n, d)  # Retorna chave pública e privada

def sign_message(message, private_key):
    """Assina a mensagem com a chave privada usando SHA-3 e RSA"""
    n, d = private_key
    hash_value = int.from_bytes(hashlib.sha3_256(message.encode()).digest(), byteorder='big')
    signature = pow(hash_value, d, n)  # m^d mod n
    return base64.b64encode(signature.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).decode()

def verify_signature(message, signature, public_key):
    """Verifica a assinatura da mensagem"""
    n, e = public_key
    hash_value = int.from_bytes(hashlib.sha3_256(message.encode()).digest(), byteorder='big')
    signature_int = int.from_bytes(base64.b64decode(signature), byteorder='big')
    decrypted_hash = pow(signature_int, e, n)  # S^e mod n
    return hash_value == decrypted_hash
