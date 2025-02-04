import random
import math
import os
from config import keys_dir

def is_prime(n, k=5):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    
    #Miller-Rabin
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        is_composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                is_composite = False
                break
        
        if is_composite:
            return False
    
    return True

def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1
        
        if is_prime(candidate):
            return candidate

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = egcd(b % a, a)
            return gcd, y - (b // a) * x, x

    gcd, x, _ = egcd(e, phi)
    if gcd != 1:
        raise ValueError('Inverso modular não existe')
    else:
        return x % phi

def generate_rsa_keys(username, key_size=2048):
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e = random.randint(3, phi - 1)
    
    d = mod_inverse(e, phi)

    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    with open(private_key_path, "w") as f:
        f.write(f"{d},{n}")

    return f"{e},{n}"