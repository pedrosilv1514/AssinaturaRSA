import base64

def oaep_encrypt(message: bytes, n: int, e: int) -> bytes:
    m = int.from_bytes(message, byteorder="big")
    c = pow(m, e, n)
    return base64.b64encode(c.to_bytes((n.bit_length() + 7) // 8, byteorder="big"))

def oaep_decrypt(ciphertext: bytes, n: int, d: int) -> bytes:
    c = int.from_bytes(base64.b64decode(ciphertext), byteorder="big")
    m = pow(c, d, n)
    return m.to_bytes((n.bit_length() + 7) // 8, byteorder="big")