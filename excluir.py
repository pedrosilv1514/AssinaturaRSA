import os
from crypto_utils import generate_rsa_keys

def generate_rsa_keys_test(username):
    print(f"Gerando chaves para {username}...")

    public_key, private_key = generate_rsa_keys(username)

    if not public_key or not private_key:
        print("Erro: A geração das chaves retornou valores inválidos!")
        return None
    
    keys_dir = "chaves_rsa"
    os.makedirs(keys_dir, exist_ok=True)

    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    public_key_path = os.path.join(keys_dir, f"{username}_public.pem")

    try:
        with open(private_key_path, "w") as priv_file:
            priv_file.write(f"{private_key[0]},{private_key[1]}")
        print(f"Chave privada salva em: {private_key_path}")

        with open(public_key_path, "w") as pub_file:
            pub_file.write(f"{public_key[0]},{public_key[1]}")
        print(f"Chave pública salva em: {public_key_path}")

        return f"{public_key[0]},{public_key[1]}"
    except Exception as e:
        print(f"Erro ao salvar as chaves: {e}")
        return None
