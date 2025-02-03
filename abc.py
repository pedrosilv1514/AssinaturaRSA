from rsa_signature import generate_keys, sign_message, verify_signature

# Gerar chaves para um usuário
public_key, private_key = generate_keys()

# Mensagem a ser assinada
message = "Este é um arquivo seguro."

# Assinar a mensagem
signature = sign_message(message, private_key)
print(f"Assinatura: {signature}")

# Verificar a assinatura
is_valid = verify_signature(message, signature, public_key)
print("Assinatura válida!" if is_valid else "Assinatura inválida!")
