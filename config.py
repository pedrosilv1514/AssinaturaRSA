import os

db_path = "users.db"
keys_dir = os.path.expanduser("~/.rsa_keys")
os.makedirs(keys_dir, exist_ok=True)