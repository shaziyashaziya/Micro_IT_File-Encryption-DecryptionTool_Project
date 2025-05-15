import os
import base64
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# --- Folders ---
ENCRYPTED_DIR = "encrypted_files"
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

# --- Create a key from password ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- Encrypt a file ---
def encrypt_file(filepath):
    password = input("🔐 Set a password to encrypt (visible): ").strip()

    salt = os.urandom(16)  # random 16-byte salt
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(filepath, "rb") as file:
        data = file.read()
    encrypted = fernet.encrypt(data)

    filename = os.path.basename(filepath)
    enc_path = os.path.join(ENCRYPTED_DIR, filename + ".enc")
    salt_path = os.path.join(ENCRYPTED_DIR, filename + ".salt")

    with open(enc_path, "wb") as f:
        f.write(encrypted)
    with open(salt_path, "wb") as f:
        f.write(salt)

    print(f"[✔] Encrypted file saved to: {enc_path}")
    print(f"[✔] Salt saved to: {salt_path}")

# --- Decrypt a file ---
def decrypt_file(enc_path):
    password = input("🔑 Enter password to decrypt (visible): ").strip()

    salt_path = enc_path.replace(".enc", ".salt")

    if not os.path.exists(salt_path):
        print("[!] Missing salt file!")
        return

    with open(salt_path, "rb") as f:
        salt = f.read()

    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(enc_path, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted = fernet.decrypt(encrypted_data)
        dec_path = enc_path.replace(".enc", ".dec")
        with open(dec_path, "wb") as f:
            f.write(decrypted)
        print(f"[✔] File decrypted and saved to: {dec_path}")
    except:
        print("[✘] Wrong password or file corrupted!")

# --- Main Menu ---
if __name__ == "__main__":
    print("📂 1. Encrypt a file")
    print("📂 2. Decrypt a file")
    choice = input("Choose (1 or 2): ").strip()

    if choice == "1":
        path = input("Enter path of file to encrypt: ").strip().strip('"')
        if os.path.exists(path):
            encrypt_file(path)
        else:
            print("[!] File not found.")
    elif choice == "2":
        path = input("Enter path of .enc file to decrypt: ").strip().strip('"')
        if os.path.exists(path):
            decrypt_file(path)
        else:
            print("[!] Encrypted file not found.")
    else:
        print("[!] Invalid choice.")
