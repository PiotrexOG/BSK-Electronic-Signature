import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

def save_public_key(public_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def encrypt_file(public_key, input_file, output_file):
    with open(input_file, "rb") as file:
        plaintext = file.read()
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_file, "wb") as file:
        file.write(ciphertext)

def decrypt_file(private_key, input_file, output_file):
    with open(input_file, "rb") as file:
        ciphertext = file.read()
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_file, "wb") as file:
        file.write(plaintext)

def select_file():
    root = tk.Tk()
    root.withdraw() # Ukryj główne okno aplikacji

    file_path = filedialog.askopenfilename() # Wybierz plik za pomocą okna dialogowego
    return file_path

# Przykładowe użycie:
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keypair()
    save_private_key(private_key, "private_key.pem")
    save_public_key(public_key, "public_key.pem")

    # Szyfrowanie pliku
    input_file = select_file()
    if input_file:
        encrypt_file(public_key, input_file, "encrypted.txt")

    # Deszyfrowanie pliku
    private_key = load_private_key("private_key.pem")
    input_file = select_file()
    if input_file:
        decrypt_file(private_key, input_file, "decrypted.txt")
