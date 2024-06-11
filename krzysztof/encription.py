import base64
import xml.etree.ElementTree as ET
import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def print_key(key):
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    print(key_pem)

def encrypt_key(password, private_key):
    salt = b'\x98A\xb9?J\xec\xe81v\x1c\xbb\xad\x1b\x85\x8a\x19\x89\x9d\x97t\xe6\xe7\xc3\x03\t"ht\xdda\xde\xcc'  # Można użyć get_random_bytes(32) w praktyce
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = AES.new(key, AES.MODE_CBC)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    padded_private_key = pad(private_key_bytes, AES.block_size)

    # Zaszyfruj dodany padding klucza prywatnego
    cipher_data = cipher.encrypt(padded_private_key)
    hasz = hashlib.sha256(password.encode()).hexdigest()
    # Zapisz sól, IV i zaszyfrowane dane do pliku
    with open('keys/encrypted_private_key.bin', 'wb') as f:
        f.write(salt)  # Zapisz sól do pliku
        f.write(hasz.encode())  # Zapisz sól do pliku
        f.write(cipher.iv)  # Zapisz wektor inicjalizacyjny do pliku
        f.write(cipher_data)  # Zapisz zaszyfrowane dane klucza prywatnego do pliku

    return

def decrypt_key(password = 123, path = 'keys/encrypted_private_key.bin'):
    with open('keys/encrypted_private_key.bin', 'rb') as f:
        salt = f.read(32)
        hasz = f.read(64)
        iv = f.read(16)
        cipher_data = f.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_private_key = cipher.decrypt(cipher_data)
    private_key_bytes = unpad(decrypted_padded_private_key, AES.block_size)
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )

    return private_key, hasz



def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


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



def encrypt_file(input_file, output_file, key):
    # Open the input file and read its contents
    with open(input_file, 'rb') as f:
        file_content = f.read()

    # Encrypt the file content with the symmetric key
    iv = os.urandom(16)  # Initialization vector for AES
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_content = encryptor.update(file_content) + encryptor.finalize()

    # Write the encrypted content to the output file
    with open(output_file, 'wb') as f:
        f.write(iv)
        f.write(encrypted_content)

def decrypt_file(input_file, output_file, key):
    # Open the encrypted file and read its contents along with the IV
    with open(input_file, 'rb') as f:
        iv = f.read(16)  # Read the first 16 bytes as the IV
        encrypted_content = f.read()

    # Decrypt the file content with the symmetric key and IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

    # Write the decrypted content to the output file
    with open(output_file, 'wb') as f:
        f.write(decrypted_content)

