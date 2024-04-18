from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_symmetric_key():
    return os.urandom(32)  # 32 bytes = 256 bits (for AES-256)

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

# Example usage:
input_file = 'example.txt'
output_file = 'encrypted_example.txt'

# Generate a symmetric key
symmetric_key = generate_symmetric_key()

# Encrypt the file
encrypt_file(input_file, output_file, symmetric_key)
