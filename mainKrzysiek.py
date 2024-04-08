from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import *
import os




# Funkcja do generowania klucza prywatnego RSA z hasłem
def generate_encrypted_private_key(password, salt):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Utwórz kdf (Key Derivation Function) z hasłem i solą
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    # Wygeneruj klucz na podstawie hasła
    key = kdf.derive(password)

    # Ustaw algorytm szyfrowania AES-CBC z hasłem
    encryption_algorithm = serialization.BestAvailableEncryption(key)

    # Konwertuj klucz prywatny do formatu PEM i zaszyfruj go
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    # Zapis klucza prywatnego do pliku
    with open("private_key.pem", "wb") as f:
        f.write(private_key_pem)
    return private_key_pem, private_key

def generate_public_key(private_key):
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as f:
        f.write(public_key_pem)
    return public_key_pem

# def sign_document(document_path, private_key_path, signature_path, password=b"0000"):
#         # Wczytaj dokument
#     with open(document_path, "rb") as f:
#         document = f.read()

#     # Wczytaj klucz prywatny
#     with open(private_key_path, "rb") as f:
#         private_key_bytes = f.read()
    
#     private_key = serialization.load_pem_private_key(
#         private_key_bytes,
#         password=password,
#         backend=default_backend()
#     )

#     # Podpisz dokument
#     signature = private_key.sign(
#         document,
#         padding.PSS(
#             mgf=padding.MGF1(hashes.SHA256()),
#             salt_length=padding.PSS.MAX_LENGTH
#         ),
#         hashes.SHA256()
#     )

#     # Zapisz podpis do pliku
#     with open(signature_path, "wb") as f:
#         f.write(signature)

# def verify_signature(document_path, signature_path, public_key_path):
    # Wczytaj dokument
    with open(document_path, "rb") as f:
        document = f.read()

    # Wczytaj podpis
    with open(signature_path, "rb") as f:
        signature = f.read()

    # Wczytaj klucz publiczny
    with open(public_key_path, "rb") as f:
        public_key_bytes = f.read()
    
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    # Weryfikuj podpis
    try:
        public_key.verify(
            signature,
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Podpis jest poprawny.")
    except:
        print("Podpis jest niepoprawny.")

if __name__ == "__main__":
    # password = input("Podaj hasło: ").encode()
    password = b"0000"
    salt = os.urandom(16)

    private_key_pem ,privateKey = generate_encrypted_private_key(password, salt)
    publicKey = generate_public_key(privateKey)
    print("Klucz prywatny:" + str(private_key_pem))
    print("Klucz publiczny:" + str(publicKey))
    document_path = "test.txt"
    private_key_path = "private_key.pem"
    signature_path = "signature.bin"
    public_key_path = "public_key.pem"

    # Podpisz dokument
    sign_document(document_path, private_key_path, signature_path)
    print("Dokument został podpisany.")

    # Weryfikuj podpis
    verify_signature(document_path, signature_path, public_key_path)