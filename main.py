import base64
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import xml.etree.ElementTree as ET
import datetime
import os

global_var = "SIEMA"
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

def sign_document(document_hash, private_key):
    signature = private_key.sign(
        document_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(document_path, signature_xml_path, public_key):
    try:
        # Oblicz skrót dokumentu
        with open(document_path, "rb") as file:
            document_content = file.read()
        document_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        document_hash.update(document_content)
        calculated_digest = document_hash.finalize()

        # Odczytaj sygnaturę z pliku XML
        tree = ET.parse(signature_xml_path)
        root = tree.getroot()
        signature_base64 = root.find("EncryptedHash").text
        signature = base64.b64decode(signature_base64)

        # Weryfikacja podpisu przy użyciu klucza publicznego
        public_key.verify(
            signature,
            calculated_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Signature verified successfully.")
    except Exception as e:
        print("Signature verification failed:", e)


def create_xades_signature(document_path, private_key):
    try:
        # Pobierz informacje o dokumencie
        document_size = os.path.getsize(document_path)
        document_extension = os.path.splitext(document_path)[-1]
        modification_date = datetime.datetime.fromtimestamp(os.path.getmtime(document_path))

        # Podpisz dokument
        with open(document_path, "rb") as file:
            document_content = file.read()

        document_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        document_hash.update(document_content)
        calculated_digest = document_hash.finalize()

        signature = sign_document(calculated_digest, private_key)

        # Stwórz dokument XML
        root = ET.Element("XAdES_Signature")
        document_info = ET.SubElement(root, "DocumentInfo")
        document_info.set("size", str(document_size))
        document_info.set("extension", document_extension)
        document_info.set("modification_date", str(modification_date))
        ET.SubElement(root, "SigningUserInfo", name="User A")
        ET.SubElement(root, "Timestamp").text = str(datetime.datetime.now())
        ET.SubElement(root, "EncryptedHash").text = base64.b64encode(signature).decode()

        # Zapisz dokument XML
        xml_tree = ET.ElementTree(root)
        xml_tree.write("signature.xml")

        return signature

    except Exception as e:
        print("Error creating XAdES signature:", e)
        return None

# Przykładowe użycie:
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keypair()
    save_private_key(private_key, "private_key.pem")
    save_public_key(public_key, "public_key.pem")

    document_path = select_file()
    signature = create_xades_signature(document_path, private_key)

    if signature:
        verify_signature(document_path, "signature.xml", public_key)

    # Szyfrowanie pliku
    input_file = select_file()
    if input_file:
        encrypt_file(public_key, input_file, "encrypted.txt")

    # Deszyfrowanie pliku
    private_key = load_private_key("private_key.pem")
    input_file = select_file()
    if input_file:
        decrypt_file(private_key, input_file, "decrypted.txt")
