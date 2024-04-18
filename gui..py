import customtkinter
from detect_USB import detect_usb
from tkinter import filedialog
from typing import Literal, Union, Tuple
from main import *
import customtkinter as ctk
import os

def generate_private_key_and_public(label):
    label.configure(text="Keys Generated")
    private_key, public_key = generate_rsa_keypair()
    save_private_key(private_key, "private_key.pem")
    save_public_key(public_key, "public_key.pem")

global_filepath = None
def choose_private_key():
    global global_filepath
    global_filepath = filedialog.askopenfilename()



def encrypt(password):

    pass


def decrypt():
    print("decrypt")
    # Functionality to decrypt using selected encrypted key and password
    pass


def choose_file_to_sign(private_key_path):
    filepath = filedialog.askopenfilename()
    print(filepath)
    print(private_key_path)
    private_key_path = os.path.normpath(private_key_path)
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    create_xades_signature(filepath, private_key)



def create_root_window():
    root = ctk.CTk()
    root.title("BSK Electronic Signature by Krzysztof Madajczak 188674 and Piotr Wesołowski")
    root.geometry("900x600")
    root.grid_rowconfigure(2, weight=1)
    return root


def create_sidebar_frame(root, row, column, rowspan, width=300):
    sidebar_frame = ctk.CTkFrame(root, width=width, corner_radius=0)
    sidebar_frame.grid(row=row, column=column, rowspan=rowspan, sticky="nsew", padx=(25, 20))
    sidebar_frame.grid_rowconfigure(4, weight=1)
    return sidebar_frame


def create_label(parent, text, font_size=20, weight: Literal["normal", "bold", None] = "bold", row=0, column=0, padx=40, pady=(20, 10)):
    label = ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=font_size, weight=weight))
    label.grid(row=row, column=column, padx=padx, pady=pady)
    return label


def create_button(parent, text, command=None, row=0, column=0, padx=40, pady: Union[int, Tuple[int, int]]= 10):
    button = ctk.CTkButton(parent, text=text, command=command)
    if isinstance(pady, tuple):
        pady_top, pady_bottom = pady
        button.grid(row=row, column=column, padx=padx, pady=(pady_top, pady_bottom))
    else:
        button.grid(row=row, column=column, padx=padx, pady=pady)
    return button


def create_entry(parent, placeholder_text="", show="", row=0, column=0, padx=40, pady=10):
    entry = ctk.CTkEntry(parent, placeholder_text=placeholder_text, show=show)
    entry.grid(row=row, column=column, padx=padx, pady=pady)
    return entry


def choose_the_document():

    global global_filepath
    global_filepath = filedialog.askopenfilename()

def create_empty_label(parent, text="", row=0, column=0, padx=40, pady=(20, 10)):
    label = ctk.CTkLabel(parent, text=text)
    label.grid(row=row, column=column, padx=padx, pady=pady)
    return label


def create_sidebar(root, row, column, rowspan):
    sidebar = create_sidebar_frame(root, row, column, rowspan)
    label = create_label(sidebar, "Status", row=3)
    label.configure(text="Status")
    # Sidebar content
    create_label(sidebar, "Generator", row=0)
    create_button(sidebar, "Generate private key and public key", command=lambda: generate_private_key_and_public(label), row=1)
    create_empty_label(sidebar, row=4)

    return sidebar


def create_encryption_sidebar(root, row, column, rowspan):
    sidebar = create_sidebar_frame(root, row, column, rowspan, width=200)

    # Encryption content
    create_label(sidebar, "Encryption", row=0)
    create_button(sidebar, "Choose private key", command=choose_private_key, row=1)
    entry_password = create_entry(sidebar, placeholder_text="Type password", show="*", row=2)
    password = entry_password.get()
    create_button(sidebar, "Encrypt", command=lambda: encrypt(password), row=3)

    create_empty_label(sidebar, row=4)
    # Decryption content
    create_label(sidebar, "Decryption", row=5)
    create_button(sidebar, "Choose private key", command=generate_private_key_and_public, row=6)
    create_entry(sidebar, placeholder_text="Type password", show="*", row=7)
    create_button(sidebar, "Decrypt", command=decrypt, row=8, padx=40, pady=(10,50))

    return sidebar


def create_sign_document_sidebar(root, row, column, rowspan):
    sidebar = create_sidebar_frame(root, row, column, rowspan, width=200)

    # Sign document content
    create_label(sidebar, "Sign document", row=0)

    pendrive_label = create_label(sidebar, "Insert Pendrive", row=1, pady=(20, 10))

    private_key_path = detect_usb()
    if os.path.exists(private_key_path):
        pendrive_label.configure(text="Pendrive Inside")
        create_button(sidebar, "Choose the document to be sign", command=lambda: choose_file_to_sign(private_key_path), row=2)
        create_empty_label(sidebar, row=4)

    return sidebar


# Main function
def main():

    root = create_root_window()
    sidebar_frame = create_sidebar(root, 0, 0, 3)
    encryption_sidebar_frame = create_encryption_sidebar(root, 0, 2, 8)
    sign_document_sidebar_frame = create_sign_document_sidebar(root, 0, 3, 3)

    root.mainloop()


if __name__ == "__main__":
    main()
