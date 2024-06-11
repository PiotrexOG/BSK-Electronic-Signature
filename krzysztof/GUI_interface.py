from signature import sign_file, verify_signature
from tkinter import filedialog
from encription import *
from frontend import *
from pathlib import Path
import globals
#TODO
#Etap 1 - użytkownik ma pendrive a na nim klucz RSA zakodowany algorytmem AES z pinem ponadto musi tam znajdować się sol
#Etap 2 -

def generate_private_key_and_public(label, pin):
    if not pin:
        label.configure(text="password required")
        return
    else:
        label.configure(text="Keys Generated")
        private_key, public_key_temp = generate_rsa_keypair()
        encrypt_key(pin, private_key)
        if not Path("keys").exists():
            Path("keys").mkdir()
        save_private_key(private_key, "keys/not_encrypted_private_key.pem")
        pri, hasz =decrypt_key(pin)
        if private_key == pri:
            print("odszyfrowanie działa pomyślnie")

        # print_key(private_key)
        # print_key(pri)

        save_public_key(public_key_temp, "keys/not_encrypted_public_key.pem")

global_filepath = None

def choose_private_key():
    globals.path_private_key = filedialog.askopenfilename()

def refresh_sidebar_if_usb_detected(root, sidebar, pendrive_label):
    if globals.usb_detected_event.is_set():
        globals.usb_detected_event.clear()
        private_key_path = globals.usb_path_queue.get()
        update_sign_document_sidebar(sidebar, private_key_path, pendrive_label)
    root.after(1000, refresh_sidebar_if_usb_detected, root, sidebar, pendrive_label)  # Check every second

def update_sign_document_sidebar(sidebar, private_key_path, pendrive_label):
    #pendrive_label.configure(text="Type password")
    password_temp = create_entry(sidebar, placeholder_text="Enter PIN", row=2)
    create_button(sidebar, "check password", command=lambda: check_password(password_temp.get(), private_key_path, pendrive_label), row=3)
    create_button(sidebar, "Choose the document to be sign", command=lambda: sign_file(password_temp.get(), private_key_path, pendrive_label), row=4)

    create_label(sidebar, "Check signature", row=5)
    create_button(sidebar, "choose document", command=lambda: choose_the_document(), row=6)
    create_button(sidebar, "choose XML", command=lambda: choose_XML(), row=7)
    create_button(sidebar, "public key", command=lambda: choose_public_key(), row=8)
    create_button(sidebar, "Check signature", command=lambda: verify_signature(global_filepath, XMLpath, globals.public_key), row=9)

    create_empty_label(sidebar, row=2)
    create_empty_label(sidebar, row=3)
def encrypt(password):
    print("encrypt")
    pass


def decrypt(password):
    print("decrypt")
    # Functionality to decrypt using selected encrypted key and password
    pass




XMLpath = None
def choose_XML():
    global XMLpath
    XMLpath = filedialog.askopenfilename()
    print("XMLpath")

def choose_the_document():

    global global_filepath
    global_filepath = filedialog.askopenfilename()


def choose_public_key():
    globals.path_public_key = filedialog.askopenfilename()
    globals.public_key = load_public_key(globals.path_public_key)

def create_empty_label(parent, text="", row=0, column=0, padx=40, pady=(20, 10)):
    label = ctk.CTkLabel(parent, text=text)
    label.grid(row=row, column=column, padx=padx, pady=pady)
    return label


def create_sidebar(root, row, column, rowspan):
    sidebar = create_sidebar_frame(root, row, column, rowspan)
    label = create_label(sidebar, "Status", row=3)
    label.configure(text="Status")
    # Sidebar content
    create_label(sidebar, "Generator - ETAP 1", row=0)
    create_button(sidebar, "Generate private key and public key", command=lambda: generate_private_key_and_public(label, pin_entry.get()), row=2)
    pin_entry = create_entry(sidebar, placeholder_text="Enter PIN", row=1)


    create_empty_label(sidebar, row=5)

    return sidebar


def check_password(password, private_key_path, label):
    private_key, hasz = decrypt_key(password,private_key_path)
    if hasz.decode('utf-8')  == hashlib.sha256(password.encode()).hexdigest():
        label.configure(text="hasło poprawne")
        globals.correctPassword = True
    else:
        globals.correctPassword = False

def create_encryption_sidebar(root, row, column, rowspan):
    sidebar = create_sidebar_frame(root, row, column, rowspan, width=200)

    # Encryption content
    create_label(sidebar, "Encryption", row=0)
    create_button(sidebar, "Choose private key", command=choose_private_key, row=1)
    create_button(sidebar, "Choose the document to be Encripted", command=lambda: choose_the_document(), row=2)
    # entry_password = create_entry(sidebar, placeholder_text="Type password", show="*", row=2)
    # password_enc = entry_password.get()
    create_button(sidebar, "Encrypt", command=lambda: encrypt(), row=3)

    create_empty_label(sidebar, row=4)
    # Decryption content
    create_label(sidebar, "Decryption", row=5)
    create_button(sidebar, "Choose private key", command=choose_private_key, row=6)
    create_button(sidebar, "Choose the document to be Decrypted", command=lambda: choose_the_document(), row=7)
    # create_entry(sidebar, placeholder_text="Type password", show="*", row=7)
    # password_dec = entry_password.get()
    #create_button(sidebar, "Decrypt", command=lambda: decrypt(global_filepath, global_filepath + "dec", symmetric_key), row=8, padx=40, pady=(10,50))



def create_sign_document_sidebar(root, row, column, rowspan):
    sidebar = create_sidebar_frame(root, row, column, rowspan, width=200)
    create_label(sidebar, "Sign document", row=0)
    pendrive_label = create_label(sidebar, "Insert Pendrive", row=1, pady=(20, 10))
    refresh_sidebar_if_usb_detected(root, sidebar, pendrive_label)  # Start periodic check



