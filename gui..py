import customtkinter
from tkinter import filedialog


def generate_private_key():
    entry.delete(0, customtkinter.END)
    entry.insert(0, "Private Key Generated")
    pass


def generate_public_key():
    entry.delete(0, customtkinter.END)
    entry.insert(0, "Public Key Generated")
    pass


def choose_private_key():
    filepath = filedialog.askopenfilename()
    # Functionality to handle selected file
    pass


def encrypt():
    # Functionality to encrypt using selected private key and password
    pass


def decrypt():
    print("decrypt")
    # Functionality to decrypt using selected encrypted key and password
    pass


def choose_file_to_sign():
    filepath = filedialog.askopenfilename()
    # Functionality to handle selected file to sign
    pass


customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()
root.title("BSK Electronic Signature by Krzysztof Madajczak 188674 and Piotr Wesołowski")
root.geometry("800x600")


# root.grid_columnconfigure(3, weight=0)
root.grid_rowconfigure(2, weight=1)
root_height = root.winfo_height()

sidebar_frame = customtkinter.CTkFrame(root, width=300, corner_radius=0)

sidebar_frame.grid(row=0, column=0, rowspan=3, sticky="nsew", padx=(25, 20))
sidebar_frame.grid_rowconfigure(4, weight=1)

logo_label = customtkinter.CTkLabel(sidebar_frame, text="Generator", font=customtkinter.CTkFont(size=20, weight="bold"))
logo_label.grid(row=0, column=0, padx=40, pady=(20, 10))

sidebar_button_1 = customtkinter.CTkButton(sidebar_frame, command=generate_private_key, text="Generate private key")
sidebar_button_1.grid(row=1, column=0, padx=40, pady=10)

sidebar_button_2 = customtkinter.CTkButton(sidebar_frame, command=generate_public_key, text="Generate public key")
sidebar_button_2.grid(row=2, column=0, padx=40, pady=10)

entry = customtkinter.CTkEntry(sidebar_frame)
entry.grid(row=3, column=0, padx=40, pady=10)

empty_label1 = customtkinter.CTkLabel(sidebar_frame, text=" ")
empty_label1.grid(row=4, column=0, padx=40, pady=(20, 10))

# Define the new sidebar_frame
sidebar_frame_encrypt = customtkinter.CTkFrame(root, width=200, corner_radius=0)
sidebar_frame_encrypt.grid(row=0, column=2, rowspan=8, sticky="nsew", padx=(20, 20))
sidebar_frame_encrypt.grid_rowconfigure(4, weight=1)

label_encrypt = customtkinter.CTkLabel(sidebar_frame_encrypt, text="Encryption", font=customtkinter.CTkFont(size=20, weight="bold"))
sidebar_button_encrypt = customtkinter.CTkButton(sidebar_frame_encrypt, command=generate_private_key, text="Choose private key")
entry_encrypt = customtkinter.CTkEntry(sidebar_frame_encrypt, placeholder_text="Type password", show="*")
button_encrypt = customtkinter.CTkButton(sidebar_frame_encrypt, text="Encrypt", command=encrypt)

empty_label = customtkinter.CTkLabel(sidebar_frame_encrypt, text=" ")

label_decrypt = customtkinter.CTkLabel(sidebar_frame_encrypt, text="Decryption", font=customtkinter.CTkFont(size=20))
sidebar_button_decrypt = customtkinter.CTkButton(sidebar_frame_encrypt, command=generate_private_key, text="Choose private key")
entry_decrypt = customtkinter.CTkEntry(sidebar_frame_encrypt, placeholder_text="Type password", show="*")
button_decrypt = customtkinter.CTkButton(sidebar_frame_encrypt, text="Decrypt", command=decrypt)

label_encrypt.grid(row=0, column=0, padx=40, pady=(20, 10))
sidebar_button_encrypt.grid(row=1, column=0, padx=40, pady=(50, 10))
entry_encrypt.grid(row=2, column=0, padx=40, pady=10)
button_encrypt.grid(row=3, column=0, padx=40, pady=(10, 50))


empty_label.grid(row=4, column=0)  # Adjust row and column as needed
label_decrypt.grid(row=5, column=0, padx=40, pady=(20, 10))
sidebar_button_decrypt.grid(row=6, column=0, padx=40, pady=10)
entry_decrypt.grid(row=7, column=0, padx=40, pady=10)
button_decrypt.grid(row=8, column=0, padx=40, pady=(10, 50))


sidebar_frame_sign = customtkinter.CTkFrame(root, width=200, corner_radius=0)

sidebar_frame_sign.grid(row=0, column=3, rowspan=3, sticky="nsew", padx=(20, 20))
sidebar_frame_sign.grid_rowconfigure(4, weight=1)

logo_label_sign = customtkinter.CTkLabel(sidebar_frame_sign, text="Sign document", font=customtkinter.CTkFont(size=20, weight="bold"))
logo_label_sign.grid(row=0, column=0, padx=40, pady=(20, 10))

logo_label_sign = customtkinter.CTkLabel(sidebar_frame_sign, text="Insert Pendrive", font=customtkinter.CTkFont(size=20, weight="bold"))
logo_label_sign.grid(row=1, column=0, padx=40, pady=(20, 10))
pendrive = False
if pendrive:
    logo_label_sign.text = "Pendrive Inside"

    sidebar_button_sign_1 = customtkinter.CTkButton(sidebar_frame_sign, command=generate_private_key, text="Choose the document to be sign")
    sidebar_button_sign_1.grid(row=2, column=0, padx=40, pady=10)

    sidebar_button_sign_2 = customtkinter.CTkButton(sidebar_frame_sign, command=generate_public_key, text="Generate public key")
    sidebar_button_sign_2.grid(row=3, column=0, padx=40, pady=10)

    empty_label1 = customtkinter.CTkLabel(sidebar_frame_sign, text=" ")
    empty_label1.grid(row=4, column=0, padx=40, pady=(20, 10))

root.mainloop()
#
# # Create main window
# root = tk.Tk()
# root.title("My GUI")
# root.geometry("1280x720")
# # First row: Generate private key button
# button_style = {'background': 'lightblue', 'foreground': 'black', 'font': ('Arial', 12)}
# generate_button = tk.Button(root, text="Generate private key", command=generate_private_key)
# generate_button.configure(**button_style)
# generate_button.grid(row=0, column=0)
#
# # Second row: Choose private key, Password textbox, Encrypt button
# choose_button = tk.Button(root, text="Choose private key", command=choose_private_key)
# choose_button.grid(row=1, column=0)
#
# password_entry = tk.Entry(root)
# password_entry.grid(row=1, column=1)
#
# encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
# encrypt_button.grid(row=1, column=2)
#
# # Third row: Choose encrypted key, Password textbox, Decrypt button
# choose_encrypted_key_entry = tk.Entry(root)
# choose_encrypted_key_entry.grid(row=2, column=0)
#
# password_decrypt_entry = tk.Entry(root)
# password_decrypt_entry.grid(row=2, column=1)
#
# decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
# decrypt_button.grid(row=2, column=2)
#
# # Fourth row: Choose file to signature, Insert pendrive text, Password textbox
# choose_file_button = tk.Button(root, text="Choose file to signature", command=choose_file_to_sign)
# choose_file_button.grid(row=3, column=0)
#
# insert_pendrive_text_entry = tk.Entry(root)
# insert_pendrive_text_entry.grid(row=3, column=1)
#
# password_signature_entry = tk.Entry(root)
# password_signature_entry.grid(row=3, column=2)
#
# root.mainloop()
