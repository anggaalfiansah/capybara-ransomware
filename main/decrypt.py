import pathlib
import os
import base64

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def generate_key(password=123):
    salt = b"raja capybara agung"
    derived_key = derive_key(salt, str(password))
    return base64.urlsafe_b64encode(derived_key)

def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Invalid token, most likely the password is incorrect")
        return
    # create the decrypted file name
    decrypted_filename = str(filename).rsplit(".capybara", 1)[0]
    # write the original file
    with open(decrypted_filename, "wb") as file:
        file.write(decrypted_data)
    # remove the encrypted file
    os.remove(filename)
    print(f"Decrypted {filename} to {decrypted_filename}")

def decrypt_folder(folder="./", key=generate_key(123)):
    # if it's a folder, decrypt the entire folder
    for child in pathlib.Path(folder).glob("*"):
        if child.is_file():
            if (
                child.name == "capybara-encrypt.exe" or child.name == "capybara-decrypt.exe"
            ):  # Skip file with specific name "salt.xxx"
                print(f"[!] Skipping {child}")
            else:
                print(f"[*] Decrypting {child}")
                # encrypt the file
                decrypt(child, key)
        elif child.is_dir():
            # if it's a folder, decrypt the entire folder by calling this function recursively
            decrypt_folder(child, key)

decrypt_folder()
