'''
1.Prompt the user for their Master Password
2.Generate a secret key using Master Password
3.Store credentials; site,username,password on a local file
4.Encrypt passwords
5.Decrypt passwords (only when vault is unlocked)
'''
#Import OS module allows script interaction with file system
import os

#Import Json for encrypted vault files
import json

#Import base64 (Encodes binary data into ASCII text safely)
import base64

#Import hmac and hashlib for hashing and validation
import hmac, hashlib

#Imports Key Derivation Funcion(KDF) from primitives
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Imports hash algorithms (SHA256) 
from cryptography.hazmat.primitives import hashes

#Import Fernet and invalid token
from cryptography.fernet import Fernet, InvalidToken

#Import getpass() to handle user password input securely
from getpass import getpass

#Import Dict, Any
from typing import Dict, Any

SALT_FILE = "vault.salt"
VERIFIER_FILE = "vault.verifier"
VAULT_FILE = "vault.enc"
ITERATIONS = 390_000
CHECK_BYTES = b"vault-check-v1"

#Load or generate random salt for consistant secure key generation
def load_or_create_salt(path: str = SALT_FILE) -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(path, "wb") as f:
        f.write(salt)
    return salt

'''
NOTE:If ran from IDLE will show password as typed.
Getpass will work ran from terminal
'''

#Generate 32-byte encryption key from master password
def generate_Key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),    #Defines the Hash algorithm used
        length = 32,    #Defines length of the key 32bytes = 256bits
        salt = salt,    #Adds bytes so identical passwords generate dif keys
        iterations = ITERATIONS,    #Hash count more is good for brute force def.
    )
    #Encodes password string into bytes, derives key, encodes key into base64
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

#Create/Verify a login check.
#First run creates verifier and returns True.
#Future runs validate with stored key
def ensure_verifier(key_bytes: bytes) -> bool:
    digest = hmac.new(key_bytes, CHECK_BYTES, hashlib.sha256).digest()
    if os.path.exists(VERIFIER_FILE):
        with open(VERIFIER_FILE, "rb") as f:
            stored = f.read()
        return hmac.compare_digest(stored, digest)
    else:
        with open(VERIFIER_FILE, "wb") as f:
            f.write(digest)
        return True
    
#Load and decrypt the vault
def load_vault(fernet: Fernet) -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        ciphertext = f.read()
    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken:
        raise RunTimeError("Vault file is corrupted or the wrong key was used.")
    return json.loads(plaintext.decode("utf-8"))

#Saving the Vault
def save_vault(fernet: Fernet, data: Dict[str, Dict[str, Any]]) -> None:
    plaintext = json.dumps(data, indent=2).encode("utf-8")
    ciphertext = fernet.encrypt(plaintext)
    with open(VAULT_FILE, "wb") as f:
        f.write(ciphertext)

#Create the Menu actions
def prompt_nonempty(label: str) -> str:
    while True:
        val = input(label).strip()
        if val:
            return val
        print("Please enter a value.")

def add_entry(vault: Dict[str, Dict[str, Any]]) -> None:
    name = prompt_nonempty("Entry name (e.g., 'Gmail'): ")
    if name in vault:
        print("An entry with that name already exists, choose another or delete.")
        return
    username = prompt_nonempty("Username: ")
    password = getpass("Password (hidden): ")
    note = input("Optional Notes: ").strip()
    vault[name] = {"username": username, "password": password, "note": note}
    print(f"Added '{name}'.")

def list_entries(vault: Dict[str, Dict[str, Any]]) -> None:
    if not vault:
        print("(The Vault is Empty)")
        return
    print("Entries:")
    for name in sorted(vault.keys()):
        print(" -", name)

def get_entry(vault: Dict[str, Dict[str, Any]]) -> None:
    name = prompt_nonempty("Entry to view: ")
    item = vault.get(name)
    if not item:
        print("No entry listed.")
        return
    print(f"\n[{name}]")
    print("Username:", item.get("username", ""))
    print("Password:", item.get("password", ""))
    note = item.get("note", "")
    if note:
        print("Note:", note)
    print("")

def delete_entry(vault: Dict[str, Dict[str, Any]]) -> None:
    name = prompt_nonempty("Which entry would you like to delete?")
    if name not in vault:
        print("Entry not listed.")
        return
    confirm = input(f"Type DELETE to confirm removal of, '{name}': ").strip()
    if confirm == "DELETE":
        del vault[name]
        print(f"Entry, '{name}', deleted!")
    else:
        print("Canceled.")

#Create the Menu loop / Visual loads and saves changes
def menu_loop(fernet: Fernet) -> None:
    vault = load_vault(fernet)
    while True:
        print("\n=== Credential Vault Menu ===")
        print("[1] Add Entry")
        print("[2] List Entries")
        print("[3] Get Entry")
        print("[4] Delete Entry")
        print("[0] Lock Vault & Exit")
        choice = input("Make a selection: ").strip()

        if choice == "1":
            add_entry(vault)
            save_vault(fernet, vault)
        elif choice == "2":
            list_entries(vault)
        elif choice == "3":
            get_entry(vault)
        elif choice == "4":
            delete_entry(vault)
            save_vault(fernet, vault)
        elif choice == "0":
            save_vault(fernet, vault)
            print("Saved & Locked, Goodbye!")
            return
        else:
            print("That is an invalid selection.")
            
#Prompt for Master Password entry into the Vault
def main():
    master_password = getpass("Enter your Master Password: ")
    print("You entered:", "*" * len(master_password))

    salt = load_or_create_salt()
    key = generate_Key(master_password, salt)
    attempts = 0
    max_attempts = 4

#Validate key with Master Password, close after 4 failed attempts
    while True:
        if ensure_verifier(key):
           print("Your Vault has been Unlocked!")
           break
        else:
            attempts += 1
            print("Master Password is incorrect!")
            if attempts >= max_attempts:
                print("You have too many failed attempts. Exiting program!")
                return
            master_password = getpass("Try again: ")
            key = generate_Key(master_password, salt)

    fernet = Fernet(key)

    try:
        menu_loop(fernet)
    except RunTimeError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
