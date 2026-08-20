# Credential Vault

Credential Vault is a command-line password manager written in Python. It stores
website credentials in an encrypted local vault protected by a master password.

## Features

- Derives an encryption key from the master password with PBKDF2-HMAC-SHA256.
- Encrypts vault data with Fernet before writing it to disk.
- Stores an entry name, username, password, and optional note.
- Lists entry names without displaying their credentials.
- Lets you view or delete individual entries.
- Locks and saves the vault when you exit.
- Allows up to four failed unlock attempts.

## Requirements

- Python 3
- The `cryptography` package

Install the dependency with:

```bash
python3 -m pip install cryptography
```

## Run

From this project directory, run:

```bash
python3 Credential_Vault.py
```

On the first run, enter a master password. That password creates the key used to
unlock and encrypt the vault. On later runs, enter the same password to access
your saved entries.

## Menu

After unlocking the vault, choose an action from the menu:

| Option | Action |
| --- | --- |
| `1` | Add an entry with a username, hidden password, and optional note |
| `2` | List saved entry names |
| `3` | View an entry's username, password, and note |
| `4` | Delete an entry after typing `DELETE` to confirm |
| `0` | Save, lock the vault, and exit |

## Files

The program creates these files in its working directory:

- `vault.enc`: encrypted credential data
- `vault.salt`: random salt used for key derivation
- `vault.verifier`: encrypted-key verification data used during unlock

Keep all three files together. Losing `vault.salt` or `vault.verifier` prevents
the existing vault from being unlocked. Do not delete or share these files unless
you intend to remove or copy the vault.

## Security Notes

- Use a strong, unique master password. It cannot be recovered if forgotten.
- Run the program from a trusted terminal and protect access to the project
	directory and its backup copies.
- The password is hidden while it is entered through a terminal using `getpass`.
- The password is displayed when you choose `Get Entry`, so avoid using that
	option where the screen may be observed.
