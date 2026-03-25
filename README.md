# DirCrypt

DirCrypt is a Python vault for encrypting directory trees in place while hiding original file and folder names.

It combines:

- Per-directory salted name hashing for metadata privacy
- Strong password-based key derivation via scrypt
- Authenticated file encryption with AES-256-GCM
- Optional post-quantum KEM (Kyber1024 via liboqs-python) for hybrid keying
- An interactive shell to navigate encrypted trees by typing original names

## Features

- Encrypt a whole folder tree recursively in place
- Hash every file and directory name using HMAC-SHA-512/256 with a random per-directory salt
- Encrypt each file into a `.enc` blob
- Create encrypted files and directories inside a vault from the interactive shell
- Open encrypted files for edit, then auto re-encrypt on close if content changed
- Keep directory salts in `.enc.salt`

## How It Works

### Name Privacy

Each directory contains a random 64-byte salt file: `.enc.salt`.

For every child entry, the original name is transformed as:

`hashed_name = HMAC_SHA512(salt, original_name)[:64 hex chars]`

This means:

- Equal names in different directories hash differently
- You cannot reverse names from disk without already knowing guesses

### File Encryption

For each file, DirCrypt stores a binary blob:

1. Magic header `VLTQ`
2. Optional KEM section (when liboqs is available)
3. 32-byte scrypt salt
4. 12-byte AES-GCM nonce
5. AES-GCM ciphertext + tag

If `liboqs-python` is installed, DirCrypt uses Kyber1024 to produce a shared secret and combines it with the password-derived key material before AES encryption.

If `liboqs-python` is not installed, it falls back to password-only AES-256-GCM + scrypt.

## Requirements

- Python 3.10+
- `cryptography`
- Optional: `liboqs-python` for Kyber1024 mode

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
# source .venv/bin/activate

pip install cryptography
# optional PQC mode
pip install liboqs-python
```

## Quick Start

Run the shell:

```bash
python shell.py
```

Inside the shell:

```text
encrypt C:\path\to\folder
cd C:\path\to\folder
ls
mkdir secrets
touch notes.txt
open notes.txt
```

The first `encrypt` command asks for a password and transforms the directory tree in place.

## Shell Commands

- `encrypt <path>`: Encrypt a directory tree recursively in place
- `cd <name>`: Enter a hashed subdirectory by typing the original name
- `cd ..`: Move up one directory
- `mkdir <name>`: Create a new hashed subdirectory
- `touch <name>`: Create an empty encrypted file
- `open <name>`: Decrypt to a temp file, open in editor, then re-encrypt if modified
- `ls`: List entries in current directory (hashed names shown)
- `pwd`: Show current working path
- `salt`: Print current directory salt in hex
- `help`: Show help
- `exit`, `quit`, `q`: Exit shell

## Notes

- Original names are not stored in recoverable form. You must remember names to navigate by them.
- `open` utilises the platform's default editor.
- Temp files are created for editing and then wiped/deleted on normal flow.
- Losing the password means losing access to encrypted data.
- This project currently provides encryption workflow and interactive access; full tree name-recovery decryption is not exposed as a user command.

## Security Notes

- Name hashing protects metadata but does not hide tree shape, file counts, or approximate sizes.
- scrypt parameters are currently `N=2^17, r=8, p=1`.
- Keep backups before first use. In-place encryption is destructive to original plaintext files.

## Project Layout

- `shell.py`: Interactive vault terminal
- `ops.py`: Recursive directory encryption operations
- `crypto.py`: Cryptographic primitives and blob forms