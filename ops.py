"""
ops.py - Encrypt / decrypt directory trees.

Encryption:
    - Walk the tree bottom-up.
    - Each directory gets its own .enc.salt (64 bytes, random)
    - Every entry (file or subdir) is renamed to HMAC-SHA-512/256(name, salt)
    - Every file gets a .enc extension appended after hashing
    - File contents are encrypted with the Kyber+AES pipeline in crypto.po

Decryption requires the user to KNOW the original names of the files and directories. The terminal shell (shell.py) hashes whatever name is given using the CWD salt and looks it up.
"""

from __future__ import annotations
import sys
from pathlib import Path
from typing import Callable

from crypto import (
    load_or_create_salt,
    hash_name,
    encrypt_file,
    decrypt_file,
    SALT_FILENAME,
)

ENC_EXT = ".enc"

def _log(msg: str, verbose: bool) -> None:
    if verbose:
        print(msg)

# Encrypt
def encrypt_directory(
        target:Path,
        password:str,
        verbose:bool=True,
        _progress:Callable[[str], None]|None=None,
) -> None:
    """Encrypt *target* in-place, recursively."""
    target = target.resolve()
    if not target.is_dir():
        raise NotADirectoryError(target)
    
    salt = load_or_create_salt(target)

    entries = [e for e in sorted(target.iterdir()) if e.name != SALT_FILENAME]

    for entry in entries:
        hashed = hash_name(entry.name, salt)

        if entry.is_dir():
            encrypt_directory(entry, password, verbose, _progress) # Recurse
            new_path = entry.parent / hashed
            entry.rename(new_path)
            msg = f"  DIR  {entry.name!r} -> {hashed}"
        elif entry.is_file():
            enc_name = hashed + ENC_EXT
            new_path = entry.parent / enc_name
            encrypt_file(entry, new_path, password)
            entry.unlink() # Remove original plaintext file
            msg = f"  FILE {entry.name!r} -> {enc_name}"
        else:
            continue

        _log(msg, verbose)
        if _progress:
            _progress(msg)

# Decrypt
def decrypt_single_file(enc_path: Path, password: str) -> bytes:
    """Decrypt one .enc file and return the plaintext bytes."""
    return decrypt_file(enc_path, password)

def _decrypt_directory_known_names(
        target: Path,
        password: str,
        name_map: dict[str, str], # hashed_name -> original_name
        verbose: bool = True,
) -> None:
    """
    Internal: Decrypt *target* given a pre-built name map for this level.
    Used by decrypt_directory_full which asks the user for every original name.
    """
    for hashed_name, original_name in name_map.items():
        entry = target / hashed_name
        if not entry.exists():
            _log(f"  [!]  {hashed_name!r} not found - skipping", verbose)
            continue

        if entry.is_dir():
            restored = entry.parent / original_name
            entry.rename(restored)
            _log(f"  DIR  {hashed_name!r} -> {original_name!r}", verbose)

        elif entry.is_file() and entry.suffix == ENC_EXT:
            plaintext = decrypt_file(entry, password)
            restored  = entry.parent / original_name
            restored.write_bytes(plaintext)
            entry.unlink()
            _log(f"  FILE {hashed_name!r} -> {original_name!r}", verbose)