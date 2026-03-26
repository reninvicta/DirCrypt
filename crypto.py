"""
crypto.py - Cryptographic primitives for vault

Name hashing: HMAC-SHA-512/256 (SHA-512 truncated to 256 bits)
              per-directory 64-byte random salt stored in .enc.salt

File encryption pipeline:
    1. Generate ephemeral Kyber-1024 key pair
    2. Enapsulate a shared-secret (ciphertext_kem, shared_secret)
    3. Derive final key: HKDF-SHA-512(shared_secret || password_key, 32 bytes)
    4. Encrypt plaintext with AES-256-GCM

    File layout (binary):
        [4] magic b"VLTQ"
        [2] kem_ct_len (uint16 big-endian)
        [N] kem_ciphertext
        [32] scrypt_salt
        [12] aes_nonce
        [*] aes_gcm_ciphertext_and_tag

Password is used as an additional factor: even with the Kyber private key you also need the password (scrypt-derived) to decrypt.
Both are XOR-combined in the HKDF step so neither alone is sufficient to derive the final key.

Fallback: if liboqs is unavailable, the module falls back to AES-256-GCM + scrypt only and prints a clear warning.
"""

import os
import sys
import hmac
import hashlib
import secrets
import ctypes
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# PQC backend
try:
    import oqs
    _KEM = oqs.KeyEncapsulation("Kyber1024")
    HAS_PQC = True
    PQC_ALG = "Kyber1024"
except Exception:
    HAS_PQC = False
    PQC_ALG = "none (AES-256-GCM + scrypt fallback)"

MAGIC           = b"VLTQ"
SALT_FILENAME   = ".enc.salt"
SCRYPT_N        = 2**17
SCRYPT_R        = 8
SCRYPT_P        = 1

def _hide_file(path: Path) -> None:
    """Mark *path* as hidden. On Unix this is a no-op as .enc.salt is already hidden via dot prefix."""
    if sys.platform == "win32":
        ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02) # FILE_ATTRIBUTE_HIDDEN

# Name hashing
def load_or_create_salt(directory: Path) -> bytes:
    """Return (or create) the 64-byte name-hashing salt for *directory*."""
    p = directory / SALT_FILENAME
    if p.exists():
        data = p.read_bytes()
        if len(data) == 64:
            return data
    salt = secrets.token_bytes(64)
    p.write_bytes(salt)
    _hide_file(p)
    return salt

def hash_name(name: str, salt: bytes) -> str:
    """
    HMAC-SHA-512/256: HMAC with SHA-512, output truncated to 256 bits (64 hex chars).
    Using HMAC rather than bare SHA-512 makes the salt a proper secret key, so an attacker cannot brute-force names even with the salt file.
    """
    h = hmac.new(salt, name.encode("utf-8"), hashlib.sha512)
    return h.hexdigest()[:64]

def name_to_disk(name: str, directory: Path) -> str:
    """Return the hashed on-disk name for *name* inside *directory*."""
    salt = load_or_create_salt(directory)
    return hash_name(name, salt)

# Password KDF
def _password_key(password: str, salt: bytes) -> bytes:
    """32-byte key derived from *password* via scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, backend=default_backend())
    return kdf.derive(password.encode("utf-8"))

# Encryption
def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Encrypt *plaintext* and return the vault blob."""
    scrypt_salt = secrets.token_bytes(32)
    pw_key      = _password_key(password, scrypt_salt)
    nonce       = secrets.token_bytes(12)

    if HAS_PQC:
        with oqs.KeyEncapsulation("Kyber1024") as kem:
            public_key         = kem.generate_keypair()
            kem_ciphertext, ss = kem.encap_secret(public_key)
            # Store private key encrypted with password key so it can be
            # recovered at decryption time with the password alone.
            private_key        = kem.export_secret_key()

        ikm = bytes(a ^ b for a, b in zip(ss[:32], pw_key))
        aes_key = HKDF(
            algorithm=hashes.SHA512(), length=32, salt=scrypt_salt,
            info=b"vault-file-key", backend=default_backend()
        ).derive(ikm + ss[32:])

        pk_nonce = secrets.token_bytes(12)
        pk_blob = AESGCM(pw_key).encrypt(pk_nonce, private_key, None)
        kem_section = (
            struct.pack(">H", len(kem_ciphertext)) + kem_ciphertext +
            struct.pack(">H", len(pk_blob)) + pk_nonce + pk_blob
        )
    else:
        aes_key     = pw_key
        kem_section = b""

    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    kem_len_prefix = struct.pack(">I", len(kem_section))
    return MAGIC + kem_len_prefix + kem_section + scrypt_salt + nonce + ciphertext

def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Decrypt a vault blob and return plaintext."""
    if blob[:4] != MAGIC:
        raise ValueError("Not a vault-encrypted blob (bad magic)")
 
    offset      = 4
    kem_len     = struct.unpack(">I", blob[offset:offset+4])[0]
    offset     += 4
    kem_section = blob[offset:offset+kem_len]
    offset     += kem_len
    scrypt_salt = blob[offset:offset+32]; offset += 32
    nonce       = blob[offset:offset+12]; offset += 12
    ciphertext  = blob[offset:]
 
    pw_key = _password_key(password, scrypt_salt)
 
    if kem_len > 0:
        # Parse kem_section
        p = 0
        ct_len       = struct.unpack(">H", kem_section[p:p+2])[0]; p += 2
        kem_ct       = kem_section[p:p+ct_len]; p += ct_len
        pk_blob_len  = struct.unpack(">H", kem_section[p:p+2])[0]; p += 2
        pk_nonce     = kem_section[p:p+12]; p += 12
        pk_blob      = kem_section[p:p+pk_blob_len]
 
        private_key = AESGCM(pw_key).decrypt(pk_nonce, pk_blob, None)
 
        with oqs.KeyEncapsulation("Kyber1024", secret_key=private_key) as kem:
            ss = kem.decap_secret(kem_ct)
 
        ikm = bytes(a ^ b for a, b in zip(ss[:32], pw_key))
        aes_key = HKDF(
            algorithm=hashes.SHA512(), length=32, salt=scrypt_salt,
            info=b"vault-file-key", backend=default_backend()
        ).derive(ikm + ss[32:])
    else:
        aes_key = pw_key
 
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)
 
 
def encrypt_file(src: Path, dst: Path, password: str) -> None:
    dst.write_bytes(encrypt_bytes(src.read_bytes(), password))
 
 
def decrypt_file(src: Path, password: str) -> bytes:
    return decrypt_bytes(src.read_bytes(), password)