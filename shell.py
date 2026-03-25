"""
shell.py - Interactive vault terminal

Commands:
    encrypt <path>      Encrypt a directory tree in-place
    decrypt <file>      Decrypt a .enc file to a temp location and open it
    cd <name>           Hash <name> with current salt -> navigate there
    cd ..               Navigate up one directory
    open <name>         Hash <name> with current salt -> decrypt and open
    ls                  List current directory (hashed names only)
    pwd                 Print current directory
    salt                Print current directory's salt (hex)
    help                Print this message
    exit / quit         Exit the shell

Navigation works by typing the original name. The shell hashes it with the current directory's .enc.salt to find the actual on-disk path.
"""

from __future__ import annotations

import os
import sys
import shlex
import getpass
import platform
import tempfile
import hashlib
import subprocess
import textwrap
from pathlib import Path

from crypto import (
    hash_name,
    load_or_create_salt,
    decrypt_bytes,
    encrypt_bytes,
    HAS_PQC,
    PQC_ALG,
    SALT_FILENAME,
)
from ops import encrypt_directory, ENC_EXT

_COLOUR = sys.stdout.isatty() or platform.system() != "Windows"

def _c(code: str, text: str) -> str:
    if not _COLOUR:
        return text
    CODES = {
        "green":  "\033[32m",
        "cyan":   "\033[36m",
        "yellow": "\033[33m",
        "red":    "\033[31m",
        "bold":   "\033[1m",
        "dim":    "\033[2m",
        "reset":  "\033[0m",
    }

    return CODES.get(code, "") + text + CODES["reset"]

BANNER = r"""
________  .__        _________                        __   
\______ \ |__|______ \_   ___ \_______ ___.__._______/  |_ 
 |    |  \|  \_  __ \/    \  \/\_  __ <   |  |\____ \   __\
 |    `   \  ||  | \/\     \____|  | \/\___  ||  |_> >  |  
/_______  /__||__|    \______  /|__|   / ____||   __/|__|  
        \/                   \/        \/     |__|         
"""

class VaultShell:
    def __init__(self):
        self.cwd: Path | None = None
        self.password: str = ""
        self._history: list[str] = []

    def _prompt(self) -> str:
        if self.cwd is None:
            return _c("Green", "vault") + _c("dim", ":~") + _c("bold", "$ ")
        short = "../" + self.cwd.name if len(str(self.cwd)) > 40 else str(self.cwd)
        return _c("green", "vault") + _c("dim", f":{short}") + _c("bold", "$ ")
    
    def _print(self, msg: str = "") -> None:
        print(msg)

    def _err(self, msg:str) -> None:
        print(_c("red", "[ERR] ") + msg)

    def _ok(self, msg:str) -> None:
        print(_c("green", "[OK] ") + msg)

    def _info(self, msg:str) -> None:
        print(_c("cyan", "[INFO] ") + msg)

    def _resolve_name(self, name: str, directory: Path | None = None) -> Path | None:
        """
        Hash *name* with the salt in *directory* (default: self.cwd)
        and return the resulting path if it exists, else None.
        """
        d = directory or self.cwd
        if d is None:
            return None
        salt   = load_or_create_salt(d)
        hashed = hash_name(name, salt)
        # Check as directory
        as_dir = d / hashed
        if as_dir.is_dir():
            return as_dir
        # Check as encrypted file
        as_file = d / (hashed + ENC_EXT)
        if as_file.is_file():
            return as_file
        return None
 
    def _open_file(self, path: Path, original_name: str) -> None:
        """Decrypt *path*, open synchronously, re-encrypt if modified, wipe temp."""
        if not self.password:
            self.password = getpass.getpass("  Password: ")

        try:
            plaintext = decrypt_bytes(path.read_bytes(), self.password)
        except Exception as e:
            self._err(f"Decryption failed: {e}")
            return

        tmp_dir  = Path(tempfile.mkdtemp(prefix="vault_"))
        tmp_dir.chmod(0o700)
        tmp_file = tmp_dir / original_name
        tmp_file.write_bytes(plaintext)
        tmp_file.chmod(0o600)

        hash_before = hashlib.sha256(plaintext).digest()

        system = platform.system()
        try:
            if system == "Windows":
                editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "notepad.exe"
                subprocess.run([editor, str(tmp_file)])
            elif system == "Darwin":
                editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
                if editor:
                    subprocess.run([editor, str(tmp_file)])
                else:
                    subprocess.run(["open", "-W", str(tmp_file)])
            else:
                editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "xdg-open"
                subprocess.run([editor, str(tmp_file)])
        except Exception as e:
            self._err(f"Could not open file: {e}")
            self._info(f"Open manually: {tmp_file}")
            return

        new_contents = tmp_file.read_bytes()
        hash_after   = hashlib.sha256(new_contents).digest()

        if hash_before != hash_after:
            try:
                path.write_bytes(encrypt_bytes(new_contents, self.password))
                self._ok("Changes encrypted and written back.")
            except Exception as e:
                self._err(f"Write-back failed: {e}")
                self._info(f"Temp file preserved at: {tmp_file}")
                return
        else:
            self._info("No changes detected, skipping write-back.")

        # Secure wipe
        try:
            tmp_file.write_bytes(os.urandom(len(new_contents)))
            tmp_file.unlink()
            tmp_dir.rmdir()
        except Exception as e:
            self._err(f"Temp cleanup failed: {e}")
 
    # ── commands ──────────────────────────────────────────────────────────────
 
    def cmd_help(self, _args: list[str]) -> None:
        self._print(_c("bold", textwrap.dedent(f"""
  Commands
  ────────
  encrypt <path>    Encrypt a directory tree in-place
  cd <name>         Navigate into a directory (type the ORIGINAL name)
  cd ..             Go up one directory
  touch <name>      Create an empty encrypted file with the given name
  mkdir <name>      Create a new subdirectory (type the ORIGINAL name)
  open <name>       Decrypt & open a file (type the ORIGINAL name)
  ls                List hashed entries in current directory
  pwd               Show current directory path
  salt              Show current directory's name-hashing salt (hex)
  help              Show this help
  exit / quit       Exit
 
  Encryption info
  ───────────────
  Name hashing : HMAC-SHA-512/256  (per-directory 64-byte random salt)
  File crypto  : {PQC_ALG} + AES-256-GCM + scrypt(N=2¹⁷)
  PQC active   : {'yes ✓' if HAS_PQC else 'no – install liboqs-python'}
""")))
 
    def cmd_encrypt(self, args: list[str]) -> None:
        if not args:
            self._err("Usage: encrypt <directory>"); return
        target = Path(args[0]).expanduser().resolve()
        if not target.is_dir():
            self._err(f"Not a directory: {target}"); return
 
        pw  = getpass.getpass("  Password       : ")
        pw2 = getpass.getpass("  Confirm        : ")
        if pw != pw2:
            self._err("Passwords do not match."); return
 
        self.password = pw
        self._info(f"Encrypting {target} …")
        try:
            encrypt_directory(target, pw, verbose=True)
            self._ok("Encryption complete.")
            self._info(f"Navigate into it:  cd {target}")
            self.cwd = target
        except Exception as e:
            self._err(str(e))

    def cmd_mkdir(self, args: list[str]) -> None:
        if not args:
            self._err("Usage: mkdir <name>"); return
        if self.cwd is None:
            self._err("Not inside a vault directory. Use cd first."); return

        name = args[0]
        salt   = load_or_create_salt(self.cwd)
        hashed = hash_name(name, salt)

        target = self.cwd / hashed
        if target.exists():
            self._err(f"'{name}' already exists."); return

        target.mkdir()
        # Initialise a fresh salt for the new subdirectory
        load_or_create_salt(target)
        self._ok(f"Directory '{name}' created.")
        self._info(f"→ {hashed}")

    def cmd_touch(self, args: list[str]) -> None:
        if not args:
            self._err("Usage: touch <filename>"); return
        if self.cwd is None:
            self._err("Not inside a vault directory. Use cd first."); return
        if not self.password:
            self.password = getpass.getpass("  Password: ")

        name = args[0]
        salt   = load_or_create_salt(self.cwd)
        hashed = hash_name(name, salt)
        target = self.cwd / (hashed + ENC_EXT)

        if target.exists():
            self._err(f"'{name}' already exists."); return

        target.write_bytes(encrypt_bytes(b"", self.password))
        self._ok(f"File '{name}' created.")
        self._info(f"→ {hashed + ENC_EXT}")
 
    def cmd_cd(self, args: list[str]) -> None:
        if not args:
            self._err("Usage: cd <name>  or  cd .."); return
        name = args[0]
 
        if name == "..":
            if self.cwd is None:
                self._err("Not inside a vault directory."); return
            self.cwd = self.cwd.parent
            self._info(f"→ {self.cwd}")
            return
 
        if name == ".":
            return  # no-op
 
        # Allow absolute / relative paths as the initial entry point
        explicit = Path(name).expanduser()
        if explicit.is_dir() and self.cwd is None:
            # First entry: set cwd without hashing
            self.cwd = explicit.resolve()
            self._info(f"→ {self.cwd}")
            return
 
        if self.cwd is None:
            # Try as an absolute/relative path directly
            if explicit.is_dir():
                self.cwd = explicit.resolve()
                self._info(f"→ {self.cwd}")
                return
            self._err("Not inside a vault yet. Use: cd <absolute-or-relative-path>")
            return
 
        resolved = self._resolve_name(name)
        if resolved is None:
            salt = load_or_create_salt(self.cwd)
            h    = hash_name(name, salt)
            self._err(
                f"'{name}' not found in current directory.\n"
                f"    (hashed to {h[:16]}…)"
            )
            return
        if not resolved.is_dir():
            self._err(f"'{name}' is a file, not a directory. Use: open {name}")
            return
 
        self.cwd = resolved
        self._info(f"→ {self.cwd}")
 
    def cmd_open(self, args: list[str]) -> None:
        if not args:
            self._err("Usage: open <filename>"); return
        name = args[0]
 
        if self.cwd is None:
            self._err("Not inside a vault directory. Use cd first."); return
 
        if not self.password:
            self.password = getpass.getpass("  Password: ")
 
        resolved = self._resolve_name(name)
        if resolved is None:
            salt = load_or_create_salt(self.cwd)
            h    = hash_name(name, salt)
            self._err(
                f"'{name}' not found.\n"
                f"    (hashed to {h[:16]}…)"
            )
            return
        if resolved.is_dir():
            self._err(f"'{name}' is a directory. Use: cd {name}")
            return
 
        self._open_file(resolved, name)
 
    def cmd_ls(self, _args: list[str]) -> None:
        if self.cwd is None:
            self._err("Not inside a vault directory."); return
        entries = sorted(self.cwd.iterdir())
        if not entries:
            self._info("(empty)"); return
        for e in entries:
            kind = _c("cyan",   "DIR ") if e.is_dir() else _c("yellow", "FILE")
            if e.name == SALT_FILENAME:
                kind = _c("dim", "SALT")
            print(f"  {kind}  {e.name}")
 
    def cmd_pwd(self, _args: list[str]) -> None:
        self._info(str(self.cwd) if self.cwd else "(not set)")
 
    def cmd_salt(self, _args: list[str]) -> None:
        if self.cwd is None:
            self._err("Not inside a vault directory."); return
        salt = load_or_create_salt(self.cwd)
        self._info(f"Salt ({len(salt)} bytes): {salt.hex()}")
 
    # ── REPL ──────────────────────────────────────────────────────────────────
 
    COMMANDS = {
        "help":    cmd_help,
        "encrypt": cmd_encrypt,
        "cd":      cmd_cd,
        "open":    cmd_open,
        "mkdir":   cmd_mkdir,
        "touch":   cmd_touch,
        "ls":      cmd_ls,
        "pwd":     cmd_pwd,
        "salt":    cmd_salt,
    }
 
    def run(self) -> None:
        print(_c("bold", BANNER))
        print(_c("cyan",
            f"  HMAC-SHA-512/256 name hashing  |  "
            f"PQC: {'Kyber-1024 ✓' if HAS_PQC else 'inactive – pip install liboqs-python'}"
        ))
        print(_c("dim", "  Type 'help' for commands.\n"))
 
        while True:
            try:
                line = input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
 
            if not line:
                continue
 
            try:
                tokens = shlex.split(line)
            except ValueError as e:
                self._err(str(e))
                continue
 
            cmd, *args = tokens
            cmd = cmd.lower()
 
            if cmd in ("exit", "quit", "q"):
                break
 
            handler = self.COMMANDS.get(cmd)
            if handler is None:
                self._err(f"Unknown command: {cmd!r}. Type 'help'.")
            else:
                try:
                    handler(self, args)
                except Exception as e:
                    self._err(f"Unexpected error: {e}")
 
        print(_c("dim", "\n  goodbye.\n"))
 
 
def main() -> None:
    VaultShell().run()
 
 
if __name__ == "__main__":
    main()