"""

    Author: vari.sh

    Description: This program is an utility to locally decrypt lsass.dmp files created with Doppelganger

"""

import sys

# XOR key used during encryption
XOR_KEY = b"0123456789abcdefghij"

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <xor_dump_path>")
        sys.exit(1)

    encrypted_path = sys.argv[1]
    output_path = encrypted_path + ".dec"

    try:
        with open(encrypted_path, "rb") as f:
            data = f.read()
    except IOError as e:
        print(f"[!] Failed to read file: {e}")
        sys.exit(1)

    decrypted = xor_decrypt(data, XOR_KEY)

    try:
        with open(output_path, "wb") as f:
            f.write(decrypted)
    except IOError as e:
        print(f"[!] Failed to write decrypted file: {e}")
        sys.exit(1)

    print(f"[+] Decryption successful. Output written to: {output_path}")

if __name__ == "__main__":
    main()
