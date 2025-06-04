import sys

def extract_all_tickets(input_file):
    with open(input_file, 'rb') as f:
        data = f.read()

    i = 0
    count = 0
    while i < len(data) - 4:
        if data[i] == 0x76 and data[i+1] == 0x82:  # Application 22 (Kerberos ticket) + 2-byte length
            length = (data[i+2] << 8) | data[i+3]
            end = i + 4 + length
            if end <= len(data):
                candidate = data[i:end]
                if b'krbtgt' in candidate:
                    filename = f'ticket_{count}.kirbi'
                    with open(filename, 'wb') as out:
                        out.write(candidate)
                    print(f"[✓] Ticket found and extracted: {filename}")
                    count += 1
                    i = end
                    continue
        i += 1

    if count == 0:
        print("[X] No valid tickets found.")
    else:
        print(f"[✓] Total tickets extracted: {count}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python raw_TGT_extractor_win11.py <dumpfile>")
    else:
        extract_all_tickets(sys.argv[1])
