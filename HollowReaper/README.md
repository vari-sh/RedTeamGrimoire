# 💀 HollowReaper - Hollow the Living, Control the Void
HollowReaper is a mystical tool crafted to manipulate processes through Process Hollowing, allowing seamless injection of custom shellcode into a legitimate process. This arcane art lets you erase a process’s soul and replace it with your own will.

![hollowreaper](https://github.com/user-attachments/assets/fdfa66ff-97b2-4860-a4c3-c022cde5095a)

## 📜 The Ritual
### 💀 HollowReaper.c
The vessel for your payload. This program performs process hollowing, carving out a legitimate process and injecting your shellcode into its husk.

### 🧬 LSASS_CDumper.c
The soul binder. This shellcode:

🛡️ Disables PPL using the cursed RTCore64.sys driver (BYOVD)

🚫 Disables Credential Guard using forbidden kernel incantations

💾 Extracts a Minidump from LSASS memory

### 🗝️ xor20charkey.py
A local obfuscation utility. XOR-encrypts the shellcode using a custom 20-character key, shielding your payload from watchful eyes.

### 📦 RTCore64.sys
A vulnerable driver — the ancient relic that grants direct access to kernel memory. Through this cursed artifact, you pierce the veil between userland and kernel.

## ⚗️ The Components
| File	| Purpose |
|-------|---------|
|HollowReaper.c	| Hollow a process and inject the embedded shellcode |
|LSASS_CDumper.c | Shellcode: disable PPL & Credential Guard, dump LSASS |
|xor20charkey.py | Python script to XOR the shellcode with a 20-char key |
|RTCore64.sys | Vulnerable driver for kernel memory access (BYOVD) |

## 🕯️ Usage Flow
1️⃣ Compile LSASS_CDumper.c

2️⃣ Use Donut to convert it into shellcode

3️⃣ Obfuscate the shellcode using xor20charkey.py

4️⃣ Embed the result into HollowReaper.c

5️⃣ Run HollowReaper to hollow a process and unleash the payload

--------------------------------------------------------------------------

⚠️ Disclaimer
This tool is provided for educational and research purposes only. Use responsibly.
The arcane always watches. 🧿

