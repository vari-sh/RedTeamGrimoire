# 🪞 Doppelganger – Mimic the Soul, Leave No Trace
Doppelganger is an arcane tool designed to mimic LSASS, extract its secrets, and hide them in plain sight. It builds upon the forbidden arts of HollowReaper, using hollowed processes, kernel exploits, and spectral clones to bypass protection and exfiltrate credentials with stealth.

![Doppelganger_logo](https://github.com/user-attachments/assets/dc6f30fb-3f7d-41aa-9455-5d7d77717fb8)

## 📜 The Ritual
### 💀 HollowReaper.c
The vessel for your payload. This performs process hollowing, carving out a legitimate process and injecting your shellcode into its husk.
🔧 Instructions for generating the shellcode to embed are provided in the HollowReaper project.

### 🩸 Doppelganger.c
The soul thief. This shellcode:

🛡️ Disables PPL using the cursed RTCore64.sys driver (BYOVD)

🧬 Clones LSASS into a benign replica

💾 Creates a Minidump from the clone

🗝️ XOR-encrypts the dump and writes it to disk, leaving behind only a shadow

### 🔐 decrypt_xor_dump.py
A local decryption utility. Use this to restore the original dump from its XOR-obfuscated form.

## 🧪 The Components
| File | Purpose |
|------|---------|
| HollowReaper.c |	Hollow a process and inject shellcode |
| Doppelganger.c | Shellcode: disable PPL, clone LSASS, dump and XOR |
| decrypt_xor_dump.py | Python tool to decrypt XOR dump |
| RTCore64.sys | Vulnerable driver used for PPL bypass (BYOVD) |

## 🕯️ Usage Flow
🔨 Compile Doppelganger.c

🧪 Use Donut to convert it into shellcode

🧿 Embed the shellcode into HollowReaper.c

💀 Run HollowReaper to hollow a process and trigger Doppelganger

🗝️ Use decrypt_xor_dump.py to decrypt the dumped file offline

## ⚠️ Disclaimer:
This tool is provided for educational and research purposes only. Use responsibly. The arcane always watches. 🧿
