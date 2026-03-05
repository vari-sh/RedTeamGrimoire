# 💀 HollowReaper – Process Hollowing Shellcode Launcher for Stealth Payload Execution

**HollowReaper** is a red team utility for stealthy **process hollowing**. It replaces the memory of a legitimate process with custom shellcode, allowing you to execute payloads under the guise of trusted binaries.

This technique evades traditional security controls by injecting directly into a remote process's memory after unmapping its image, commonly used to execute LSASS dumper shellcode without spawning suspicious processes.

> 🧠 Common payloads include: LSASS clone & dump shellcode, Beacon loaders, or BYOVD-based PPL bypassers.

Once prepared, HollowReaper serves as a "vessel" to deploy your enchanted shellcode into the void of a hollowed process.

<p align="center">
  <img src="../Images/HollowReaper.png" width="500"/>
</p>

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



