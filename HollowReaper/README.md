# 💀 HollowReaper – Process Hollowing Shellcode Launcher for Stealth Payload Execution

**HollowReaper** is a red team utility for stealthy **process hollowing**. It replaces the memory of a legitimate process with custom shellcode, allowing you to execute payloads under the guise of trusted binaries.

This technique evades traditional security controls by injecting directly into a remote process's memory after unmapping its image.

Once prepared, HollowReaper serves as a "vessel" to deploy your enchanted shellcode into the void of a hollowed process.

<p align="center">
  <img src="../Images/HollowReaper.png" width="500"/>
</p>

## 📜 The Ritual
### 💀 HollowReaper.c
The vessel for your payload. This program performs process hollowing, carving out a legitimate process and injecting your shellcode into its husk.

### 🗝️ xor20charkey.py
A local obfuscation utility. XOR-encrypts the shellcode using a custom 20-character key, shielding your payload from watchful eyes.


## ⚗️ The Components
| File	| Purpose |
|-------|---------|
|HollowReaper.c	| Hollow a process and inject the embedded shellcode |
|xor20charkey.py | Python script to XOR the shellcode with a 20-char key |

## 🕯️ Usage Flow

1. Obfuscate the shellcode using xor20charkey.py

2. Embed the result into HollowReaper.c

3. Run HollowReaper to hollow a process and unleash the payload

--------------------------------------------------------------------------

⚠️ Disclaimer
This tool is provided for educational and research purposes only. Use responsibly.
The arcane always watches. 🧿



