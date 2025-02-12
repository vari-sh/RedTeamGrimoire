# 💀 HollowReaper - Hollow the Living, Control the Void
HollowReaper is a mystical tool crafted to manipulate processes through Process Hollowing, allowing seamless injection of custom shellcode into a legitimate process. This arcane art lets you erase a process’s soul and replace it with your own will.

## 📜 The Components 
💀 HollowReaper.c - The core of this dark ritual, this program performs process hollowing, carving out a legitimate process and injecting your custom payload.

💎 LSASS_CDumper.c - A sacrificial script, an example C code that extracts LSASS memory. This must be compiled, and its shellcode must be extracted using Donut.

🗝️ xor20charkey.py - A cryptic enchantment, a Python script to obfuscate shellcode via XOR, ensuring your payload remains unseen in the void.

## 🕯️ The Ritual
1️⃣ Compile LSASS_CDumper.c into an executable.

2️⃣ Use Donut to extract the shellcode from the compiled binary.

3️⃣ Obfuscate the shellcode using xor20charkey.py.

4️⃣ Summon HollowReaper to hollow a process and inject your payload into its husk.

----------------------------------------------------------------
🕯️ Tread carefully, for the void sees all. 🔮✨
