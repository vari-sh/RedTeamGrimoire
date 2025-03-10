# 💀 HollowReaper - Hollow the Living, Control the Void
HollowReaper is a mystical tool crafted to manipulate processes through Process Hollowing, allowing seamless injection of custom shellcode into a legitimate process. This arcane art lets you erase a process’s soul and replace it with your own will.

## 📜 The Components 
💀 HollowReaper.c - The core of this dark ritual, this program performs process hollowing, carving out a legitimate process and injecting your custom payload.

💎 LSASS_CDumper.c - A sacrificial script, an example C code that extracts LSASS memory. It uses BYOVD (Bring Your Own Vulnerable Driver) arcane technique to disable PPL protection from LSASS process acting at Kernel-Land and disable Credential Guard using the technique explained [here](https://github.com/ricardojoserf/NativeBypassCredGuard). This must be compiled, its shellcode must be extracted using Donut and finally xored and inserted in HollowReaper.c.

🗝️ xor20charkey.py - A cryptic enchantment, a Python script to obfuscate shellcode via XOR, ensuring your payload remains unseen in the void.

⚙️ RTCore64.sys - An ancient cursed artifact, a vulnerable driver that grants the forbidden power to write directly into kernel memory. Through this relic of flawed craftsmanship, the barriers between userland and kernel are shattered, allowing the wielder to manipulate the very fabric of the operating system. 

## 🕯️ The Ritual
1️⃣ Compile LSASS_CDumper.c into an executable.

2️⃣ Use Donut to extract the shellcode from the compiled binary.

3️⃣ Obfuscate the shellcode using xor20charkey.py.

4️⃣ Summon HollowReaper to hollow a process and inject your payload into its husk.

----------------------------------------------------------------
🕯️ Tread carefully, for the void sees all. 🔮✨
