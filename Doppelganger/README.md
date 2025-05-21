# 🪞 Doppelganger – Mimic the Soul, Leave No Trace
Doppelganger is an arcane tool designed to mimic LSASS, extract its secrets, and hide them in plain sight. It builds upon the forbidden arts of HollowReaper, using hollowed processes, kernel exploits, and spectral clones to bypass protection and exfiltrate credentials with stealth.

![Doppelganger_logo](https://github.com/user-attachments/assets/dc6f30fb-3f7d-41aa-9455-5d7d77717fb8)

## 📜 The Ritual
### 🩸 Doppelganger
The soul thief. This shellcode:

🛡️ Disables PPL using the cursed RTCore64.sys driver (BYOVD)

🧬 Clones LSASS into a benign replica

💾 Creates a Minidump from the clone

🗝️ XOR-encrypts the dump and writes it to disk, leaving behind only a shadow

📜 Writes logs in C:\Users\Public\log.txt

### 🧿 Utilities
#### 💀 HollowReaper.c
The vessel for your payload. This performs process hollowing, carving out a legitimate process and injecting your shellcode into its husk.
🔧 Instructions for generating the shellcode to embed are provided in the HollowReaper project.

#### 🔐 decrypt_xor_dump.py
A local decryption utility. Use this to restore the original dump from its XOR-obfuscated form.

## ⚗️ The Components
| File | Purpose |
|------|---------|
| Doppelganger | The shellcode: disable PPL, clone LSASS, dump and XOR |
| HollowReaper.c |	Hollow a process and inject shellcode |
| decrypt_xor_dump.py | Python tool to decrypt XOR dump |
| RTCore64.sys | Vulnerable driver used for PPL bypass (BYOVD) |

## 🕯️ Usage Flow
### Standalone
In order to use Doppelganger you must place RTCore64.sys in C:\Users\Public. Doppleganger can be used standalone or hollowed through HollowReaper.
```
.\Doppelganger.exe
```
--------------------------------------------------------------------------------
### Process Hollowed

1️⃣ Compile Doppelganger

2️⃣ Use Donut to convert it into shellcode
```
.\donut.exe -a 2 -f 7 -i Doppelganger.exe
```
3️⃣ XOR the shellcode and embed it into HollowReaper.c (look for util files in [HollowReaper](https://github.com/vari-sh/RedTeamGrimoire/tree/main/HollowReaper))

4️⃣ Run HollowReaper to hollow a process and trigger Doppelganger (all files saved to C:\Users\Public)
```
.\HollowReaper.exe "C:\windows\explorer.exe"
```
5️⃣ Use decrypt_xor_dump.py to decrypt the dumped file offline
```
python .\decrypt_xor_dump.py .\doppelganger.dmp
```

---------------------------------------------------------------------------------

## 🧙‍♂️ Counterspell - YARA Rules

The following YARA rules can be used to detect Doppelganger binary, artifacts, and opcode stubs in memory or on disk.

These rules were generated using [`yarGen`](https://github.com/Neo23x0/yarGen) to match unique patterns such as string constants related to the Doppelganger LSASS dumper.

<details>
<summary>Click to expand YARA rules</summary>

```yara
rule Doppelganger {
   meta:
      description = " - file Doppelganger.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-04-14"
      hash1 = "203b32b5579bd7e8450eb3ff00bb80826ed38814b3fa121e5a4ac22e7bff060e"
   strings:
      $x1 = "C:\\Users\\Public\\RTCore64.sys" fullword ascii
      $x2 = "C:\\Users\\Public\\log.txt" fullword ascii
      $s3 = "C:\\Users\\Public\\doppelganger.dmp" fullword ascii
      $s4 = "uwinlogon.exe" fullword wide
      $s5 = "Failed to open lsass.exe" fullword ascii
      $s6 = "Failed to dump and XOR LSASS." fullword ascii
      $s7 = "Error getting current process handle" fullword ascii
      $s8 = "Failed to write XORed dump to file. Error: %lu" fullword ascii
      $s9 = "XOR'd dump written to %s successfully" fullword ascii
      $s10 = "Execution completed successfully." fullword ascii
      $s11 = "Starting dump to memory buffer" fullword ascii
      $s12 = "ImpersonateLoggedOnUser failed." fullword ascii
      $s13 = "Failed to allocate memory for dump buffer" fullword ascii
      $s14 = "Dump failed. Error: %lu" fullword ascii
      $s15 = "LookupPrivilegeValue failed for %s. Error: %lu" fullword ascii
      $s16 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s17 = "Successfully cloned process, handle: 0x%p" fullword ascii
      $s18 = "Found process: %ls (PID: %lu)" fullword ascii
      $s19 = "Successfully duplicated token. Process can now run as SYSTEM." fullword ascii
      $op0 = { 33 d2 48 8d 4d a4 41 b8 34 02 00 00 e8 17 2f 00 }
      $op1 = { 48 8d 15 61 3a 00 00 48 8d 4d cc ff 15 37 34 00 }
      $op2 = { 0f b6 05 cb 36 00 00 34 6c 88 03 0f b6 05 c1 36 }
      $op3 = { 0f b6 05 59 35 00 00 34 5e 88 03 0f b6 05 4f 35 }
      $op4 = { 0f b6 05 88 2b 00 00 34 6c 88 03 0f b6 05 7e 2b }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}
```
</details>

## ⚠️ Disclaimer:
This tool is provided for educational and research purposes only. Use responsibly. The arcane always watches. 🧿
