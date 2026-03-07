# 🚣 Charon 🚣

> *"The Ferryman waits. Pay the coin, and he shall guide your soul across the river Styx, past the watchful eyes of the guardians, into the realm of the living kernel."*

<p align="center">
  <img src="../Images/Charon.png" width="500"/>
</p>

**Charon** is a standalone, self-compiling artifact builder designed for Red Team operations. It creates a specialized vessel (executable) for your soul (shellcode) that utilizes advanced evasion techniques to bypass EDR hooks, memory scanners, and static analysis.

---

## 📂 Project Variants

TL;DR: for best evasion, use External Payload Version

This repository contains two versions of Charon, depending on your staging requirements:

1.  **Monolithic Version (Legacy):** The "classic" version where the encrypted payload is embedded within the executable's resources.
2.  **External Payload Version:** A specialized variant that loads the payload from an external UUID-encoded file to minimize the main artifact's entropy and bypass advanced static analysis. 
    * **See details here:** [`/Charon-PayloadFileVersion`](./Charon_ExternalPayloadVersion)

---

## 🔮 Arcane Mechanics (Techniques Used)

Charon weaves together several state-of-the-art techniques to ensure the payload's safe passage:

* **Spectral Image (Module Stomping):**
    Charon avoids the suspicious usage of `VirtualAlloc` (which creates "Private" memory regions often flagged by scanners). Instead, it stealthily loads a legitimate, signed Microsoft DLL (`Chakra.dll`) using `LoadLibraryExA` with specific flags to suppress system notifications. The payload is then injected directly into the `.text` section of this module, making the malware appear as file-backed, legitimate code.

* **SilentMoonwalk (Adaptive Stack Spoofing):**
    To evade "Stack Walk" analysis, Charon mathematically reconstructs the entire call chain. It parses the `.pdata` (Exception Directory) of system modules at runtime to calculate the exact frame sizes for `VirtualProtectEx`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. It then constructs a perfect synthetic stack that hides the malicious origin of the thread.

* **Lethe's Wipe (Forensic Stack Cleaning):**
    Before handing over control to the payload, Charon performs an aggressive "Wipe" of the stack. By physically zeroing out the bytes used during the preparation phase, it eliminates "trailing bytes" that could reveal the loader's activity to behavioral scanners.

* **Tartarus Gate (Dynamic SSN Resolution):**
    Dynamically resolves System Service Numbers (SSNs) at runtime. If an API is hooked by an EDR (starts with a `JMP`), Charon scans the neighboring functions in memory to calculate the correct SSN without touching the hooked bytes, bypassing user-land hooks entirely.

* **Polymorphic Stubs:**
    The syscall generation engine creates 512 unique assembly stubs. Instead of a repetitive pattern of `mov eax, SSN; syscall`, Charon inserts random "junk code" (NOPs and register exchanges) into the padding of every stub. This breaks static byte signatures and hash-based detection.

* **KeyGuard (Runtime Key Brute-Force):**
    The RC4 decryption key is not stored in the binary. Instead, the artifact contains a mathematical relationship and a "Hint Byte". At runtime, the malware must brute-force a secret value (costing CPU cycles) to reconstruct the key. This delays execution and foils many sandbox environments and static analysis tools.

* **Abyssal Leap (Tail Call Execution):**
    Instead of high-noise events like creating new threads or using suspicious callbacks, Charon utilizes a direct `JMP` (Tail Call). By wiping the stack and registers before the jump, the payload appears as the natural and legitimate occupant of the current thread.


## 🕯️ Updated Ritual (New Usage)

The build process now requires an additional step to prepare the external payload.

### Prerequisites

* Windows Environment
* Visual Studio (with C++ Desktop Development) installed.
* **Developer Command Prompt for VS** (Must be used to access `cl` and `ml64`).

### Step 1. Forge the Soul (Generate Shellcode)

Generate your raw shellcode using `msfvenom` or your C2 framework of choice or Donut. The format **must** be raw.

**Example: Generating a Calc payload**

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin
```

Use the new Python utility to generate your obfuscated staging file:
```bash
python UUIDEncrypter.py payload.bin payload.enc
```

### Step 2: Build the Artifact
Compile the updated Charon builder and generate the vessel:
```bash
cl Charon.c
.\Charon.exe
```

### Step 3: Execution
On the target machine, the artifact now requires the path to the external soul (payload) as a command-line argument:
```bash
.\CharonArtifact.exe payload.enc
```

---

## 🕯️ The Ritual (Legacy)

### Prerequisites

* Windows Environment
* Visual Studio (with C++ Desktop Development) installed.
* **Developer Command Prompt for VS** (Must be used to access `cl` and `ml64`).

### 1. Forge the Soul (Generate Shellcode)

Generate your raw shellcode using `msfvenom` (or your C2 framework of choice or Donut). The format **must** be raw.

**Example: Generating a Calc payload**

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
```

### 2. Summon the Ferryman (Build the Artifact)

Open the **Developer Command Prompt for VS**, navigate to the Charon directory, and execute the builder.

**Compile Charon (if not already compiled):**

```cmd
cl Charon.c
```

**Cast the Spell:**

```cmd
Charon.exe calc.bin
```

Charon will read the shellcode, encrypt it, calculate the KeyGuard variables, generate the polymorphic source code, and automatically invoke the compiler to produce **`CharonArtifact.exe`**.

### 3. Crossing the Styx (Execution)

Deploy `CharonArtifact.exe` to the target machine. Upon execution, the artifact follows this stealth flow:

1.  **Initialization:** Dynamic resolution of `ntdll` and adaptive stack frame calculation.
2.  **Stomping:** Silent loading of `Chakra.dll`.
3.  **Preparation:** Memory protection change to RW via Indirect Syscall with Stack Spoofing.
4.  **Awakening:** KeyGuard brute-force and payload decryption (from resource or external file).
5.  **Armoring:** Memory protection restore to RX (Execute-Read).
6.  **Purification & Leap:** Total stack wipe and final `JMP` into the payload.

---

## 📜 Credits & Acknowledgments

This tool was forged using knowledge and techniques shared by the masters of the craft.

* **[Helvio Junior](https://github.com/helviojunior/hookchain):** For the **HookChain** research. Although Charon has evolved to use Indirect Syscall instead of IAT redirection, the concept of automated assembly stub generation and syscall integration was heavily inspired by his work.
* **[Maldev Academy](https://maldevacademy.com):** The core logic for **HellHall**, **Tartarus Gate**, and the foundational concepts of Indirect Syscalls and Stack Spoofing are derived from their exceptional course materials and research.
* **[trickster0](https://github.com/trickster0/TartarusGate):** For the original Tartarus Gate research.

---

## ⚠️ Disclaimer

**Red Team Grimoire** and **Charon** are developed solely for educational purposes and authorized security assessments. Misuse of this software to compromise systems without prior consent is illegal. The author accepts no liability for damage caused by this tool.
