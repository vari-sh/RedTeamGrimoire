# 🚣 Charon 🚣

> *"The Ferryman waits. Pay the coin, and he shall guide your payload across the river Styx, past the watchful eyes of the guardians, into the realm of the living kernel."*

<p align="center">
  <img src="https://github.com/user-attachments/assets/381e2857-5b52-472b-aa5c-3987b19ef205" width="500"/>
</p>

**Charon** is a standalone, self-compiling artifact builder designed for Red Team operations. It creates a specialized vessel (executable) for your shellcode that utilizes advanced evasion techniques to bypass EDR hooks, memory scanners, and static analysis.

## 🔮 Arcane Mechanics (Techniques Used)

Charon weaves together several state-of-the-art techniques to ensure the payload's safe passage:

* **Spectral Image (Module Stomping):**
    Charon avoids the suspicious usage of `VirtualAlloc` (which creates "Private" memory regions often flagged by scanners). Instead, it stealthily loads a legitimate, signed Microsoft DLL (`Chakra.dll`) using `LoadLibraryExA` with specific flags to suppress system notifications. The payload is then injected directly into the `.text` section of this module, making the malware appear as file-backed, legitimate code.

* **SilentMoonwalk (Dynamic Stack Spoofing):**
    To evade "Stack Walk" analysis by EDRs, Charon does not merely jump to a syscall. It parses the `.pdata` (Exception Directory) of legitimate system DLLs at runtime to calculate the exact stack frame size required by functions like `BaseThreadInitThunk`. It then constructs a synthetic call stack and copies stack arguments, ensuring the execution flow looks mathematically perfect and indistinguishable from normal Windows behavior.

* **Tartarus Gate (Dynamic SSN Resolution):**
    Dynamically resolves System Service Numbers (SSNs) at runtime. If an API is hooked by an EDR (starts with a `JMP`), Charon scans the neighboring functions in memory to calculate the correct SSN without touching the hooked bytes, bypassing user-land hooks entirely.

* **Polymorphic Stubs:**
    The syscall generation engine creates 512 unique assembly stubs. Instead of a repetitive pattern of `mov eax, SSN; syscall`, Charon inserts random "junk code" (NOPs and register exchanges) into the padding of every stub. This breaks static byte signatures and hash-based detection.

* **KeyGuard (Runtime Key Brute-Force):**
    The RC4 decryption key is not stored in the binary. Instead, the artifact contains a mathematical relationship and a "Hint Byte". At runtime, the malware must brute-force a secret value (costing CPU cycles) to reconstruct the key. This delays execution and foils many sandbox environments and static analysis tools.

* **Phantasmal Execution (Thread Pools):**
    Instead of creating a new thread (which is a high-noise event), Charon leverages the Windows Thread Pool API (`TpAllocWork`, `TpPostWork`). The payload execution is queued as a legitimate work item, blending in with standard system background activity.

---

## 🕯️ The Ritual (Usage)

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

1.  **Initialization:** Resolves `LoadLibraryExA` and syscalls dynamically (no suspicious imports).
2.  **Stomping:** Loads `Chakra.dll` without triggering `DLL_PROCESS_ATTACH`.
3.  **Preparation:** Changes the legitimate DLL's memory protection to RW (via Indirect Syscall).
4.  **Awakening:** Brute-forces its own encryption key and decrypts the payload into the DLL.
5.  **Armoring:** Flips memory protection to RX (Execute-Read).
6.  **Execution:** Queues the hijacked DLL entry point to the Windows Thread Pool.

---

## 📜 Credits & Acknowledgments

This tool was forged using knowledge and techniques shared by the masters of the craft.

* **[Maldev Academy](https://maldevacademy.com):** The core logic for **HellHall**, **Tartarus Gate**, and the foundational concepts of Indirect Syscalls and Stack Spoofing are derived from their exceptional course materials and research.
* **[trickster0](https://github.com/trickster0/TartarusGate):** For the original Tartarus Gate research.

---

## ⚠️ Disclaimer

**Red Team Grimoire** and **Charon** are developed solely for educational purposes and authorized security assessments. Misuse of this software to compromise systems without prior consent is illegal. The author accepts no liability for damage caused by this tool.
