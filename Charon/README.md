🚣 Charon 🚣
> "The Ferryman waits. Pay the coin, and he shall guide your payload across the river Styx, past the watchful eyes of the guardians, into the realm of the living kernel."
> 
Charon is a standalone, self-compiling artifact builder designed for Red Team operations. It creates a specialized vessel (executable) for your shellcode that utilizes advanced evasion techniques to bypass EDR hooks and static analysis.
🔮 Arcane Mechanics (Techniques Used)
Charon weaves together several potent techniques to ensure the payload's safe passage:
 * Tartarus Gate (Evolution of Halo's Gate):
   Dynamically resolves System Service Numbers (SSNs) at runtime. If an API is hooked by an EDR (starts with a JMP), Charon scans the neighboring functions in memory to calculate the correct SSN without touching the hooked bytes.
 * HellHall (Indirect Syscalls):
   Instead of executing the syscall instruction directly in the malware's text section (a common Indicator of Compromise), Charon searches for a clean syscall; ret gadget within ntdll.dll and jumps to it. This techniques spoofs the call stack, making the execution appear legitimate.
 * KeyGuard (Runtime Key Brute-Force):
   The RC4 decryption key is not stored in the binary. Instead, the artifact contains a mathematical relationship and a "Hint Byte". At runtime, the malware must brute-force a secret value (costing CPU cycles) to reconstruct the key. This delays execution and foils many sandbox environments and static analysis tools.
 * Monolithic Compilation:
   The builder is standalone. It embeds the C templates and Assembly code within itself, compiling the final artifact on-the-fly using MSVC (cl.exe and ml64.exe).
🕯️ The Ritual (Usage)
Prerequisites
 * Windows Environment
 * Visual Studio (with C++ Desktop Development) installed.
 * Developer Command Prompt for VS (Must be used to access cl and ml64).
1. Forge the Soul (Generate Shellcode)
Generate your raw shellcode using msfvenom (or your C2 framework of choice). The format must be raw.
Example: Generating a Calc payload
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin

2. Summon the Ferryman (Build the Artifact)
Open the Developer Command Prompt for VS, navigate to the Charon directory, and execute the builder.
Compile Charon (if not already compiled):
cl Charon.c

Cast the Spell:
Charon.exe calc.bin

Charon will read the shellcode, encrypt it, calculate the KeyGuard variables, generate the source code, and automatically invoke the compiler to produce CharonArtifact.exe.
3. Crossing the Styx (Execution)
Deploy CharonArtifact.exe to the target machine. Upon execution, it will:
 * Initialize Tartarus Gate.
 * Allocate memory (RW) via Indirect Syscalls.
 * Brute-force its own encryption key.
 * Decrypt the payload in-place.
 * Flip memory protection to RX (Execute-Read).
 * Execute the payload via a new thread using HellHall.
📜 Credits & Acknowledgments
This tool was forged using knowledge and techniques shared by the masters of the craft.

[Maldev Academy](https://maldevacademy.com/): The core logic for HellHall, Tartarus Gate, and the foundational concepts of Indirect Syscalls and API Hashing are derived from their exceptional course materials and research.

[trickster0](https://github.com/trickster0/TartarusGate): For the original Tartarus Gate research.

⚠️ Disclaimer
Red Team Grimoire and Charon are developed solely for educational purposes and authorized security assessments. Misuse of this software to compromise systems without prior consent is illegal. The author accepts no liability for damage caused by this tool.