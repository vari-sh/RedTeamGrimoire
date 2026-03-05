# 🪙 Obolos 🪙
> "No soul crosses the river Styx for free. The Ferryman demands his coin, and the guardians of the underworld demand silence. Present the Obolos, and the gates to the abyss shall open unnoticed."

Obolos is a pure, agnostic evasion engine designed for Red Team sorcery. 
Stripped of any specific payload loaders or module stomping techniques, it serves 
as the raw, foundational dark magic required to execute System Calls directly 
into the Windows Kernel while remaining completely invisible to modern 
Endpoint Detection and Response (EDR) guardians.

## 🔮 Arcane Mechanics (Techniques Used)
Obolos is the core mechanism that powers tools like Charon. It provides a clean API to weave illusions and bypass user-land inspections:

* **Tartarus Gate (Dynamic SSN Resolution):**
Obolos dynamically maps the underworld at runtime. It resolves System Service Numbers (SSNs) via the PEB and export directories. If a guardian has placed a hook (a JMP instruction) on an API, Obolos inspects the neighboring memory addresses to calculate the true SSN, entirely bypassing user-land hooks.

* **SilentMoonwalk (Synthetic Stack Weaving):**
Calling the kernel directly leaves a massive forensic anomaly. Obolos parses the Exception Directory (.pdata) of system modules to mathematically calculate the exact frame sizes of legitimate functions (like WaitForSingleObjectEx or VirtualProtectEx). It then weaves a perfect, mathematically sound synthetic call stack. When the guardians perform a "Stack Walk", they see only the illusion of a benign, legitimate thread.

* **Polymorphic Glyphs (Dynamic ASM Stubs):**
Static signatures are the downfall of lazy mages. Obolos includes a Python-based invocation script that generates 512 unique Assembly stubs before compilation. It dynamically injects arcane junk code (NOPs, register exchanges) into the padding of each stub, ensuring the compiled artifact has a completely randomized block hash on every build.

## 🕯️ The Ritual (Usage)
Obolos is meant to be integrated into your own dark projects. It handles the low-level architecture so you can focus on the payload logic.

### The Fast Path
To automate the entire ritual (generating stubs, assembling, and compiling the test framework), simply open the x64 Native Tools Command Prompt and invoke the provided script:
```cmd
build.bat
```

### The Manual Forging
Or, to forge it manually into your own tools, follow the ancient steps:

1. Prepare the Runes
Before compiling your C project, invoke the Python script to generate the polymorphic assembly engine:
```cmd
python generate_stubs.py
```
This merges the base template with the 512 randomized syscall stubs into `syscalls.asm`.

2. Link the Grimoire
Include `engine.h` in your project and compile the C code alongside the generated Assembly object:
```cmd
ml64 /c /Cx /nologo syscalls.asm
cl /nologo /O2 your_project.c engine.c syscalls.obj /link /CETCOMPAT:NO
```

3. Invoke the Shadows
Initialize the engine and pass the pre-calculated illusions (masks) to execute your desired syscalls safely:
```c
#include "engine.h"

int main() {
    InitEngine(); // Maps ntdll, resolves SSNs, finds gadgets

    // Example: Locate NtAllocateVirtualMemory by its djb2 hash
    DWORD64 hAlloc = djb2((PBYTE)"NtAllocateVirtualMemory");
    // [Locate index and map to pStubBase...]
    
    // Execute the syscall cloaked behind the illusion of WaitForSingleObjectEx
    ExecuteSyscall(pAlloc, Mask_Worker, (HANDLE)-1, &pMem, 0, &sSize, MEM_COMMIT, PAGE_READWRITE);
}
```
