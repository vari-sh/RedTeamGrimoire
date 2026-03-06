#pragma once

#include <windows.h>
#include <stdio.h>

#define INVALID_SSN ((DWORD64)-1)
#define DEFAULT_FRAME_SIZE 0x28

// Syscall Wrapper Macro: Dynamically updates the spoofing mask before execution
#define ExecuteSyscall(func_ptr, mask, ...) ( \
    qActiveMaskAddress = (mask).pAddress, \
    qActiveMaskFrame = (mask).dwFrameSize, \
    func_ptr(__VA_ARGS__) \
)

// Dynamic Mask Structure
typedef struct _DYNAMIC_MASK {
    PVOID pAddress;
    DWORD dwFrameSize;
} DYNAMIC_MASK, *PDYNAMIC_MASK;

// Predefined Global Masks
extern DYNAMIC_MASK Mask_Memory;   // MapViewOfFile
extern DYNAMIC_MASK Mask_File;     // CreateFileW
extern DYNAMIC_MASK Mask_Security; // VirtualProtectEx
extern DYNAMIC_MASK Mask_Worker;   // WaitForSingleObjectEx / BaseThreadInitThunk

// Syscall Entry Structure
typedef struct _SYSCALL_ENTRY {
    PVOID pAddress;      // 0x00 - Original Address
    DWORD64 dwSsn;       // 0x08 - Syscall Number (SSN)
    PVOID pSyscallRet;   // 0x10 - Address of 'syscall; ret' instruction
    DWORD64 dwHash;      // 0x18 - Hash of the function name
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

typedef struct _SYSCALL_LIST {
    DWORD Count;
    SYSCALL_ENTRY Entries[512];
} SYSCALL_LIST, *PSYSCALL_LIST;

// Globals linked to ASM
extern void* qTableAddr;
extern void* qGadgetAddress;
extern DWORD qGadgetType;
extern DWORD qFrameSize;
extern void* qSavedReg;
extern void* qSavedRetAddr;
extern void* qActiveMaskAddress;
extern void* qThreadBase;
extern void* qRtlUserThreadStart;
extern DWORD qActiveMaskFrame;
extern DWORD qThreadBaseFrame;
extern DWORD qRtlUserThreadStartFrame;

// External ASM functions
extern void SetTableAddr(PVOID pTable, PVOID pGadget, DWORD dwType, DWORD dwFrameSize);
extern void Fnc0000();
extern void Fnc0001();

// Engine API
BOOL InitEngine();
DWORD64 djb2(PBYTE str);
DWORD CalcFrameSize(PVOID pFunc);