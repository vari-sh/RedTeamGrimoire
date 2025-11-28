#pragma once
#include <windows.h>
#include "Structs.h"

// Configuration Constants
#define UP      -32
#define DOWN    32
#define RANGE   0xFF

// Structure to hold Syscall Information
typedef struct _NT_SYSCALL
{
    DWORD dwSSn;                    // syscall number
    DWORD dwSyscallHash;            // syscall hash value
    PVOID pSyscallAddress;          // syscall address
    PVOID pSyscallInstAddress;      // address of a random 'syscall' instruction in ntdll    
} NT_SYSCALL, * PNT_SYSCALL;

// Structure to hold NTDLL Exports info
typedef struct _NTDLL_CONFIG
{
    PVOID uModule;
    DWORD dwNumberOfNames;
    PDWORD pdwArrayOfNames;
    PDWORD pdwArrayOfAddresses;
    PWORD pwArrayOfOrdinals;
} NTDLL_CONFIG, * PNTDLL_CONFIG;

// Global config
extern NTDLL_CONFIG g_NtdllConf;

// Prototypes
BOOL InitNtdllConfigStructure();
BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);
DWORD CRC32B(LPCSTR string);

// Assembly externs
extern void SetSSn(DWORD dwSSn, PVOID pSyscallInstAddress);
extern NTSTATUS RunSyscall(); // Variadic arguments in C, handled by ASM