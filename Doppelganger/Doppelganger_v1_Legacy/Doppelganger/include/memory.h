#pragma once
#include <Windows.h>

typedef struct _RTCORE64_MSR_READ {
    DWORD Register;
    DWORD ValueHigh;
    DWORD ValueLow;
} RTCORE64_MSR_READ;

typedef struct _RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
} RTCORE64_MEMORY_READ;

typedef struct _RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
} RTCORE64_MEMORY_WRITE;

DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address);
void  WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value);
WORD  ReadMemoryWORD(HANDLE Device, DWORD64 Address);
DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address);
DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address);
void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value);
BOOL ReadMemoryBuffer(HANDLE Device, DWORD64 Address, void* Buffer, DWORD BufferSize);
void disablePPL();
void restorePPL();