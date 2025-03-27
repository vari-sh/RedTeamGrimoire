#include <windows.h>
#include <psapi.h>
#include "osinfo.h"
#include "logger.h"

// =====================================================
// OS Information Functions
// =====================================================

unsigned long long getKBAddr() {
    DWORD cbNeeded = 0;
    PVOID* base = NULL;

    if (EnumDeviceDrivers(NULL, 0, &cbNeeded)) {
        base = (PVOID*)malloc(cbNeeded);
        if (base) {
            if (EnumDeviceDrivers(base, cbNeeded, &cbNeeded)) {
                unsigned long long addr = (unsigned long long)base[0];
                free(base);
                return addr;
            }
            free(base);
        }
    }

    return 0;
}

// Function to get the OS version
int GetOSVersion() {
    wchar_t CurrentBuild[255] = { 0 };
    DWORD bufferSize = sizeof(CurrentBuild);
    LONG ret = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"CurrentBuild",
        RRF_RT_REG_SZ,
        NULL,
        CurrentBuild,
        &bufferSize
    );
    if (ret == ERROR_SUCCESS) {
        log_info("Windows Build %ls detected", CurrentBuild);
        return _wtoi(CurrentBuild);
    }
    else {
        log_error("Unable to retrieve Windows Build. Error code: %ld", ret);
        return -1;
    }
}

