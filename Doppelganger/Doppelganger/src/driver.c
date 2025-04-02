#include "driver.h"
#include "logger.h"
#include "api.h"

// =====================================================
// Driver loading and unloading
// =====================================================

// Helper function to open the Service Control Manager with the specified access rights
static SC_HANDLE OpenSCManagerHandle(DWORD dwAccess) {
    SC_HANDLE hSCM = pOSCM(NULL, NULL, dwAccess);
    if (!hSCM) {
        log_error("OSCM failed. Error code: %lu", GetLastError());
    }
    return hSCM;
}

// Helper function to create or open the driver service
static SC_HANDLE CreateOrOpenDriverService(SC_HANDLE hSCM, const char* driverName, const char* driverPath) {
    SC_HANDLE hService = pCS(
        hSCM,
        driverName,          // Internal service name
        driverName,          // Display name
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driverPath,          // Full path to the driver file
        NULL, NULL, NULL, NULL, NULL
    );
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hService = pOS(hSCM, driverName, SERVICE_ALL_ACCESS);
            if (hService) {
                log_success("Existing service opened successfully.");
            }
            else {
                log_error("Unable to open the existing service. Error code: %lu", GetLastError());
            }
        }
        else if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            log_error("Service is marked for deletion.");
        }
        else {
            log_error("CS error. Error code: %lu", err);
        }
    }
    else {
        log_success("Service created successfully.");
    }
    return hService;
}

// Function to load and start the driver
int LoadAndStartDriver(void) {
    SC_HANDLE hSCM = OpenSCManagerHandle(SC_MANAGER_CREATE_SERVICE);
    if (!hSCM)
        return 1;

    SC_HANDLE hService = CreateOrOpenDriverService(hSCM, DRIVER_NAME, DRIVER_PATH);
    if (!hService) {
        pCSH(hSCM);
        return 1;
    }

    // Start the driver service
    if (!pSS(hService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            log_error("SS error. Error code: %lu", err);
            pDS(hService);
            pCSH(hService);
            pCSH(hSCM);
            return 1;
        }
        else {
            log_info("Driver is already loaded.");
        }
    }
    else {
        log_success("Driver loaded and started successfully.");
    }

    // Close the handles
    pCSH(hService);
    pCSH(hSCM);
    return 0;
}

// Function to stop and unload the driver
int StopAndUnloadDriver(const char* driverName) {
    SC_HANDLE hSCM = OpenSCManagerHandle(SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
        return 1;

    SC_HANDLE hService = pOS(hSCM, driverName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            log_error("Service does not exist.");
            pCSH(hSCM);
            return 0;
        }
        else if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            log_info("Service is already marked for deletion.");
            pCSH(hSCM);
            return 0;
        }
        else {
            log_error("Error: %lu.", err);
            pCSH(hSCM);
            return 0;
        }
    }

    SERVICE_STATUS status;
    if (!pCSVC(hService, SERVICE_CONTROL_STOP, &status)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            log_info("The service is not active.");
        }
        else {
            log_error("ControlService (stop) failed. Error code: %lu", err);
        }
    }
    else {
        log_success("Service stopped successfully.");
    }

    // Attempt to delete the service
    if (!pDS(hService)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            log_info("Service is already marked for deletion.");
        }
        else {
            log_error("DeleteService failed. Error code: %lu", err);
            pCSH(hService);
            pCSH(hSCM);
            return 1;
        }
    }
    else {
        log_success("Service deleted successfully.");
    }

    // Close the handles
    pCSH(hService);
    pCSH(hSCM);
    return 0;
}