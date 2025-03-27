#include "driver.h"
#include "logger.h"

// =====================================================
// Driver loading and unloading
// =====================================================

// Helper function to open the Service Control Manager with the specified access rights
static SC_HANDLE OpenSCManagerHandle(DWORD dwAccess) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, dwAccess);
    if (!hSCM) {
        log_error("OpenSCManager failed. Error code: %lu", GetLastError());
    }
    return hSCM;
}

// Helper function to create or open the driver service
static SC_HANDLE CreateOrOpenDriverService(SC_HANDLE hSCM, const char* driverName, const char* driverPath) {
    SC_HANDLE hService = CreateServiceA(
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
            hService = OpenServiceA(hSCM, driverName, SERVICE_ALL_ACCESS);
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
            log_error("CreateService error. Error code: %lu", err);
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
        CloseServiceHandle(hSCM);
        return 1;
    }

    // Start the driver service
    if (!StartServiceA(hService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            log_error("StartService error. Error code: %lu", err);
            DeleteService(hService);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
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
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 0;
}

// Function to stop and unload the driver
int StopAndUnloadDriver(const char* driverName) {
    SC_HANDLE hSCM = OpenSCManagerHandle(SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
        return 1;

    SC_HANDLE hService = OpenServiceA(hSCM, driverName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            log_error("Service does not exist.");
            CloseServiceHandle(hSCM);
            return 0;
        }
        else if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            log_info("Service is already marked for deletion.");
            CloseServiceHandle(hSCM);
            return 0;
        }
        else {
            log_error("Error: %s.", err);
            CloseServiceHandle(hSCM);
            return 0;
        }
        log_error("OpenService failed. Error code: %lu", err);
        CloseServiceHandle(hSCM);
        return 1;

    }

    SERVICE_STATUS status;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
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
    if (!DeleteService(hService)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            log_info("Service is already marked for deletion.");
        }
        else {
            log_error("DeleteService failed. Error code: %lu", err);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return 1;
        }
    }
    else {
        log_success("Service deleted successfully.");
    }

    // Close the handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 0;
}