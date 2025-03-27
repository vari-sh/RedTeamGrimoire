#pragma once
#include <Windows.h>

// Driver parameters
#define DRIVER_NAME "mDriver"
#define DRIVER_PATH "C:\\Windows\\Tasks\\RTCore64.sys"
#define DEVICE_NAME L"\\\\.\\RTCore64"

// IOCTL codes for RTCORE64
static const DWORD RTC64_MSR_READ_CODE = 0x80002030;
static const DWORD RTC64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTC64_MEMORY_WRITE_CODE = 0x8000204c;

// Driver loading functions 
int LoadAndStartDriver(void);
int StopAndUnloadDriver(const char* driverName);