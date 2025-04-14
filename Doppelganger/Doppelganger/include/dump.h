#pragma once

#pragma once
#include <Windows.h>

// Clone LSASS and return handle to the clone
HANDLE CloneProcess(void);

// Utility to retrieve PID from a process handle
DWORD GetProcessIdFromHandle(HANDLE hProcess);

// Dump LSASS
BOOL DumpAndXorLsass(const char* outPath, const char* key, size_t key_len);

// Set read access to dump
BOOL SetFileGenericReadAccess(const char* filePath);
