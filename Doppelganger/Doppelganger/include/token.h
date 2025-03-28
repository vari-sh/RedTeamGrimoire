#pragma once

#pragma once

#include <windows.h>

// Retrieves and duplicates a SYSTEM token (e.g., from winlogon.exe)
BOOL GetSystemTokenAndDuplicate(HANDLE* hSystemToken);

// Enables a specific privilege on a given token (using obfuscated name)
BOOL EnablePrivilege(HANDLE hToken, const unsigned char* encryptedPriv, size_t encLen);

// Enables all predefined privileges (e.g., SeDebugPrivilege, SeImpersonatePrivilege)
void EnableAllPrivileges(HANDLE hToken);

// Enable SEDBGPVG on current process
BOOL EnableSEDBGPRV();
