#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include "defs.h"

BOOL ResolveAllApis(void);

// Exported resolved API pointers
extern PFN_P32F pP32F;
extern PFN_P32N pP32N;
extern PFN_OP pOP;
extern PFN_GPA pGPA;
extern PFN_NTCPX pNTCPX;
extern PFN_CTH pCTH;
extern PFN_OPTK pOPTK;
extern PFN_DUPTOK pDUPTOK;
extern PFN_IMP pIMP;
extern PFN_STT pSTT;
extern PFN_ATP pATP;
extern PFN_LPVA pLPVA;
extern PFN_MDWD pMDWD;
extern PFN_GPID pGPID;
