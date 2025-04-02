#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Aclapi.h>
#include <DbgHelp.h>
#include <Psapi.h>

// ==========================
// Macro
// ==========================

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES     0x00000004
#define PROCESS_CREATE_FLAGS_NO_SYNCHRONIZE      0x00000008

// ==========================
// Structures
// ==========================
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// ==========================
// API Function Pointer Types
// ==========================

typedef BOOL(WINAPI* PFN_P32F)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );

typedef BOOL(WINAPI* PFN_P32N)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );

typedef HANDLE(WINAPI* PFN_OP)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
    );

typedef FARPROC(WINAPI* PFN_GPA)(
    HMODULE hModule,
    LPCSTR lpProcName
    );

typedef NTSTATUS(NTAPI* PFN_NTCPX)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE ExceptionPort OPTIONAL,
    BOOLEAN InJob
    );

typedef HANDLE(WINAPI* PFN_CTH)(
    DWORD dwFlags,
    DWORD th32ProcessID
    );

typedef BOOL(WINAPI* PFN_OPTK)(
    HANDLE ProcessHandle,
    DWORD DesiredAccess,
    PHANDLE TokenHandle
    );

typedef BOOL(WINAPI* PFN_DUPTOK)(
    HANDLE ExistingTokenHandle,
    DWORD dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpTokenAttributes,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    TOKEN_TYPE TokenType,
    PHANDLE DuplicateTokenHandle
    );

typedef BOOL(WINAPI* PFN_IMP)(
    HANDLE hToken
    );

typedef BOOL(WINAPI* PFN_STT)(
    PHANDLE Thread,
    HANDLE Token
    );

typedef BOOL(WINAPI* PFN_ATP)(
    HANDLE TokenHandle,
    BOOL DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD ReturnLength
    );

typedef BOOL(WINAPI* PFN_LPVA)(
    LPCWSTR lpSystemName,
    LPCWSTR lpName,
    PLUID   lpLuid
    );

typedef BOOL(WINAPI* PFN_MDWD)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
    );

typedef DWORD(WINAPI* PFN_GPID)(
    HANDLE hProcess   // Handle to the process
    );

typedef HANDLE(WINAPI* PFN_GCP)(
    void
    );

typedef HANDLE(WINAPI* PFN_CFA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
    );

typedef BOOL(WINAPI* PFN_DIOC)(
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped
    );

typedef HMODULE(WINAPI* PFN_LLW)(
    LPCWSTR LoadLibraryW_t
    );

typedef BOOL(WINAPI* PFN_EDD)(
    LPVOID* lpImageBase,
    DWORD cb,
    LPDWORD lpcbNeeded
    );

// OpenSCManagerA
typedef SC_HANDLE(WINAPI* PFN_OSCM)(
    LPCSTR lpMachineName,
    LPCSTR lpDatabaseName,
    DWORD dwDesiredAccess
    );

// CreateServiceA
typedef SC_HANDLE(WINAPI* PFN_CS)(
    SC_HANDLE hSCManager,
    LPCSTR lpServiceName,
    LPCSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPCSTR lpBinaryPathName,
    LPCSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPCSTR lpDependencies,
    LPCSTR lpServiceStartName,
    LPCSTR lpPassword
    );

// OpenServiceA
typedef SC_HANDLE(WINAPI* PFN_OS)(
    SC_HANDLE hSCManager,
    LPCSTR lpServiceName,
    DWORD dwDesiredAccess
    );

// StartServiceA
typedef BOOL(WINAPI* PFN_SS)(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPCSTR* lpServiceArgVectors
    );

// ControlService
typedef BOOL(WINAPI* PFN_CSVC)(
    SC_HANDLE hService,
    DWORD dwControl,
    LPSERVICE_STATUS lpServiceStatus
    );

// DeleteService
typedef BOOL(WINAPI* PFN_DS)(
    SC_HANDLE hService
    );

// CloseServiceHandle
typedef BOOL(WINAPI* PFN_CSH)(
    SC_HANDLE hSCObject
    );



// ==========================
// Function Pointer Declarations
// ==========================
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
extern PFN_GCP pGCP;
extern PFN_CFA pCFA;
extern PFN_DIOC pDIOC;
extern PFN_LLW pLLW;
extern PFN_EDD pEDD;
extern PFN_OSCM pOSCM;
extern PFN_CS pCS;
extern PFN_OS pOS;
extern PFN_SS pSS;
extern PFN_CSVC pCSVC;
extern PFN_DS pDS;
extern PFN_CSH pCSH;
