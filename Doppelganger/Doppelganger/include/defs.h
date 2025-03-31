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


// ==========================
// Function Pointer Declarations (can go in a global header or resolved inside a resolver function)
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
