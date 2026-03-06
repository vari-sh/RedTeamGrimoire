#define _CRT_SECURE_NO_WARNINGS
#include "utils.h"
#include "logger.h"
#include "nocrt.h"

// ======================================
//  Functions to XOR encrypt/decrypt
// ======================================
const char *XOR_KEY = "0123456789abcdefghij";
size_t key_len = 20;

char *xor_decrypt_string(const unsigned char *cipher, size_t len,
                         const char *key, size_t key_len) {
  char *result = (char *)custom_malloc(len + 1);
  if (!result)
    return NULL;
  for (size_t i = 0; i < len; i++) {
    result[i] = cipher[i] ^ key[i % key_len];
  }
  result[len] = '\0';
  return result;
}

void xor_buffer(unsigned char *buffer, size_t len, const char *key,
                size_t key_len) {
  for (size_t i = 0; i < len; i++) {
    buffer[i] ^= key[i % key_len];
  }
}

// ========================================
//  Function to convert string to UNICODE
// ========================================
wchar_t *to_wide(const char *str) {
  int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  if (len == 0)
    return NULL;
  wchar_t *wstr = (wchar_t *)custom_malloc(len * sizeof(wchar_t));
  if (!wstr)
    return NULL;
  MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
  return wstr;
}

// =====================================================
// Function to load clean versions of DLLs
// =====================================================
HMODULE LoadCleanDLL(char *dllPath) {

  HMODULE hDLL = LoadLibraryA(dllPath);
  /* DEBUG
  if (hDLL)
  {
      log_success("Loaded clean copy of %s at: %p", dllPath, hDLL);
  }
  else
  {
      log_error("Failed to load %s. Error: %lu", dllPath, GetLastError());
  }*/

  return hDLL;
}

// =====================================================
// GetProcAddress reimplementation
// =====================================================

FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
  if (!hModule || !lpProcName)
    return NULL;

  BYTE *baseAddr = (BYTE *)hModule;
  IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)baseAddr;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  IMAGE_NT_HEADERS *ntHeaders =
      (IMAGE_NT_HEADERS *)(baseAddr + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  IMAGE_DATA_DIRECTORY exportDirData =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!exportDirData.VirtualAddress)
    return NULL;

  IMAGE_EXPORT_DIRECTORY *exportDir =
      (IMAGE_EXPORT_DIRECTORY *)(baseAddr + exportDirData.VirtualAddress);

  DWORD *names = (DWORD *)(baseAddr + exportDir->AddressOfNames);
  WORD *ordinals = (WORD *)(baseAddr + exportDir->AddressOfNameOrdinals);
  DWORD *functions = (DWORD *)(baseAddr + exportDir->AddressOfFunctions);

  for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
    char *name = (char *)(baseAddr + names[i]);
    if (custom_stricmp(name, lpProcName) == 0) {
      WORD ordinal = ordinals[i];
      DWORD funcRVA = functions[ordinal];
      FARPROC address = (FARPROC)(baseAddr + funcRVA);

      // Check if it's a forward export
      DWORD exportStart = exportDirData.VirtualAddress;
      DWORD exportEnd = exportStart + exportDirData.Size;
      if (funcRVA >= exportStart && funcRVA <= exportEnd) {
        // It's a forward export (e.g., "sechost.OpenProcessToken")
        char *forwardName = (char *)address;
        char dllName[256] = {0};
        char funcName[128] = {0};
        const char *dot = forwardName;
        while (*dot && *dot != '.')
          dot++;

        size_t dllLen = dot - forwardName;
        if (dllLen < sizeof(dllName) - 5) {
          for (size_t k = 0; k < dllLen; k++)
            dllName[k] = forwardName[k];
          dllName[dllLen] = '.';
          dllName[dllLen + 1] = 'd';
          dllName[dllLen + 2] = 'l';
          dllName[dllLen + 3] = 'l';
          dllName[dllLen + 4] = '\0';
        }

        if (*dot == '.') {
          const char *func = dot + 1;
          size_t fLen = custom_strlen(func);
          if (fLen < sizeof(funcName)) {
            for (size_t k = 0; k < fLen; k++)
              funcName[k] = func[k];
            funcName[fLen] = '\0';
          }
        }

        HMODULE hFwd = LoadLibraryA(dllName);
        if (!hFwd)
          return NULL;

        return CustomGetProcAddress(hFwd, funcName);
      }

      return address;
    }
  }

  return NULL;
}
