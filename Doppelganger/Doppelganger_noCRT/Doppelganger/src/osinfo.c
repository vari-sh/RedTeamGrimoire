#include "osinfo.h"
#include "api.h"
#include "defs.h"
#include "logger.h"
#include "nocrt.h"
#include <psapi.h>
#include <windows.h>


static int custom_wtoi(const wchar_t *str) {
  int res = 0;
  while (*str >= L'0' && *str <= L'9') {
    res = res * 10 + (*str - L'0');
    str++;
  }
  return res;
}

// =====================================================
// OS Information Functions
// =====================================================

unsigned long long getKBAddr() {
  DWORD cbNeeded = 0;
  PVOID *base = NULL;

  if (pEDD(NULL, 0, &cbNeeded)) {
    base = (PVOID *)custom_malloc(cbNeeded);
    if (base) {
      if (pEDD(base, cbNeeded, &cbNeeded)) {
        unsigned long long addr = (unsigned long long)base[0];
        custom_free(base);
        return addr;
      }
      custom_free(base);
    }
  }

  return 0;
}

// Function to get the OS version
int GetOSVersion() {
  wchar_t CurrentBuild[255] = {0};
  DWORD bufferSize = sizeof(CurrentBuild);
  LONG ret = RegGetValueW(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      L"CurrentBuild", RRF_RT_REG_SZ, NULL, CurrentBuild, &bufferSize);
  if (ret == ERROR_SUCCESS) {
    log_info("Windows Build %ls detected", CurrentBuild);
    return custom_wtoi(CurrentBuild);
  } else {
    log_error("Unable to retrieve Windows Build. Error code: %ld", ret);
    return -1;
  }
}
