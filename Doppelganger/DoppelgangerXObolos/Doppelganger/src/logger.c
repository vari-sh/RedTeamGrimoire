#include "logger.h"
#include "nocrt.h"
#include "utils.h"
#include <stdarg.h>

HANDLE hLogFile = INVALID_HANDLE_VALUE;

typedef int(__cdecl *PVSNPRINTF)(char *buffer, size_t count, const char *format,
                                 va_list argptr);
static PVSNPRINTF p_vsnprintf = NULL;

// Open log file and disable buffering
BOOL init_logger(const char *path) {
  if (!p_vsnprintf) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
      p_vsnprintf = (PVSNPRINTF)CustomGetProcAddress(hNtdll, "_vsnprintf");
    }
  }

  hLogFile =
      CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
  if (hLogFile == INVALID_HANDLE_VALUE)
    return FALSE;
  return TRUE;
}

// Close log file
void close_logger(void) {
  if (hLogFile != INVALID_HANDLE_VALUE) {
    CloseHandle(hLogFile);
    hLogFile = INVALID_HANDLE_VALUE;
  }
}

// Internal log formatter
static void log_formatted(const char *prefix, const char *fmt, va_list args) {
  if (hLogFile == INVALID_HANDLE_VALUE || !p_vsnprintf)
    return;

  char buffer[2048];
  DWORD written;

  int len = p_vsnprintf(buffer, sizeof(buffer) - 1, fmt, args);
  if (len < 0)
    return;
  buffer[len] = '\0';

  WriteFile(hLogFile, "[", 1, &written, NULL);
  WriteFile(hLogFile, prefix, (DWORD)custom_strlen(prefix), &written, NULL);
  WriteFile(hLogFile, "] ", 2, &written, NULL);
  WriteFile(hLogFile, buffer, (DWORD)len, &written, NULL);
  WriteFile(hLogFile, "\n", 1, &written, NULL);
  FlushFileBuffers(hLogFile);
}

void log_info(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  log_formatted("*", fmt, args);
  va_end(args);
}

void log_error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  log_formatted("ERROR", fmt, args);
  va_end(args);
}

void log_success(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  log_formatted("+", fmt, args);
  va_end(args);
}
