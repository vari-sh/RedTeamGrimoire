#include "nocrt.h"

// Defined to satisfy linker for floating point operations
int _fltused = 0;

void *custom_malloc(size_t size) {
  return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

void *custom_calloc(size_t num, size_t size) {
  return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, num * size);
}

void custom_free(void *ptr) {
  if (ptr) {
    HeapFree(GetProcessHeap(), 0, ptr);
  }
}

size_t custom_strlen(const char *str) {
  const char *s = str;
  while (*s)
    s++;
  return s - str;
}

int custom_strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

int custom_stricmp(const char *s1, const char *s2) { return lstrcmpiA(s1, s2); }

#pragma function(memset)
void *__cdecl memset(void *dest, int c, size_t count) {
  char *bytes = (char *)dest;
  while (count--) {
    *bytes++ = (char)c;
  }
  return dest;
}

#pragma function(memcpy)
void *__cdecl memcpy(void *dest, const void *src, size_t count) {
  char *d = (char *)dest;
  const char *s = (const char *)src;
  while (count--) {
    *d++ = *s++;
  }
  return dest;
}
