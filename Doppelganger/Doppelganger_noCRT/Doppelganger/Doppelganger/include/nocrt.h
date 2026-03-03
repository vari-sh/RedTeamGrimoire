#pragma once
#include <windows.h>
#include <stddef.h>

// Memory functions
void* custom_malloc(size_t size);
void* custom_calloc(size_t num, size_t size);
void custom_free(void* ptr);

// String functions
size_t custom_strlen(const char* str);
int custom_strcmp(const char* s1, const char* s2);
int custom_stricmp(const char* s1, const char* s2);

// Memory operations intrinsic replacements
#ifdef __cplusplus
extern "C" {
#endif

void* __cdecl memset(void* dest, int c, size_t count);
void* __cdecl memcpy(void* dest, const void* src, size_t count);

#ifdef __cplusplus
}
#endif
