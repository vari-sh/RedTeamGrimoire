#pragma once
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include "utils.h"


extern const char* XOR_KEY;
extern size_t key_len;

char* xor_decrypt_string(const unsigned char* cipher, size_t len, const char* key, size_t key_len);
void xor_buffer(unsigned char* buffer, size_t len, const char* key, size_t key_len);
HMODULE LoadCleanDLL(char* dllPath);
FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpApiName);
wchar_t* to_wide(const char* str);