#pragma once
#include <windows.h>

// Structure containing the three useful offsets
typedef struct _Offsets {
    DWORD64 ActiveProcessLinks;  // Offset of the ActiveProcessLinks field in _EPROCESS
    DWORD64 ImageFileName;       // Offset of the ImageFileName field in _EPROCESS
    DWORD64 Protection;          // Offset of the Protection (PS_PROTECTION) field in _EPROCESS
} Offsets;

// Function do get correct OS offsets
Offsets getOffsets();