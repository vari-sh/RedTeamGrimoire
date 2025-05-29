#!/usr/bin/env python3

def xor_encrypt(api_name: str, key: str):
    key_bytes = key.encode()
    encrypted = []
    for i, c in enumerate(api_name.encode()):
        encrypted.append(c ^ key_bytes[i % len(key_bytes)])
    return encrypted

def format_bytes(byte_list):
    return ', '.join(f'0x{b:02X}' for b in byte_list)

def main():
    key = "0123456789abcdefghij"  # XOR Key
    api_names = [
        "Process32FirstW",
        "Process32NextW",
        "OpenProcess",
        "GetProcAddress",
        "NtCreateProcessEx",
        "CreateToolhelp32Snapshot",
        "OpenProcessToken",
        "DuplicateTokenEx",
        "ImpersonateLoggedOnUser",
        "SetThreadToken",
        "AdjustTokenPrivileges",
        "LookupPrivilegeValueW",
        "MiniDumpWriteDump",
        "GetProcessId",
        "GetCurrentProcess",
        "CreateFileA",
        "DeviceIoControl",
        "LoadLibraryW",
        "EnumDeviceDrivers",
        "OpenSCManagerA",
        "CreateServiceA",
        "OpenServiceA",
        "StartServiceA",
        "ControlService",
        "DeleteService",
        "CloseServiceHandle"
    ]

    for api in api_names:
        encrypted = xor_encrypt(api, key)
        formatted = format_bytes(encrypted)
        print(f"{api} = {{ {formatted} }}")

if __name__ == "__main__":
    main()
