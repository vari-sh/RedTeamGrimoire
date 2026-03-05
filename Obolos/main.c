#include "engine.h"

// Define function pointer type for the syscall
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

// Extern global syscall list from the engine
extern SYSCALL_LIST SyscallList;

int main() {
    printf("[*] Initializing Syscall Engine...\n");
    if (!InitEngine()) {
        printf("[!] Engine initialization failed.\n");
        return 1;
    }
    printf("[+] Engine ready! Masks are preloaded.\n");

    // 1. Locate the target Syscall by its djb2 hash
    // Hash for "NtAllocateVirtualMemory" is 0x75080f0c0575e538
    DWORD64 hAlloc = djb2((PBYTE)"NtAllocateVirtualMemory"); 
    int idxAllocate = -1;
    
    for (int i = 0; i < SyscallList.Count; i++) {
        if (SyscallList.Entries[i].dwHash == hAlloc) {
            idxAllocate = i;
            break;
        }
    }

    if (idxAllocate == -1) {
        printf("[!] Syscall not found.\n");
        return 1;
    }

    // 2. Map the function pointer to the respective ASM stub dynamically
    // Each stub is exactly 16 bytes long, so we multiply the index by 16 (0x10)
    PBYTE pStubBase = (PBYTE)&Fnc0000;
    fnNtAllocateVirtualMemory pAlloc = (fnNtAllocateVirtualMemory)(pStubBase + (idxAllocate * 16));

    // 3. Execute safely using the preloaded Mask_Worker
    PVOID pMem = NULL;
    SIZE_T sSize = 4096;
    printf("[*] Executing NtAllocateVirtualMemory...\n");
    
    // Using (HANDLE)-1 for current process
    NTSTATUS status = ExecuteSyscall(pAlloc, Mask_Worker, (HANDLE)-1, &pMem, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status == 0) {
        printf("[+] Memory allocated successfully at %p\n", pMem);
    } else {
        printf("[!] Allocation failed with NTSTATUS: 0x%X\n", status);
    }

    return 0;
}