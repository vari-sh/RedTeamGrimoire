import random
import sys
import os

def generate_asm():
    base_file = "syscalls_base.asm"
    output_file = "syscalls.asm"
    stub_count = 512

    print(f"[*] Reading base template from {base_file}...")
    
    if not os.path.exists(base_file):
        print(f"[!] Error: {base_file} not found.")
        sys.exit(1)

    with open(base_file, "r") as f:
        base_content = f.read()

    print(f"[*] Generating {stub_count} polymorphic stubs...")
    
    stubs = ""
    for i in range(stub_count):
        stubs += f"    PUBLIC Fnc{i:04X}\n"
        stubs += f"    ALIGN 16\n"
        stubs += f"    Fnc{i:04X} PROC\n"
        
        # Standard instruction loading the index into EAX
        stubs += f"        mov eax, {i}\n"
        stubs += f"        jmp SyscallExec\n"
        
        # Random Junk / NOPs to fill remaining bytes (breaks block hash signature)
        # We need to fill 6 bytes (16 bytes total alignment - 10 bytes for mov+jmp)
        padding_type = random.randint(0, 2)
        
        if padding_type == 0:
            # 6 NOPs (1 byte each)
            stubs += "        nop\n" * 6
        elif padding_type == 1:
            # xchg r8, r8 (3 bytes) + 3 NOPs (1 byte each) = 6 bytes
            stubs += "        xchg r8, r8\n"
            stubs += "        nop\n" * 3
        else:
            # xchg ax, ax (2 bytes) + xchg ax, ax (2 bytes) + 2 NOPs = 6 bytes
            stubs += "        xchg ax, ax\n"
            stubs += "        xchg ax, ax\n"
            stubs += "        nop\n" * 2

        stubs += f"    Fnc{i:04X} ENDP\n\n"

    # End of the assembly file
    stubs += "end\n"

    print(f"[*] Writing final output to {output_file}...")
    with open(output_file, "w") as f:
        f.write(base_content)
        f.write("\n")
        f.write(stubs)

    print("[+] syscalls.asm generated successfully.")

if __name__ == "__main__":
    generate_asm()