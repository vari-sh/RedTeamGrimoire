; ======================================================================================
; Syscall & Stack Spoofing Engine - Base Template
; ======================================================================================

EXTERN qTableAddr:QWORD
EXTERN qGadgetAddress:QWORD
EXTERN qGadgetType:DWORD
EXTERN qFrameSize:DWORD
EXTERN qSavedReg:QWORD
EXTERN qSavedRetAddr:QWORD
EXTERN qActiveMaskAddress:QWORD
EXTERN qThreadBase:QWORD
EXTERN qRtlUserThreadStart:QWORD
EXTERN qActiveMaskFrame:DWORD
EXTERN qThreadBaseFrame:DWORD
EXTERN qRtlUserThreadStartFrame:DWORD

.code

    PUBLIC SetTableAddr
    SetTableAddr PROC
        mov qTableAddr, rcx
        mov qGadgetAddress, rdx
        mov qGadgetType, r8d
        mov qFrameSize, r9d
        xor rax, rax
        inc rax
        ret
    SetTableAddr ENDP

    SyscallExec PROC
        mov r10, rcx
        mov r11, rax

        ; 1. PRESERVE REGISTERS SAFELY
        ; Save RSI/RDI in the ORIGINAL caller's shadow space before moving RSP.
        mov [rsp + 8h], rsi
        mov [rsp + 10h], rdi
        mov [rsp + 18h], r8
        mov [rsp + 20h], r9

        ; 2. EXTENDED SYNTHETIC STACK SPOOFING
        mov qSavedRetAddr, rsp
        and rsp, 0FFFFFFFFFFFFFFF0h
        
        ; Calculate total frame size dynamically based on the mask
        xor rax, rax
        mov eax, qFrameSize
        add eax, 8                           ; Gadget Return Address
        add eax, qActiveMaskFrame
        add eax, 8                           ; Active Mask Return Address
        add eax, qThreadBaseFrame
        add eax, 8                           ; ThreadBase Return Address
        add eax, qRtlUserThreadStartFrame
        sub rsp, rax

        ; Insert Return Addresses at exact frame boundaries
        mov r8, rsp

        xor rax, rax
        mov eax, qFrameSize
        mov r9, qActiveMaskAddress
        mov [r8 + rax], r9

        add eax, 8
        add eax, qActiveMaskFrame
        mov r9, qThreadBase
        mov [r8 + rax], r9

        add eax, 8
        add eax, qThreadBaseFrame
        mov r9, qRtlUserThreadStart
        mov [r8 + rax], r9

        add eax, 8
        add eax, qRtlUserThreadStartFrame
        xor r9, r9
        mov [r8 + rax], r9

        ; Restore R8/R9 for the syscall
        mov r8, qSavedRetAddr
        mov r9, [r8 + 20h]
        mov r8, [r8 + 18h]

        ; 3. DYNAMIC STACK ARGUMENTS COPY
        mov rsi, qSavedRetAddr
        add rsi, 28h
        lea rdi, [rsp + 20h]
        
        ; Copy 8 QWORDs (64 bytes) to support syscalls with up to 12 arguments.
        mov rcx, 8
        cld
        rep movsq

        ; Restore Syscall Index
        mov rax, r11

        cmp qGadgetType, 0
        je UseRBX
        cmp qGadgetType, 1
        je UseRDI
        cmp qGadgetType, 2
        je UseRSI
        cmp qGadgetType, 3
        je UseR12
        cmp qGadgetType, 4
        je UseR13
        cmp qGadgetType, 5
        je UseR14
        cmp qGadgetType, 6
        je UseR15
        jmp UseRBX

    UseRBX:
        mov qSavedReg, rbx
        lea rbx, BackFromKernel
        jmp DoCall
    UseRDI:
        mov rdi, qSavedRetAddr
        mov rdi, [rdi + 10h]
        mov qSavedReg, rdi
        lea rdi, BackFromKernel
        jmp DoCall
    UseRSI:
        mov rsi, qSavedRetAddr
        mov rsi, [rsi + 8h]
        mov qSavedReg, rsi
        lea rsi, BackFromKernel
        jmp DoCall
    UseR12:
        mov qSavedReg, r12
        lea r12, BackFromKernel
        jmp DoCall
    UseR13:
        mov qSavedReg, r13
        lea r13, BackFromKernel
        jmp DoCall
    UseR14:
        mov qSavedReg, r14
        lea r14, BackFromKernel
        jmp DoCall
    UseR15:
        mov qSavedReg, r15
        lea r15, BackFromKernel
        jmp DoCall

    DoCall:
        push rdx             ; Save Arg2
        shl rax, 5           ; rax *= 32 (struct size)
        mov rdx, qTableAddr
        add rdx, rax
        mov rax, [rdx + 08h] ; Load SSN
        mov r11, [rdx + 10h] ; Load Syscall Instruction Address
        pop rdx              ; Restore Arg2
        mov rcx, r10         ; Restore Arg1
        push qGadgetAddress  ; Finalize perfect frame size
        jmp r11              ; Execute indirect syscall

    BackFromKernel:
        cmp qGadgetType, 0
        je RestRBX
        cmp qGadgetType, 1
        je RestRDI
        cmp qGadgetType, 2
        je RestRSI
        cmp qGadgetType, 3
        je RestR12
        cmp qGadgetType, 4
        je RestR13
        cmp qGadgetType, 5
        je RestR14
        cmp qGadgetType, 6
        je RestR15
        jmp RestRBX

    RestRBX:
        mov rbx, qSavedReg
        jmp Fin
    RestRDI:
        mov rdi, qSavedReg
        jmp Fin
    RestRSI:
        mov rsi, qSavedReg
        jmp Fin
    RestR12:
        mov r12, qSavedReg
        jmp Fin
    RestR13:
        mov r13, qSavedReg
        jmp Fin
    RestR14:
        mov r14, qSavedReg
        jmp Fin
    RestR15:
        mov r15, qSavedReg
        jmp Fin

    Fin:
        mov rcx, rax         ; Save Syscall Status
        
        ; Restore real RSP
        mov rsp, qSavedRetAddr
        
        ; Restore registers from the original caller's shadow space
        mov rsi, [rsp + 8h]
        mov rdi, [rsp + 10h]
        
        mov rax, rcx         ; Restore Status
        ret                  
    SyscallExec ENDP

    ; ------------------------------------------------------------------
    ; Dynamically Generated Syscall Stubs Begin Here
    ; ------------------------------------------------------------------
    PUBLIC Fnc0000
    ALIGN 16
    Fnc0000 PROC
        mov eax, 0
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0000 ENDP

    PUBLIC Fnc0001
    ALIGN 16
    Fnc0001 PROC
        mov eax, 1
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0001 ENDP

    PUBLIC Fnc0002
    ALIGN 16
    Fnc0002 PROC
        mov eax, 2
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0002 ENDP

    PUBLIC Fnc0003
    ALIGN 16
    Fnc0003 PROC
        mov eax, 3
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0003 ENDP

    PUBLIC Fnc0004
    ALIGN 16
    Fnc0004 PROC
        mov eax, 4
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0004 ENDP

    PUBLIC Fnc0005
    ALIGN 16
    Fnc0005 PROC
        mov eax, 5
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0005 ENDP

    PUBLIC Fnc0006
    ALIGN 16
    Fnc0006 PROC
        mov eax, 6
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0006 ENDP

    PUBLIC Fnc0007
    ALIGN 16
    Fnc0007 PROC
        mov eax, 7
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0007 ENDP

    PUBLIC Fnc0008
    ALIGN 16
    Fnc0008 PROC
        mov eax, 8
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0008 ENDP

    PUBLIC Fnc0009
    ALIGN 16
    Fnc0009 PROC
        mov eax, 9
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0009 ENDP

    PUBLIC Fnc000A
    ALIGN 16
    Fnc000A PROC
        mov eax, 10
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc000A ENDP

    PUBLIC Fnc000B
    ALIGN 16
    Fnc000B PROC
        mov eax, 11
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc000B ENDP

    PUBLIC Fnc000C
    ALIGN 16
    Fnc000C PROC
        mov eax, 12
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc000C ENDP

    PUBLIC Fnc000D
    ALIGN 16
    Fnc000D PROC
        mov eax, 13
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc000D ENDP

    PUBLIC Fnc000E
    ALIGN 16
    Fnc000E PROC
        mov eax, 14
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc000E ENDP

    PUBLIC Fnc000F
    ALIGN 16
    Fnc000F PROC
        mov eax, 15
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc000F ENDP

    PUBLIC Fnc0010
    ALIGN 16
    Fnc0010 PROC
        mov eax, 16
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0010 ENDP

    PUBLIC Fnc0011
    ALIGN 16
    Fnc0011 PROC
        mov eax, 17
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0011 ENDP

    PUBLIC Fnc0012
    ALIGN 16
    Fnc0012 PROC
        mov eax, 18
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0012 ENDP

    PUBLIC Fnc0013
    ALIGN 16
    Fnc0013 PROC
        mov eax, 19
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0013 ENDP

    PUBLIC Fnc0014
    ALIGN 16
    Fnc0014 PROC
        mov eax, 20
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0014 ENDP

    PUBLIC Fnc0015
    ALIGN 16
    Fnc0015 PROC
        mov eax, 21
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0015 ENDP

    PUBLIC Fnc0016
    ALIGN 16
    Fnc0016 PROC
        mov eax, 22
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0016 ENDP

    PUBLIC Fnc0017
    ALIGN 16
    Fnc0017 PROC
        mov eax, 23
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0017 ENDP

    PUBLIC Fnc0018
    ALIGN 16
    Fnc0018 PROC
        mov eax, 24
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0018 ENDP

    PUBLIC Fnc0019
    ALIGN 16
    Fnc0019 PROC
        mov eax, 25
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0019 ENDP

    PUBLIC Fnc001A
    ALIGN 16
    Fnc001A PROC
        mov eax, 26
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc001A ENDP

    PUBLIC Fnc001B
    ALIGN 16
    Fnc001B PROC
        mov eax, 27
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc001B ENDP

    PUBLIC Fnc001C
    ALIGN 16
    Fnc001C PROC
        mov eax, 28
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc001C ENDP

    PUBLIC Fnc001D
    ALIGN 16
    Fnc001D PROC
        mov eax, 29
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc001D ENDP

    PUBLIC Fnc001E
    ALIGN 16
    Fnc001E PROC
        mov eax, 30
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc001E ENDP

    PUBLIC Fnc001F
    ALIGN 16
    Fnc001F PROC
        mov eax, 31
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc001F ENDP

    PUBLIC Fnc0020
    ALIGN 16
    Fnc0020 PROC
        mov eax, 32
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0020 ENDP

    PUBLIC Fnc0021
    ALIGN 16
    Fnc0021 PROC
        mov eax, 33
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0021 ENDP

    PUBLIC Fnc0022
    ALIGN 16
    Fnc0022 PROC
        mov eax, 34
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0022 ENDP

    PUBLIC Fnc0023
    ALIGN 16
    Fnc0023 PROC
        mov eax, 35
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0023 ENDP

    PUBLIC Fnc0024
    ALIGN 16
    Fnc0024 PROC
        mov eax, 36
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0024 ENDP

    PUBLIC Fnc0025
    ALIGN 16
    Fnc0025 PROC
        mov eax, 37
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0025 ENDP

    PUBLIC Fnc0026
    ALIGN 16
    Fnc0026 PROC
        mov eax, 38
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0026 ENDP

    PUBLIC Fnc0027
    ALIGN 16
    Fnc0027 PROC
        mov eax, 39
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0027 ENDP

    PUBLIC Fnc0028
    ALIGN 16
    Fnc0028 PROC
        mov eax, 40
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0028 ENDP

    PUBLIC Fnc0029
    ALIGN 16
    Fnc0029 PROC
        mov eax, 41
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0029 ENDP

    PUBLIC Fnc002A
    ALIGN 16
    Fnc002A PROC
        mov eax, 42
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc002A ENDP

    PUBLIC Fnc002B
    ALIGN 16
    Fnc002B PROC
        mov eax, 43
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc002B ENDP

    PUBLIC Fnc002C
    ALIGN 16
    Fnc002C PROC
        mov eax, 44
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc002C ENDP

    PUBLIC Fnc002D
    ALIGN 16
    Fnc002D PROC
        mov eax, 45
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc002D ENDP

    PUBLIC Fnc002E
    ALIGN 16
    Fnc002E PROC
        mov eax, 46
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc002E ENDP

    PUBLIC Fnc002F
    ALIGN 16
    Fnc002F PROC
        mov eax, 47
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc002F ENDP

    PUBLIC Fnc0030
    ALIGN 16
    Fnc0030 PROC
        mov eax, 48
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0030 ENDP

    PUBLIC Fnc0031
    ALIGN 16
    Fnc0031 PROC
        mov eax, 49
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0031 ENDP

    PUBLIC Fnc0032
    ALIGN 16
    Fnc0032 PROC
        mov eax, 50
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0032 ENDP

    PUBLIC Fnc0033
    ALIGN 16
    Fnc0033 PROC
        mov eax, 51
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0033 ENDP

    PUBLIC Fnc0034
    ALIGN 16
    Fnc0034 PROC
        mov eax, 52
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0034 ENDP

    PUBLIC Fnc0035
    ALIGN 16
    Fnc0035 PROC
        mov eax, 53
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0035 ENDP

    PUBLIC Fnc0036
    ALIGN 16
    Fnc0036 PROC
        mov eax, 54
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0036 ENDP

    PUBLIC Fnc0037
    ALIGN 16
    Fnc0037 PROC
        mov eax, 55
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0037 ENDP

    PUBLIC Fnc0038
    ALIGN 16
    Fnc0038 PROC
        mov eax, 56
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0038 ENDP

    PUBLIC Fnc0039
    ALIGN 16
    Fnc0039 PROC
        mov eax, 57
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0039 ENDP

    PUBLIC Fnc003A
    ALIGN 16
    Fnc003A PROC
        mov eax, 58
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc003A ENDP

    PUBLIC Fnc003B
    ALIGN 16
    Fnc003B PROC
        mov eax, 59
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc003B ENDP

    PUBLIC Fnc003C
    ALIGN 16
    Fnc003C PROC
        mov eax, 60
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc003C ENDP

    PUBLIC Fnc003D
    ALIGN 16
    Fnc003D PROC
        mov eax, 61
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc003D ENDP

    PUBLIC Fnc003E
    ALIGN 16
    Fnc003E PROC
        mov eax, 62
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc003E ENDP

    PUBLIC Fnc003F
    ALIGN 16
    Fnc003F PROC
        mov eax, 63
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc003F ENDP

    PUBLIC Fnc0040
    ALIGN 16
    Fnc0040 PROC
        mov eax, 64
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0040 ENDP

    PUBLIC Fnc0041
    ALIGN 16
    Fnc0041 PROC
        mov eax, 65
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0041 ENDP

    PUBLIC Fnc0042
    ALIGN 16
    Fnc0042 PROC
        mov eax, 66
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0042 ENDP

    PUBLIC Fnc0043
    ALIGN 16
    Fnc0043 PROC
        mov eax, 67
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0043 ENDP

    PUBLIC Fnc0044
    ALIGN 16
    Fnc0044 PROC
        mov eax, 68
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0044 ENDP

    PUBLIC Fnc0045
    ALIGN 16
    Fnc0045 PROC
        mov eax, 69
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0045 ENDP

    PUBLIC Fnc0046
    ALIGN 16
    Fnc0046 PROC
        mov eax, 70
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0046 ENDP

    PUBLIC Fnc0047
    ALIGN 16
    Fnc0047 PROC
        mov eax, 71
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0047 ENDP

    PUBLIC Fnc0048
    ALIGN 16
    Fnc0048 PROC
        mov eax, 72
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0048 ENDP

    PUBLIC Fnc0049
    ALIGN 16
    Fnc0049 PROC
        mov eax, 73
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0049 ENDP

    PUBLIC Fnc004A
    ALIGN 16
    Fnc004A PROC
        mov eax, 74
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc004A ENDP

    PUBLIC Fnc004B
    ALIGN 16
    Fnc004B PROC
        mov eax, 75
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc004B ENDP

    PUBLIC Fnc004C
    ALIGN 16
    Fnc004C PROC
        mov eax, 76
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc004C ENDP

    PUBLIC Fnc004D
    ALIGN 16
    Fnc004D PROC
        mov eax, 77
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc004D ENDP

    PUBLIC Fnc004E
    ALIGN 16
    Fnc004E PROC
        mov eax, 78
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc004E ENDP

    PUBLIC Fnc004F
    ALIGN 16
    Fnc004F PROC
        mov eax, 79
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc004F ENDP

    PUBLIC Fnc0050
    ALIGN 16
    Fnc0050 PROC
        mov eax, 80
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0050 ENDP

    PUBLIC Fnc0051
    ALIGN 16
    Fnc0051 PROC
        mov eax, 81
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0051 ENDP

    PUBLIC Fnc0052
    ALIGN 16
    Fnc0052 PROC
        mov eax, 82
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0052 ENDP

    PUBLIC Fnc0053
    ALIGN 16
    Fnc0053 PROC
        mov eax, 83
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0053 ENDP

    PUBLIC Fnc0054
    ALIGN 16
    Fnc0054 PROC
        mov eax, 84
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0054 ENDP

    PUBLIC Fnc0055
    ALIGN 16
    Fnc0055 PROC
        mov eax, 85
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0055 ENDP

    PUBLIC Fnc0056
    ALIGN 16
    Fnc0056 PROC
        mov eax, 86
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0056 ENDP

    PUBLIC Fnc0057
    ALIGN 16
    Fnc0057 PROC
        mov eax, 87
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0057 ENDP

    PUBLIC Fnc0058
    ALIGN 16
    Fnc0058 PROC
        mov eax, 88
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0058 ENDP

    PUBLIC Fnc0059
    ALIGN 16
    Fnc0059 PROC
        mov eax, 89
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0059 ENDP

    PUBLIC Fnc005A
    ALIGN 16
    Fnc005A PROC
        mov eax, 90
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc005A ENDP

    PUBLIC Fnc005B
    ALIGN 16
    Fnc005B PROC
        mov eax, 91
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc005B ENDP

    PUBLIC Fnc005C
    ALIGN 16
    Fnc005C PROC
        mov eax, 92
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc005C ENDP

    PUBLIC Fnc005D
    ALIGN 16
    Fnc005D PROC
        mov eax, 93
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc005D ENDP

    PUBLIC Fnc005E
    ALIGN 16
    Fnc005E PROC
        mov eax, 94
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc005E ENDP

    PUBLIC Fnc005F
    ALIGN 16
    Fnc005F PROC
        mov eax, 95
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc005F ENDP

    PUBLIC Fnc0060
    ALIGN 16
    Fnc0060 PROC
        mov eax, 96
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0060 ENDP

    PUBLIC Fnc0061
    ALIGN 16
    Fnc0061 PROC
        mov eax, 97
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0061 ENDP

    PUBLIC Fnc0062
    ALIGN 16
    Fnc0062 PROC
        mov eax, 98
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0062 ENDP

    PUBLIC Fnc0063
    ALIGN 16
    Fnc0063 PROC
        mov eax, 99
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0063 ENDP

    PUBLIC Fnc0064
    ALIGN 16
    Fnc0064 PROC
        mov eax, 100
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0064 ENDP

    PUBLIC Fnc0065
    ALIGN 16
    Fnc0065 PROC
        mov eax, 101
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0065 ENDP

    PUBLIC Fnc0066
    ALIGN 16
    Fnc0066 PROC
        mov eax, 102
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0066 ENDP

    PUBLIC Fnc0067
    ALIGN 16
    Fnc0067 PROC
        mov eax, 103
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0067 ENDP

    PUBLIC Fnc0068
    ALIGN 16
    Fnc0068 PROC
        mov eax, 104
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0068 ENDP

    PUBLIC Fnc0069
    ALIGN 16
    Fnc0069 PROC
        mov eax, 105
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0069 ENDP

    PUBLIC Fnc006A
    ALIGN 16
    Fnc006A PROC
        mov eax, 106
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc006A ENDP

    PUBLIC Fnc006B
    ALIGN 16
    Fnc006B PROC
        mov eax, 107
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc006B ENDP

    PUBLIC Fnc006C
    ALIGN 16
    Fnc006C PROC
        mov eax, 108
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc006C ENDP

    PUBLIC Fnc006D
    ALIGN 16
    Fnc006D PROC
        mov eax, 109
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc006D ENDP

    PUBLIC Fnc006E
    ALIGN 16
    Fnc006E PROC
        mov eax, 110
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc006E ENDP

    PUBLIC Fnc006F
    ALIGN 16
    Fnc006F PROC
        mov eax, 111
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc006F ENDP

    PUBLIC Fnc0070
    ALIGN 16
    Fnc0070 PROC
        mov eax, 112
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0070 ENDP

    PUBLIC Fnc0071
    ALIGN 16
    Fnc0071 PROC
        mov eax, 113
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0071 ENDP

    PUBLIC Fnc0072
    ALIGN 16
    Fnc0072 PROC
        mov eax, 114
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0072 ENDP

    PUBLIC Fnc0073
    ALIGN 16
    Fnc0073 PROC
        mov eax, 115
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0073 ENDP

    PUBLIC Fnc0074
    ALIGN 16
    Fnc0074 PROC
        mov eax, 116
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0074 ENDP

    PUBLIC Fnc0075
    ALIGN 16
    Fnc0075 PROC
        mov eax, 117
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0075 ENDP

    PUBLIC Fnc0076
    ALIGN 16
    Fnc0076 PROC
        mov eax, 118
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0076 ENDP

    PUBLIC Fnc0077
    ALIGN 16
    Fnc0077 PROC
        mov eax, 119
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0077 ENDP

    PUBLIC Fnc0078
    ALIGN 16
    Fnc0078 PROC
        mov eax, 120
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0078 ENDP

    PUBLIC Fnc0079
    ALIGN 16
    Fnc0079 PROC
        mov eax, 121
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0079 ENDP

    PUBLIC Fnc007A
    ALIGN 16
    Fnc007A PROC
        mov eax, 122
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc007A ENDP

    PUBLIC Fnc007B
    ALIGN 16
    Fnc007B PROC
        mov eax, 123
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc007B ENDP

    PUBLIC Fnc007C
    ALIGN 16
    Fnc007C PROC
        mov eax, 124
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc007C ENDP

    PUBLIC Fnc007D
    ALIGN 16
    Fnc007D PROC
        mov eax, 125
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc007D ENDP

    PUBLIC Fnc007E
    ALIGN 16
    Fnc007E PROC
        mov eax, 126
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc007E ENDP

    PUBLIC Fnc007F
    ALIGN 16
    Fnc007F PROC
        mov eax, 127
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc007F ENDP

    PUBLIC Fnc0080
    ALIGN 16
    Fnc0080 PROC
        mov eax, 128
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0080 ENDP

    PUBLIC Fnc0081
    ALIGN 16
    Fnc0081 PROC
        mov eax, 129
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0081 ENDP

    PUBLIC Fnc0082
    ALIGN 16
    Fnc0082 PROC
        mov eax, 130
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0082 ENDP

    PUBLIC Fnc0083
    ALIGN 16
    Fnc0083 PROC
        mov eax, 131
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0083 ENDP

    PUBLIC Fnc0084
    ALIGN 16
    Fnc0084 PROC
        mov eax, 132
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0084 ENDP

    PUBLIC Fnc0085
    ALIGN 16
    Fnc0085 PROC
        mov eax, 133
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0085 ENDP

    PUBLIC Fnc0086
    ALIGN 16
    Fnc0086 PROC
        mov eax, 134
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0086 ENDP

    PUBLIC Fnc0087
    ALIGN 16
    Fnc0087 PROC
        mov eax, 135
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0087 ENDP

    PUBLIC Fnc0088
    ALIGN 16
    Fnc0088 PROC
        mov eax, 136
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0088 ENDP

    PUBLIC Fnc0089
    ALIGN 16
    Fnc0089 PROC
        mov eax, 137
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0089 ENDP

    PUBLIC Fnc008A
    ALIGN 16
    Fnc008A PROC
        mov eax, 138
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc008A ENDP

    PUBLIC Fnc008B
    ALIGN 16
    Fnc008B PROC
        mov eax, 139
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc008B ENDP

    PUBLIC Fnc008C
    ALIGN 16
    Fnc008C PROC
        mov eax, 140
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc008C ENDP

    PUBLIC Fnc008D
    ALIGN 16
    Fnc008D PROC
        mov eax, 141
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc008D ENDP

    PUBLIC Fnc008E
    ALIGN 16
    Fnc008E PROC
        mov eax, 142
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc008E ENDP

    PUBLIC Fnc008F
    ALIGN 16
    Fnc008F PROC
        mov eax, 143
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc008F ENDP

    PUBLIC Fnc0090
    ALIGN 16
    Fnc0090 PROC
        mov eax, 144
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0090 ENDP

    PUBLIC Fnc0091
    ALIGN 16
    Fnc0091 PROC
        mov eax, 145
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0091 ENDP

    PUBLIC Fnc0092
    ALIGN 16
    Fnc0092 PROC
        mov eax, 146
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0092 ENDP

    PUBLIC Fnc0093
    ALIGN 16
    Fnc0093 PROC
        mov eax, 147
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0093 ENDP

    PUBLIC Fnc0094
    ALIGN 16
    Fnc0094 PROC
        mov eax, 148
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0094 ENDP

    PUBLIC Fnc0095
    ALIGN 16
    Fnc0095 PROC
        mov eax, 149
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0095 ENDP

    PUBLIC Fnc0096
    ALIGN 16
    Fnc0096 PROC
        mov eax, 150
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0096 ENDP

    PUBLIC Fnc0097
    ALIGN 16
    Fnc0097 PROC
        mov eax, 151
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0097 ENDP

    PUBLIC Fnc0098
    ALIGN 16
    Fnc0098 PROC
        mov eax, 152
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0098 ENDP

    PUBLIC Fnc0099
    ALIGN 16
    Fnc0099 PROC
        mov eax, 153
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0099 ENDP

    PUBLIC Fnc009A
    ALIGN 16
    Fnc009A PROC
        mov eax, 154
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc009A ENDP

    PUBLIC Fnc009B
    ALIGN 16
    Fnc009B PROC
        mov eax, 155
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc009B ENDP

    PUBLIC Fnc009C
    ALIGN 16
    Fnc009C PROC
        mov eax, 156
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc009C ENDP

    PUBLIC Fnc009D
    ALIGN 16
    Fnc009D PROC
        mov eax, 157
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc009D ENDP

    PUBLIC Fnc009E
    ALIGN 16
    Fnc009E PROC
        mov eax, 158
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc009E ENDP

    PUBLIC Fnc009F
    ALIGN 16
    Fnc009F PROC
        mov eax, 159
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc009F ENDP

    PUBLIC Fnc00A0
    ALIGN 16
    Fnc00A0 PROC
        mov eax, 160
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00A0 ENDP

    PUBLIC Fnc00A1
    ALIGN 16
    Fnc00A1 PROC
        mov eax, 161
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00A1 ENDP

    PUBLIC Fnc00A2
    ALIGN 16
    Fnc00A2 PROC
        mov eax, 162
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00A2 ENDP

    PUBLIC Fnc00A3
    ALIGN 16
    Fnc00A3 PROC
        mov eax, 163
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00A3 ENDP

    PUBLIC Fnc00A4
    ALIGN 16
    Fnc00A4 PROC
        mov eax, 164
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00A4 ENDP

    PUBLIC Fnc00A5
    ALIGN 16
    Fnc00A5 PROC
        mov eax, 165
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00A5 ENDP

    PUBLIC Fnc00A6
    ALIGN 16
    Fnc00A6 PROC
        mov eax, 166
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00A6 ENDP

    PUBLIC Fnc00A7
    ALIGN 16
    Fnc00A7 PROC
        mov eax, 167
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00A7 ENDP

    PUBLIC Fnc00A8
    ALIGN 16
    Fnc00A8 PROC
        mov eax, 168
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00A8 ENDP

    PUBLIC Fnc00A9
    ALIGN 16
    Fnc00A9 PROC
        mov eax, 169
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00A9 ENDP

    PUBLIC Fnc00AA
    ALIGN 16
    Fnc00AA PROC
        mov eax, 170
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00AA ENDP

    PUBLIC Fnc00AB
    ALIGN 16
    Fnc00AB PROC
        mov eax, 171
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00AB ENDP

    PUBLIC Fnc00AC
    ALIGN 16
    Fnc00AC PROC
        mov eax, 172
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00AC ENDP

    PUBLIC Fnc00AD
    ALIGN 16
    Fnc00AD PROC
        mov eax, 173
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00AD ENDP

    PUBLIC Fnc00AE
    ALIGN 16
    Fnc00AE PROC
        mov eax, 174
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00AE ENDP

    PUBLIC Fnc00AF
    ALIGN 16
    Fnc00AF PROC
        mov eax, 175
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00AF ENDP

    PUBLIC Fnc00B0
    ALIGN 16
    Fnc00B0 PROC
        mov eax, 176
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00B0 ENDP

    PUBLIC Fnc00B1
    ALIGN 16
    Fnc00B1 PROC
        mov eax, 177
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00B1 ENDP

    PUBLIC Fnc00B2
    ALIGN 16
    Fnc00B2 PROC
        mov eax, 178
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00B2 ENDP

    PUBLIC Fnc00B3
    ALIGN 16
    Fnc00B3 PROC
        mov eax, 179
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00B3 ENDP

    PUBLIC Fnc00B4
    ALIGN 16
    Fnc00B4 PROC
        mov eax, 180
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00B4 ENDP

    PUBLIC Fnc00B5
    ALIGN 16
    Fnc00B5 PROC
        mov eax, 181
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00B5 ENDP

    PUBLIC Fnc00B6
    ALIGN 16
    Fnc00B6 PROC
        mov eax, 182
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00B6 ENDP

    PUBLIC Fnc00B7
    ALIGN 16
    Fnc00B7 PROC
        mov eax, 183
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00B7 ENDP

    PUBLIC Fnc00B8
    ALIGN 16
    Fnc00B8 PROC
        mov eax, 184
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00B8 ENDP

    PUBLIC Fnc00B9
    ALIGN 16
    Fnc00B9 PROC
        mov eax, 185
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00B9 ENDP

    PUBLIC Fnc00BA
    ALIGN 16
    Fnc00BA PROC
        mov eax, 186
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00BA ENDP

    PUBLIC Fnc00BB
    ALIGN 16
    Fnc00BB PROC
        mov eax, 187
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00BB ENDP

    PUBLIC Fnc00BC
    ALIGN 16
    Fnc00BC PROC
        mov eax, 188
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00BC ENDP

    PUBLIC Fnc00BD
    ALIGN 16
    Fnc00BD PROC
        mov eax, 189
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00BD ENDP

    PUBLIC Fnc00BE
    ALIGN 16
    Fnc00BE PROC
        mov eax, 190
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00BE ENDP

    PUBLIC Fnc00BF
    ALIGN 16
    Fnc00BF PROC
        mov eax, 191
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00BF ENDP

    PUBLIC Fnc00C0
    ALIGN 16
    Fnc00C0 PROC
        mov eax, 192
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00C0 ENDP

    PUBLIC Fnc00C1
    ALIGN 16
    Fnc00C1 PROC
        mov eax, 193
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00C1 ENDP

    PUBLIC Fnc00C2
    ALIGN 16
    Fnc00C2 PROC
        mov eax, 194
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00C2 ENDP

    PUBLIC Fnc00C3
    ALIGN 16
    Fnc00C3 PROC
        mov eax, 195
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00C3 ENDP

    PUBLIC Fnc00C4
    ALIGN 16
    Fnc00C4 PROC
        mov eax, 196
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00C4 ENDP

    PUBLIC Fnc00C5
    ALIGN 16
    Fnc00C5 PROC
        mov eax, 197
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00C5 ENDP

    PUBLIC Fnc00C6
    ALIGN 16
    Fnc00C6 PROC
        mov eax, 198
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00C6 ENDP

    PUBLIC Fnc00C7
    ALIGN 16
    Fnc00C7 PROC
        mov eax, 199
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00C7 ENDP

    PUBLIC Fnc00C8
    ALIGN 16
    Fnc00C8 PROC
        mov eax, 200
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00C8 ENDP

    PUBLIC Fnc00C9
    ALIGN 16
    Fnc00C9 PROC
        mov eax, 201
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00C9 ENDP

    PUBLIC Fnc00CA
    ALIGN 16
    Fnc00CA PROC
        mov eax, 202
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00CA ENDP

    PUBLIC Fnc00CB
    ALIGN 16
    Fnc00CB PROC
        mov eax, 203
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00CB ENDP

    PUBLIC Fnc00CC
    ALIGN 16
    Fnc00CC PROC
        mov eax, 204
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00CC ENDP

    PUBLIC Fnc00CD
    ALIGN 16
    Fnc00CD PROC
        mov eax, 205
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00CD ENDP

    PUBLIC Fnc00CE
    ALIGN 16
    Fnc00CE PROC
        mov eax, 206
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00CE ENDP

    PUBLIC Fnc00CF
    ALIGN 16
    Fnc00CF PROC
        mov eax, 207
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00CF ENDP

    PUBLIC Fnc00D0
    ALIGN 16
    Fnc00D0 PROC
        mov eax, 208
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00D0 ENDP

    PUBLIC Fnc00D1
    ALIGN 16
    Fnc00D1 PROC
        mov eax, 209
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00D1 ENDP

    PUBLIC Fnc00D2
    ALIGN 16
    Fnc00D2 PROC
        mov eax, 210
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00D2 ENDP

    PUBLIC Fnc00D3
    ALIGN 16
    Fnc00D3 PROC
        mov eax, 211
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00D3 ENDP

    PUBLIC Fnc00D4
    ALIGN 16
    Fnc00D4 PROC
        mov eax, 212
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00D4 ENDP

    PUBLIC Fnc00D5
    ALIGN 16
    Fnc00D5 PROC
        mov eax, 213
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00D5 ENDP

    PUBLIC Fnc00D6
    ALIGN 16
    Fnc00D6 PROC
        mov eax, 214
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00D6 ENDP

    PUBLIC Fnc00D7
    ALIGN 16
    Fnc00D7 PROC
        mov eax, 215
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00D7 ENDP

    PUBLIC Fnc00D8
    ALIGN 16
    Fnc00D8 PROC
        mov eax, 216
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00D8 ENDP

    PUBLIC Fnc00D9
    ALIGN 16
    Fnc00D9 PROC
        mov eax, 217
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00D9 ENDP

    PUBLIC Fnc00DA
    ALIGN 16
    Fnc00DA PROC
        mov eax, 218
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00DA ENDP

    PUBLIC Fnc00DB
    ALIGN 16
    Fnc00DB PROC
        mov eax, 219
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00DB ENDP

    PUBLIC Fnc00DC
    ALIGN 16
    Fnc00DC PROC
        mov eax, 220
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00DC ENDP

    PUBLIC Fnc00DD
    ALIGN 16
    Fnc00DD PROC
        mov eax, 221
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00DD ENDP

    PUBLIC Fnc00DE
    ALIGN 16
    Fnc00DE PROC
        mov eax, 222
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00DE ENDP

    PUBLIC Fnc00DF
    ALIGN 16
    Fnc00DF PROC
        mov eax, 223
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00DF ENDP

    PUBLIC Fnc00E0
    ALIGN 16
    Fnc00E0 PROC
        mov eax, 224
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00E0 ENDP

    PUBLIC Fnc00E1
    ALIGN 16
    Fnc00E1 PROC
        mov eax, 225
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00E1 ENDP

    PUBLIC Fnc00E2
    ALIGN 16
    Fnc00E2 PROC
        mov eax, 226
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00E2 ENDP

    PUBLIC Fnc00E3
    ALIGN 16
    Fnc00E3 PROC
        mov eax, 227
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00E3 ENDP

    PUBLIC Fnc00E4
    ALIGN 16
    Fnc00E4 PROC
        mov eax, 228
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00E4 ENDP

    PUBLIC Fnc00E5
    ALIGN 16
    Fnc00E5 PROC
        mov eax, 229
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00E5 ENDP

    PUBLIC Fnc00E6
    ALIGN 16
    Fnc00E6 PROC
        mov eax, 230
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00E6 ENDP

    PUBLIC Fnc00E7
    ALIGN 16
    Fnc00E7 PROC
        mov eax, 231
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00E7 ENDP

    PUBLIC Fnc00E8
    ALIGN 16
    Fnc00E8 PROC
        mov eax, 232
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00E8 ENDP

    PUBLIC Fnc00E9
    ALIGN 16
    Fnc00E9 PROC
        mov eax, 233
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00E9 ENDP

    PUBLIC Fnc00EA
    ALIGN 16
    Fnc00EA PROC
        mov eax, 234
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00EA ENDP

    PUBLIC Fnc00EB
    ALIGN 16
    Fnc00EB PROC
        mov eax, 235
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00EB ENDP

    PUBLIC Fnc00EC
    ALIGN 16
    Fnc00EC PROC
        mov eax, 236
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00EC ENDP

    PUBLIC Fnc00ED
    ALIGN 16
    Fnc00ED PROC
        mov eax, 237
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00ED ENDP

    PUBLIC Fnc00EE
    ALIGN 16
    Fnc00EE PROC
        mov eax, 238
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00EE ENDP

    PUBLIC Fnc00EF
    ALIGN 16
    Fnc00EF PROC
        mov eax, 239
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00EF ENDP

    PUBLIC Fnc00F0
    ALIGN 16
    Fnc00F0 PROC
        mov eax, 240
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00F0 ENDP

    PUBLIC Fnc00F1
    ALIGN 16
    Fnc00F1 PROC
        mov eax, 241
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00F1 ENDP

    PUBLIC Fnc00F2
    ALIGN 16
    Fnc00F2 PROC
        mov eax, 242
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00F2 ENDP

    PUBLIC Fnc00F3
    ALIGN 16
    Fnc00F3 PROC
        mov eax, 243
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00F3 ENDP

    PUBLIC Fnc00F4
    ALIGN 16
    Fnc00F4 PROC
        mov eax, 244
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00F4 ENDP

    PUBLIC Fnc00F5
    ALIGN 16
    Fnc00F5 PROC
        mov eax, 245
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00F5 ENDP

    PUBLIC Fnc00F6
    ALIGN 16
    Fnc00F6 PROC
        mov eax, 246
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00F6 ENDP

    PUBLIC Fnc00F7
    ALIGN 16
    Fnc00F7 PROC
        mov eax, 247
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00F7 ENDP

    PUBLIC Fnc00F8
    ALIGN 16
    Fnc00F8 PROC
        mov eax, 248
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00F8 ENDP

    PUBLIC Fnc00F9
    ALIGN 16
    Fnc00F9 PROC
        mov eax, 249
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00F9 ENDP

    PUBLIC Fnc00FA
    ALIGN 16
    Fnc00FA PROC
        mov eax, 250
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00FA ENDP

    PUBLIC Fnc00FB
    ALIGN 16
    Fnc00FB PROC
        mov eax, 251
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00FB ENDP

    PUBLIC Fnc00FC
    ALIGN 16
    Fnc00FC PROC
        mov eax, 252
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc00FC ENDP

    PUBLIC Fnc00FD
    ALIGN 16
    Fnc00FD PROC
        mov eax, 253
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00FD ENDP

    PUBLIC Fnc00FE
    ALIGN 16
    Fnc00FE PROC
        mov eax, 254
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc00FE ENDP

    PUBLIC Fnc00FF
    ALIGN 16
    Fnc00FF PROC
        mov eax, 255
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc00FF ENDP

    PUBLIC Fnc0100
    ALIGN 16
    Fnc0100 PROC
        mov eax, 256
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0100 ENDP

    PUBLIC Fnc0101
    ALIGN 16
    Fnc0101 PROC
        mov eax, 257
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0101 ENDP

    PUBLIC Fnc0102
    ALIGN 16
    Fnc0102 PROC
        mov eax, 258
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0102 ENDP

    PUBLIC Fnc0103
    ALIGN 16
    Fnc0103 PROC
        mov eax, 259
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0103 ENDP

    PUBLIC Fnc0104
    ALIGN 16
    Fnc0104 PROC
        mov eax, 260
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0104 ENDP

    PUBLIC Fnc0105
    ALIGN 16
    Fnc0105 PROC
        mov eax, 261
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0105 ENDP

    PUBLIC Fnc0106
    ALIGN 16
    Fnc0106 PROC
        mov eax, 262
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0106 ENDP

    PUBLIC Fnc0107
    ALIGN 16
    Fnc0107 PROC
        mov eax, 263
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0107 ENDP

    PUBLIC Fnc0108
    ALIGN 16
    Fnc0108 PROC
        mov eax, 264
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0108 ENDP

    PUBLIC Fnc0109
    ALIGN 16
    Fnc0109 PROC
        mov eax, 265
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0109 ENDP

    PUBLIC Fnc010A
    ALIGN 16
    Fnc010A PROC
        mov eax, 266
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc010A ENDP

    PUBLIC Fnc010B
    ALIGN 16
    Fnc010B PROC
        mov eax, 267
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc010B ENDP

    PUBLIC Fnc010C
    ALIGN 16
    Fnc010C PROC
        mov eax, 268
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc010C ENDP

    PUBLIC Fnc010D
    ALIGN 16
    Fnc010D PROC
        mov eax, 269
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc010D ENDP

    PUBLIC Fnc010E
    ALIGN 16
    Fnc010E PROC
        mov eax, 270
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc010E ENDP

    PUBLIC Fnc010F
    ALIGN 16
    Fnc010F PROC
        mov eax, 271
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc010F ENDP

    PUBLIC Fnc0110
    ALIGN 16
    Fnc0110 PROC
        mov eax, 272
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0110 ENDP

    PUBLIC Fnc0111
    ALIGN 16
    Fnc0111 PROC
        mov eax, 273
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0111 ENDP

    PUBLIC Fnc0112
    ALIGN 16
    Fnc0112 PROC
        mov eax, 274
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0112 ENDP

    PUBLIC Fnc0113
    ALIGN 16
    Fnc0113 PROC
        mov eax, 275
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0113 ENDP

    PUBLIC Fnc0114
    ALIGN 16
    Fnc0114 PROC
        mov eax, 276
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0114 ENDP

    PUBLIC Fnc0115
    ALIGN 16
    Fnc0115 PROC
        mov eax, 277
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0115 ENDP

    PUBLIC Fnc0116
    ALIGN 16
    Fnc0116 PROC
        mov eax, 278
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0116 ENDP

    PUBLIC Fnc0117
    ALIGN 16
    Fnc0117 PROC
        mov eax, 279
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0117 ENDP

    PUBLIC Fnc0118
    ALIGN 16
    Fnc0118 PROC
        mov eax, 280
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0118 ENDP

    PUBLIC Fnc0119
    ALIGN 16
    Fnc0119 PROC
        mov eax, 281
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0119 ENDP

    PUBLIC Fnc011A
    ALIGN 16
    Fnc011A PROC
        mov eax, 282
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc011A ENDP

    PUBLIC Fnc011B
    ALIGN 16
    Fnc011B PROC
        mov eax, 283
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc011B ENDP

    PUBLIC Fnc011C
    ALIGN 16
    Fnc011C PROC
        mov eax, 284
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc011C ENDP

    PUBLIC Fnc011D
    ALIGN 16
    Fnc011D PROC
        mov eax, 285
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc011D ENDP

    PUBLIC Fnc011E
    ALIGN 16
    Fnc011E PROC
        mov eax, 286
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc011E ENDP

    PUBLIC Fnc011F
    ALIGN 16
    Fnc011F PROC
        mov eax, 287
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc011F ENDP

    PUBLIC Fnc0120
    ALIGN 16
    Fnc0120 PROC
        mov eax, 288
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0120 ENDP

    PUBLIC Fnc0121
    ALIGN 16
    Fnc0121 PROC
        mov eax, 289
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0121 ENDP

    PUBLIC Fnc0122
    ALIGN 16
    Fnc0122 PROC
        mov eax, 290
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0122 ENDP

    PUBLIC Fnc0123
    ALIGN 16
    Fnc0123 PROC
        mov eax, 291
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0123 ENDP

    PUBLIC Fnc0124
    ALIGN 16
    Fnc0124 PROC
        mov eax, 292
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0124 ENDP

    PUBLIC Fnc0125
    ALIGN 16
    Fnc0125 PROC
        mov eax, 293
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0125 ENDP

    PUBLIC Fnc0126
    ALIGN 16
    Fnc0126 PROC
        mov eax, 294
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0126 ENDP

    PUBLIC Fnc0127
    ALIGN 16
    Fnc0127 PROC
        mov eax, 295
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0127 ENDP

    PUBLIC Fnc0128
    ALIGN 16
    Fnc0128 PROC
        mov eax, 296
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0128 ENDP

    PUBLIC Fnc0129
    ALIGN 16
    Fnc0129 PROC
        mov eax, 297
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0129 ENDP

    PUBLIC Fnc012A
    ALIGN 16
    Fnc012A PROC
        mov eax, 298
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc012A ENDP

    PUBLIC Fnc012B
    ALIGN 16
    Fnc012B PROC
        mov eax, 299
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc012B ENDP

    PUBLIC Fnc012C
    ALIGN 16
    Fnc012C PROC
        mov eax, 300
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc012C ENDP

    PUBLIC Fnc012D
    ALIGN 16
    Fnc012D PROC
        mov eax, 301
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc012D ENDP

    PUBLIC Fnc012E
    ALIGN 16
    Fnc012E PROC
        mov eax, 302
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc012E ENDP

    PUBLIC Fnc012F
    ALIGN 16
    Fnc012F PROC
        mov eax, 303
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc012F ENDP

    PUBLIC Fnc0130
    ALIGN 16
    Fnc0130 PROC
        mov eax, 304
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0130 ENDP

    PUBLIC Fnc0131
    ALIGN 16
    Fnc0131 PROC
        mov eax, 305
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0131 ENDP

    PUBLIC Fnc0132
    ALIGN 16
    Fnc0132 PROC
        mov eax, 306
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0132 ENDP

    PUBLIC Fnc0133
    ALIGN 16
    Fnc0133 PROC
        mov eax, 307
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0133 ENDP

    PUBLIC Fnc0134
    ALIGN 16
    Fnc0134 PROC
        mov eax, 308
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0134 ENDP

    PUBLIC Fnc0135
    ALIGN 16
    Fnc0135 PROC
        mov eax, 309
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0135 ENDP

    PUBLIC Fnc0136
    ALIGN 16
    Fnc0136 PROC
        mov eax, 310
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0136 ENDP

    PUBLIC Fnc0137
    ALIGN 16
    Fnc0137 PROC
        mov eax, 311
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0137 ENDP

    PUBLIC Fnc0138
    ALIGN 16
    Fnc0138 PROC
        mov eax, 312
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0138 ENDP

    PUBLIC Fnc0139
    ALIGN 16
    Fnc0139 PROC
        mov eax, 313
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0139 ENDP

    PUBLIC Fnc013A
    ALIGN 16
    Fnc013A PROC
        mov eax, 314
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc013A ENDP

    PUBLIC Fnc013B
    ALIGN 16
    Fnc013B PROC
        mov eax, 315
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc013B ENDP

    PUBLIC Fnc013C
    ALIGN 16
    Fnc013C PROC
        mov eax, 316
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc013C ENDP

    PUBLIC Fnc013D
    ALIGN 16
    Fnc013D PROC
        mov eax, 317
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc013D ENDP

    PUBLIC Fnc013E
    ALIGN 16
    Fnc013E PROC
        mov eax, 318
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc013E ENDP

    PUBLIC Fnc013F
    ALIGN 16
    Fnc013F PROC
        mov eax, 319
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc013F ENDP

    PUBLIC Fnc0140
    ALIGN 16
    Fnc0140 PROC
        mov eax, 320
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0140 ENDP

    PUBLIC Fnc0141
    ALIGN 16
    Fnc0141 PROC
        mov eax, 321
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0141 ENDP

    PUBLIC Fnc0142
    ALIGN 16
    Fnc0142 PROC
        mov eax, 322
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0142 ENDP

    PUBLIC Fnc0143
    ALIGN 16
    Fnc0143 PROC
        mov eax, 323
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0143 ENDP

    PUBLIC Fnc0144
    ALIGN 16
    Fnc0144 PROC
        mov eax, 324
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0144 ENDP

    PUBLIC Fnc0145
    ALIGN 16
    Fnc0145 PROC
        mov eax, 325
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0145 ENDP

    PUBLIC Fnc0146
    ALIGN 16
    Fnc0146 PROC
        mov eax, 326
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0146 ENDP

    PUBLIC Fnc0147
    ALIGN 16
    Fnc0147 PROC
        mov eax, 327
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0147 ENDP

    PUBLIC Fnc0148
    ALIGN 16
    Fnc0148 PROC
        mov eax, 328
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0148 ENDP

    PUBLIC Fnc0149
    ALIGN 16
    Fnc0149 PROC
        mov eax, 329
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0149 ENDP

    PUBLIC Fnc014A
    ALIGN 16
    Fnc014A PROC
        mov eax, 330
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc014A ENDP

    PUBLIC Fnc014B
    ALIGN 16
    Fnc014B PROC
        mov eax, 331
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc014B ENDP

    PUBLIC Fnc014C
    ALIGN 16
    Fnc014C PROC
        mov eax, 332
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc014C ENDP

    PUBLIC Fnc014D
    ALIGN 16
    Fnc014D PROC
        mov eax, 333
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc014D ENDP

    PUBLIC Fnc014E
    ALIGN 16
    Fnc014E PROC
        mov eax, 334
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc014E ENDP

    PUBLIC Fnc014F
    ALIGN 16
    Fnc014F PROC
        mov eax, 335
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc014F ENDP

    PUBLIC Fnc0150
    ALIGN 16
    Fnc0150 PROC
        mov eax, 336
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0150 ENDP

    PUBLIC Fnc0151
    ALIGN 16
    Fnc0151 PROC
        mov eax, 337
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0151 ENDP

    PUBLIC Fnc0152
    ALIGN 16
    Fnc0152 PROC
        mov eax, 338
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0152 ENDP

    PUBLIC Fnc0153
    ALIGN 16
    Fnc0153 PROC
        mov eax, 339
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0153 ENDP

    PUBLIC Fnc0154
    ALIGN 16
    Fnc0154 PROC
        mov eax, 340
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0154 ENDP

    PUBLIC Fnc0155
    ALIGN 16
    Fnc0155 PROC
        mov eax, 341
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0155 ENDP

    PUBLIC Fnc0156
    ALIGN 16
    Fnc0156 PROC
        mov eax, 342
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0156 ENDP

    PUBLIC Fnc0157
    ALIGN 16
    Fnc0157 PROC
        mov eax, 343
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0157 ENDP

    PUBLIC Fnc0158
    ALIGN 16
    Fnc0158 PROC
        mov eax, 344
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0158 ENDP

    PUBLIC Fnc0159
    ALIGN 16
    Fnc0159 PROC
        mov eax, 345
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0159 ENDP

    PUBLIC Fnc015A
    ALIGN 16
    Fnc015A PROC
        mov eax, 346
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc015A ENDP

    PUBLIC Fnc015B
    ALIGN 16
    Fnc015B PROC
        mov eax, 347
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc015B ENDP

    PUBLIC Fnc015C
    ALIGN 16
    Fnc015C PROC
        mov eax, 348
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc015C ENDP

    PUBLIC Fnc015D
    ALIGN 16
    Fnc015D PROC
        mov eax, 349
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc015D ENDP

    PUBLIC Fnc015E
    ALIGN 16
    Fnc015E PROC
        mov eax, 350
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc015E ENDP

    PUBLIC Fnc015F
    ALIGN 16
    Fnc015F PROC
        mov eax, 351
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc015F ENDP

    PUBLIC Fnc0160
    ALIGN 16
    Fnc0160 PROC
        mov eax, 352
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0160 ENDP

    PUBLIC Fnc0161
    ALIGN 16
    Fnc0161 PROC
        mov eax, 353
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0161 ENDP

    PUBLIC Fnc0162
    ALIGN 16
    Fnc0162 PROC
        mov eax, 354
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0162 ENDP

    PUBLIC Fnc0163
    ALIGN 16
    Fnc0163 PROC
        mov eax, 355
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0163 ENDP

    PUBLIC Fnc0164
    ALIGN 16
    Fnc0164 PROC
        mov eax, 356
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0164 ENDP

    PUBLIC Fnc0165
    ALIGN 16
    Fnc0165 PROC
        mov eax, 357
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0165 ENDP

    PUBLIC Fnc0166
    ALIGN 16
    Fnc0166 PROC
        mov eax, 358
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0166 ENDP

    PUBLIC Fnc0167
    ALIGN 16
    Fnc0167 PROC
        mov eax, 359
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0167 ENDP

    PUBLIC Fnc0168
    ALIGN 16
    Fnc0168 PROC
        mov eax, 360
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0168 ENDP

    PUBLIC Fnc0169
    ALIGN 16
    Fnc0169 PROC
        mov eax, 361
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0169 ENDP

    PUBLIC Fnc016A
    ALIGN 16
    Fnc016A PROC
        mov eax, 362
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc016A ENDP

    PUBLIC Fnc016B
    ALIGN 16
    Fnc016B PROC
        mov eax, 363
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc016B ENDP

    PUBLIC Fnc016C
    ALIGN 16
    Fnc016C PROC
        mov eax, 364
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc016C ENDP

    PUBLIC Fnc016D
    ALIGN 16
    Fnc016D PROC
        mov eax, 365
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc016D ENDP

    PUBLIC Fnc016E
    ALIGN 16
    Fnc016E PROC
        mov eax, 366
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc016E ENDP

    PUBLIC Fnc016F
    ALIGN 16
    Fnc016F PROC
        mov eax, 367
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc016F ENDP

    PUBLIC Fnc0170
    ALIGN 16
    Fnc0170 PROC
        mov eax, 368
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0170 ENDP

    PUBLIC Fnc0171
    ALIGN 16
    Fnc0171 PROC
        mov eax, 369
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0171 ENDP

    PUBLIC Fnc0172
    ALIGN 16
    Fnc0172 PROC
        mov eax, 370
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0172 ENDP

    PUBLIC Fnc0173
    ALIGN 16
    Fnc0173 PROC
        mov eax, 371
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0173 ENDP

    PUBLIC Fnc0174
    ALIGN 16
    Fnc0174 PROC
        mov eax, 372
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0174 ENDP

    PUBLIC Fnc0175
    ALIGN 16
    Fnc0175 PROC
        mov eax, 373
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0175 ENDP

    PUBLIC Fnc0176
    ALIGN 16
    Fnc0176 PROC
        mov eax, 374
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0176 ENDP

    PUBLIC Fnc0177
    ALIGN 16
    Fnc0177 PROC
        mov eax, 375
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0177 ENDP

    PUBLIC Fnc0178
    ALIGN 16
    Fnc0178 PROC
        mov eax, 376
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0178 ENDP

    PUBLIC Fnc0179
    ALIGN 16
    Fnc0179 PROC
        mov eax, 377
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0179 ENDP

    PUBLIC Fnc017A
    ALIGN 16
    Fnc017A PROC
        mov eax, 378
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc017A ENDP

    PUBLIC Fnc017B
    ALIGN 16
    Fnc017B PROC
        mov eax, 379
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc017B ENDP

    PUBLIC Fnc017C
    ALIGN 16
    Fnc017C PROC
        mov eax, 380
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc017C ENDP

    PUBLIC Fnc017D
    ALIGN 16
    Fnc017D PROC
        mov eax, 381
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc017D ENDP

    PUBLIC Fnc017E
    ALIGN 16
    Fnc017E PROC
        mov eax, 382
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc017E ENDP

    PUBLIC Fnc017F
    ALIGN 16
    Fnc017F PROC
        mov eax, 383
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc017F ENDP

    PUBLIC Fnc0180
    ALIGN 16
    Fnc0180 PROC
        mov eax, 384
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0180 ENDP

    PUBLIC Fnc0181
    ALIGN 16
    Fnc0181 PROC
        mov eax, 385
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0181 ENDP

    PUBLIC Fnc0182
    ALIGN 16
    Fnc0182 PROC
        mov eax, 386
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0182 ENDP

    PUBLIC Fnc0183
    ALIGN 16
    Fnc0183 PROC
        mov eax, 387
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0183 ENDP

    PUBLIC Fnc0184
    ALIGN 16
    Fnc0184 PROC
        mov eax, 388
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0184 ENDP

    PUBLIC Fnc0185
    ALIGN 16
    Fnc0185 PROC
        mov eax, 389
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0185 ENDP

    PUBLIC Fnc0186
    ALIGN 16
    Fnc0186 PROC
        mov eax, 390
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0186 ENDP

    PUBLIC Fnc0187
    ALIGN 16
    Fnc0187 PROC
        mov eax, 391
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0187 ENDP

    PUBLIC Fnc0188
    ALIGN 16
    Fnc0188 PROC
        mov eax, 392
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0188 ENDP

    PUBLIC Fnc0189
    ALIGN 16
    Fnc0189 PROC
        mov eax, 393
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0189 ENDP

    PUBLIC Fnc018A
    ALIGN 16
    Fnc018A PROC
        mov eax, 394
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc018A ENDP

    PUBLIC Fnc018B
    ALIGN 16
    Fnc018B PROC
        mov eax, 395
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc018B ENDP

    PUBLIC Fnc018C
    ALIGN 16
    Fnc018C PROC
        mov eax, 396
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc018C ENDP

    PUBLIC Fnc018D
    ALIGN 16
    Fnc018D PROC
        mov eax, 397
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc018D ENDP

    PUBLIC Fnc018E
    ALIGN 16
    Fnc018E PROC
        mov eax, 398
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc018E ENDP

    PUBLIC Fnc018F
    ALIGN 16
    Fnc018F PROC
        mov eax, 399
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc018F ENDP

    PUBLIC Fnc0190
    ALIGN 16
    Fnc0190 PROC
        mov eax, 400
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0190 ENDP

    PUBLIC Fnc0191
    ALIGN 16
    Fnc0191 PROC
        mov eax, 401
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0191 ENDP

    PUBLIC Fnc0192
    ALIGN 16
    Fnc0192 PROC
        mov eax, 402
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0192 ENDP

    PUBLIC Fnc0193
    ALIGN 16
    Fnc0193 PROC
        mov eax, 403
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0193 ENDP

    PUBLIC Fnc0194
    ALIGN 16
    Fnc0194 PROC
        mov eax, 404
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0194 ENDP

    PUBLIC Fnc0195
    ALIGN 16
    Fnc0195 PROC
        mov eax, 405
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0195 ENDP

    PUBLIC Fnc0196
    ALIGN 16
    Fnc0196 PROC
        mov eax, 406
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc0196 ENDP

    PUBLIC Fnc0197
    ALIGN 16
    Fnc0197 PROC
        mov eax, 407
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0197 ENDP

    PUBLIC Fnc0198
    ALIGN 16
    Fnc0198 PROC
        mov eax, 408
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc0198 ENDP

    PUBLIC Fnc0199
    ALIGN 16
    Fnc0199 PROC
        mov eax, 409
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc0199 ENDP

    PUBLIC Fnc019A
    ALIGN 16
    Fnc019A PROC
        mov eax, 410
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc019A ENDP

    PUBLIC Fnc019B
    ALIGN 16
    Fnc019B PROC
        mov eax, 411
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc019B ENDP

    PUBLIC Fnc019C
    ALIGN 16
    Fnc019C PROC
        mov eax, 412
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc019C ENDP

    PUBLIC Fnc019D
    ALIGN 16
    Fnc019D PROC
        mov eax, 413
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc019D ENDP

    PUBLIC Fnc019E
    ALIGN 16
    Fnc019E PROC
        mov eax, 414
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc019E ENDP

    PUBLIC Fnc019F
    ALIGN 16
    Fnc019F PROC
        mov eax, 415
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc019F ENDP

    PUBLIC Fnc01A0
    ALIGN 16
    Fnc01A0 PROC
        mov eax, 416
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01A0 ENDP

    PUBLIC Fnc01A1
    ALIGN 16
    Fnc01A1 PROC
        mov eax, 417
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01A1 ENDP

    PUBLIC Fnc01A2
    ALIGN 16
    Fnc01A2 PROC
        mov eax, 418
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01A2 ENDP

    PUBLIC Fnc01A3
    ALIGN 16
    Fnc01A3 PROC
        mov eax, 419
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01A3 ENDP

    PUBLIC Fnc01A4
    ALIGN 16
    Fnc01A4 PROC
        mov eax, 420
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01A4 ENDP

    PUBLIC Fnc01A5
    ALIGN 16
    Fnc01A5 PROC
        mov eax, 421
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01A5 ENDP

    PUBLIC Fnc01A6
    ALIGN 16
    Fnc01A6 PROC
        mov eax, 422
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01A6 ENDP

    PUBLIC Fnc01A7
    ALIGN 16
    Fnc01A7 PROC
        mov eax, 423
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01A7 ENDP

    PUBLIC Fnc01A8
    ALIGN 16
    Fnc01A8 PROC
        mov eax, 424
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01A8 ENDP

    PUBLIC Fnc01A9
    ALIGN 16
    Fnc01A9 PROC
        mov eax, 425
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01A9 ENDP

    PUBLIC Fnc01AA
    ALIGN 16
    Fnc01AA PROC
        mov eax, 426
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01AA ENDP

    PUBLIC Fnc01AB
    ALIGN 16
    Fnc01AB PROC
        mov eax, 427
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01AB ENDP

    PUBLIC Fnc01AC
    ALIGN 16
    Fnc01AC PROC
        mov eax, 428
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01AC ENDP

    PUBLIC Fnc01AD
    ALIGN 16
    Fnc01AD PROC
        mov eax, 429
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01AD ENDP

    PUBLIC Fnc01AE
    ALIGN 16
    Fnc01AE PROC
        mov eax, 430
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01AE ENDP

    PUBLIC Fnc01AF
    ALIGN 16
    Fnc01AF PROC
        mov eax, 431
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01AF ENDP

    PUBLIC Fnc01B0
    ALIGN 16
    Fnc01B0 PROC
        mov eax, 432
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01B0 ENDP

    PUBLIC Fnc01B1
    ALIGN 16
    Fnc01B1 PROC
        mov eax, 433
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01B1 ENDP

    PUBLIC Fnc01B2
    ALIGN 16
    Fnc01B2 PROC
        mov eax, 434
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01B2 ENDP

    PUBLIC Fnc01B3
    ALIGN 16
    Fnc01B3 PROC
        mov eax, 435
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01B3 ENDP

    PUBLIC Fnc01B4
    ALIGN 16
    Fnc01B4 PROC
        mov eax, 436
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01B4 ENDP

    PUBLIC Fnc01B5
    ALIGN 16
    Fnc01B5 PROC
        mov eax, 437
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01B5 ENDP

    PUBLIC Fnc01B6
    ALIGN 16
    Fnc01B6 PROC
        mov eax, 438
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01B6 ENDP

    PUBLIC Fnc01B7
    ALIGN 16
    Fnc01B7 PROC
        mov eax, 439
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01B7 ENDP

    PUBLIC Fnc01B8
    ALIGN 16
    Fnc01B8 PROC
        mov eax, 440
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01B8 ENDP

    PUBLIC Fnc01B9
    ALIGN 16
    Fnc01B9 PROC
        mov eax, 441
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01B9 ENDP

    PUBLIC Fnc01BA
    ALIGN 16
    Fnc01BA PROC
        mov eax, 442
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01BA ENDP

    PUBLIC Fnc01BB
    ALIGN 16
    Fnc01BB PROC
        mov eax, 443
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01BB ENDP

    PUBLIC Fnc01BC
    ALIGN 16
    Fnc01BC PROC
        mov eax, 444
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01BC ENDP

    PUBLIC Fnc01BD
    ALIGN 16
    Fnc01BD PROC
        mov eax, 445
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01BD ENDP

    PUBLIC Fnc01BE
    ALIGN 16
    Fnc01BE PROC
        mov eax, 446
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01BE ENDP

    PUBLIC Fnc01BF
    ALIGN 16
    Fnc01BF PROC
        mov eax, 447
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01BF ENDP

    PUBLIC Fnc01C0
    ALIGN 16
    Fnc01C0 PROC
        mov eax, 448
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01C0 ENDP

    PUBLIC Fnc01C1
    ALIGN 16
    Fnc01C1 PROC
        mov eax, 449
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01C1 ENDP

    PUBLIC Fnc01C2
    ALIGN 16
    Fnc01C2 PROC
        mov eax, 450
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01C2 ENDP

    PUBLIC Fnc01C3
    ALIGN 16
    Fnc01C3 PROC
        mov eax, 451
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01C3 ENDP

    PUBLIC Fnc01C4
    ALIGN 16
    Fnc01C4 PROC
        mov eax, 452
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01C4 ENDP

    PUBLIC Fnc01C5
    ALIGN 16
    Fnc01C5 PROC
        mov eax, 453
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01C5 ENDP

    PUBLIC Fnc01C6
    ALIGN 16
    Fnc01C6 PROC
        mov eax, 454
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01C6 ENDP

    PUBLIC Fnc01C7
    ALIGN 16
    Fnc01C7 PROC
        mov eax, 455
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01C7 ENDP

    PUBLIC Fnc01C8
    ALIGN 16
    Fnc01C8 PROC
        mov eax, 456
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01C8 ENDP

    PUBLIC Fnc01C9
    ALIGN 16
    Fnc01C9 PROC
        mov eax, 457
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01C9 ENDP

    PUBLIC Fnc01CA
    ALIGN 16
    Fnc01CA PROC
        mov eax, 458
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01CA ENDP

    PUBLIC Fnc01CB
    ALIGN 16
    Fnc01CB PROC
        mov eax, 459
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01CB ENDP

    PUBLIC Fnc01CC
    ALIGN 16
    Fnc01CC PROC
        mov eax, 460
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01CC ENDP

    PUBLIC Fnc01CD
    ALIGN 16
    Fnc01CD PROC
        mov eax, 461
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01CD ENDP

    PUBLIC Fnc01CE
    ALIGN 16
    Fnc01CE PROC
        mov eax, 462
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01CE ENDP

    PUBLIC Fnc01CF
    ALIGN 16
    Fnc01CF PROC
        mov eax, 463
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01CF ENDP

    PUBLIC Fnc01D0
    ALIGN 16
    Fnc01D0 PROC
        mov eax, 464
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01D0 ENDP

    PUBLIC Fnc01D1
    ALIGN 16
    Fnc01D1 PROC
        mov eax, 465
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01D1 ENDP

    PUBLIC Fnc01D2
    ALIGN 16
    Fnc01D2 PROC
        mov eax, 466
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01D2 ENDP

    PUBLIC Fnc01D3
    ALIGN 16
    Fnc01D3 PROC
        mov eax, 467
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01D3 ENDP

    PUBLIC Fnc01D4
    ALIGN 16
    Fnc01D4 PROC
        mov eax, 468
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01D4 ENDP

    PUBLIC Fnc01D5
    ALIGN 16
    Fnc01D5 PROC
        mov eax, 469
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01D5 ENDP

    PUBLIC Fnc01D6
    ALIGN 16
    Fnc01D6 PROC
        mov eax, 470
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01D6 ENDP

    PUBLIC Fnc01D7
    ALIGN 16
    Fnc01D7 PROC
        mov eax, 471
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01D7 ENDP

    PUBLIC Fnc01D8
    ALIGN 16
    Fnc01D8 PROC
        mov eax, 472
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01D8 ENDP

    PUBLIC Fnc01D9
    ALIGN 16
    Fnc01D9 PROC
        mov eax, 473
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01D9 ENDP

    PUBLIC Fnc01DA
    ALIGN 16
    Fnc01DA PROC
        mov eax, 474
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01DA ENDP

    PUBLIC Fnc01DB
    ALIGN 16
    Fnc01DB PROC
        mov eax, 475
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01DB ENDP

    PUBLIC Fnc01DC
    ALIGN 16
    Fnc01DC PROC
        mov eax, 476
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01DC ENDP

    PUBLIC Fnc01DD
    ALIGN 16
    Fnc01DD PROC
        mov eax, 477
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01DD ENDP

    PUBLIC Fnc01DE
    ALIGN 16
    Fnc01DE PROC
        mov eax, 478
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01DE ENDP

    PUBLIC Fnc01DF
    ALIGN 16
    Fnc01DF PROC
        mov eax, 479
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01DF ENDP

    PUBLIC Fnc01E0
    ALIGN 16
    Fnc01E0 PROC
        mov eax, 480
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01E0 ENDP

    PUBLIC Fnc01E1
    ALIGN 16
    Fnc01E1 PROC
        mov eax, 481
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01E1 ENDP

    PUBLIC Fnc01E2
    ALIGN 16
    Fnc01E2 PROC
        mov eax, 482
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01E2 ENDP

    PUBLIC Fnc01E3
    ALIGN 16
    Fnc01E3 PROC
        mov eax, 483
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01E3 ENDP

    PUBLIC Fnc01E4
    ALIGN 16
    Fnc01E4 PROC
        mov eax, 484
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01E4 ENDP

    PUBLIC Fnc01E5
    ALIGN 16
    Fnc01E5 PROC
        mov eax, 485
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01E5 ENDP

    PUBLIC Fnc01E6
    ALIGN 16
    Fnc01E6 PROC
        mov eax, 486
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01E6 ENDP

    PUBLIC Fnc01E7
    ALIGN 16
    Fnc01E7 PROC
        mov eax, 487
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01E7 ENDP

    PUBLIC Fnc01E8
    ALIGN 16
    Fnc01E8 PROC
        mov eax, 488
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01E8 ENDP

    PUBLIC Fnc01E9
    ALIGN 16
    Fnc01E9 PROC
        mov eax, 489
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01E9 ENDP

    PUBLIC Fnc01EA
    ALIGN 16
    Fnc01EA PROC
        mov eax, 490
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01EA ENDP

    PUBLIC Fnc01EB
    ALIGN 16
    Fnc01EB PROC
        mov eax, 491
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01EB ENDP

    PUBLIC Fnc01EC
    ALIGN 16
    Fnc01EC PROC
        mov eax, 492
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01EC ENDP

    PUBLIC Fnc01ED
    ALIGN 16
    Fnc01ED PROC
        mov eax, 493
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01ED ENDP

    PUBLIC Fnc01EE
    ALIGN 16
    Fnc01EE PROC
        mov eax, 494
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01EE ENDP

    PUBLIC Fnc01EF
    ALIGN 16
    Fnc01EF PROC
        mov eax, 495
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01EF ENDP

    PUBLIC Fnc01F0
    ALIGN 16
    Fnc01F0 PROC
        mov eax, 496
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01F0 ENDP

    PUBLIC Fnc01F1
    ALIGN 16
    Fnc01F1 PROC
        mov eax, 497
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01F1 ENDP

    PUBLIC Fnc01F2
    ALIGN 16
    Fnc01F2 PROC
        mov eax, 498
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01F2 ENDP

    PUBLIC Fnc01F3
    ALIGN 16
    Fnc01F3 PROC
        mov eax, 499
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01F3 ENDP

    PUBLIC Fnc01F4
    ALIGN 16
    Fnc01F4 PROC
        mov eax, 500
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01F4 ENDP

    PUBLIC Fnc01F5
    ALIGN 16
    Fnc01F5 PROC
        mov eax, 501
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01F5 ENDP

    PUBLIC Fnc01F6
    ALIGN 16
    Fnc01F6 PROC
        mov eax, 502
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01F6 ENDP

    PUBLIC Fnc01F7
    ALIGN 16
    Fnc01F7 PROC
        mov eax, 503
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01F7 ENDP

    PUBLIC Fnc01F8
    ALIGN 16
    Fnc01F8 PROC
        mov eax, 504
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01F8 ENDP

    PUBLIC Fnc01F9
    ALIGN 16
    Fnc01F9 PROC
        mov eax, 505
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01F9 ENDP

    PUBLIC Fnc01FA
    ALIGN 16
    Fnc01FA PROC
        mov eax, 506
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01FA ENDP

    PUBLIC Fnc01FB
    ALIGN 16
    Fnc01FB PROC
        mov eax, 507
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01FB ENDP

    PUBLIC Fnc01FC
    ALIGN 16
    Fnc01FC PROC
        mov eax, 508
        jmp SyscallExec
        xchg ax, ax
        xchg ax, ax
        nop
        nop
    Fnc01FC ENDP

    PUBLIC Fnc01FD
    ALIGN 16
    Fnc01FD PROC
        mov eax, 509
        jmp SyscallExec
        xchg r8, r8
        nop
        nop
        nop
    Fnc01FD ENDP

    PUBLIC Fnc01FE
    ALIGN 16
    Fnc01FE PROC
        mov eax, 510
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01FE ENDP

    PUBLIC Fnc01FF
    ALIGN 16
    Fnc01FF PROC
        mov eax, 511
        jmp SyscallExec
        nop
        nop
        nop
        nop
        nop
        nop
    Fnc01FF ENDP

end
