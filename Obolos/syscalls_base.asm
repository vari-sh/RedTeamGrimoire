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