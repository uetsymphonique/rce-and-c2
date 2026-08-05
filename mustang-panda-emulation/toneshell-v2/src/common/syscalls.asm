PUBLIC SysNtCreateUserProcess
PUBLIC SysNtAllocateVirtualMemory
PUBLIC SysNtWriteVirtualMemory
PUBLIC SysNtProtectVirtualMemory
PUBLIC SysNtQueueApcThread
PUBLIC SysNtResumeThread

.code

SysNtCreateUserProcess PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtCreateUserProcess ENDP

SysNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtAllocateVirtualMemory ENDP

SysNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtWriteVirtualMemory ENDP

SysNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtProtectVirtualMemory ENDP

SysNtQueueApcThread PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtQueueApcThread ENDP

SysNtResumeThread PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtResumeThread ENDP

END
