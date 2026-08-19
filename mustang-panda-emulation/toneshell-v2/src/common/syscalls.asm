PUBLIC SysNtCreateUserProcess
PUBLIC SysNtAllocateVirtualMemory
PUBLIC SysNtWriteVirtualMemory
PUBLIC SysNtProtectVirtualMemory
PUBLIC SysNtQueueApcThread
PUBLIC SysNtResumeThread
PUBLIC SysNtCreateSection
PUBLIC SysNtMapViewOfSection
PUBLIC SysNtUnmapViewOfSection

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

SysNtCreateSection PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtCreateSection ENDP

SysNtMapViewOfSection PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtMapViewOfSection ENDP

SysNtUnmapViewOfSection PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtUnmapViewOfSection ENDP

END
