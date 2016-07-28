%include "syscall.inc"

global print_stack
extern kernel

section .text

print_num:
        push    ecx
        mov     ecx, 8
.digit:
        xor     eax, eax
        mov     eax, edx
        shr     eax, 28
        cmp     al, 0ah
        jl      .noalpha
        add     eax, 3ch ; 'F' - 10
        jmp     .print
.noalpha:
        add     eax, 30h ; '0'
.print:
        push    eax
        mov     eax, esp
        push    1
        push    eax
        push    1
        mov     eax, SYS_WRITE
        call    kernel
        add     esp, 16
        shl     edx, 4
        loop    .digit
        pop     ecx
        push    0ah
        mov     eax, esp
        push    1
        push    eax
        push    1
        mov     eax, SYS_WRITE
        call    kernel
        add     esp, 16
        ret


print_stack:    ; args: eax is how deep we want to print the stack
        pushad
        mov ecx, eax
        mov ebx, 24h
.dump:
        mov edx, [esp + ebx]
        call print_num
        add ebx, 4
        loop .dump
        popad
        ret
