global _start
extern syscall

%assign MSG_LEN		12
%assign SYS_WRITE	4
%assign SYS_EXIT	1

section .rodata
	msg	db	"Hello world", 0ah

section .text

_start:
	push    dword MSG_LEN
	push	dword msg
	push	dword 1
	mov	dword eax, SYS_WRITE
	call    kernel
	push    dword 42
	mov	dword eax, SYS_EXIT
	call    kernel
