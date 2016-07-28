	.386
	.model flat, stdcall
	option casemap:none

	include	\masm32\include\ntstrsafe.inc
	include	\masm32\include\windows.inc
	include	\masm32\include\user32.inc
	include	\masm32\include\kernel32.inc
	include	\masm32\include\msvcrt.inc
	include	\masm32\include\shlwapi.inc

	includelib	\masm32\lib\msvcrt.lib
	includelib	\masm32\lib\user32.lib
	includelib	\masm32\lib\kernel32.lib
	includelib	\masm32\lib\masm32.lib
	includelib	\masm32\lib\shlwapi.lib
	;; -----------
	;; crypt.asm
	;; -----------

	.const
		CRLF equ 13d, 10d
	.data
		printf_int db 	"int = %d", CRLF, 0
		printf_str db 	"str = %s", CRLF, 0
		printf_ptr db 	"ptr = %p", CRLF, 0
	        printf_exa db   "exa = %x", CRLF, 0

		cle2 db 'lolipop', 0
	.code
	;; crypt(begin, end, key)
mycode:
	;; push 0
	;; call ExitProcess
	push offset printf_str
	push offset printf_str
	call crt_printf

	jmp myend
	;; invoke ExitProcess, 0
	;; db 'kikou loul asv', 0
cle:
	db 'lolipop', 0

crypt:
	push ebp
	mov ebp, esp
	sub esp, 64		; arbitraty size
	push ebx

	push [ebp + 16]
	call crt_strlen

	mov [ebp - 4], eax		; key len

	mov eax, [ebp + 12]
	sub eax, [ebp + 8]
	mov [ebp - 12], eax

	push eax
	call crt_malloc

	cmp eax, 0
	je malloc_error		; eax = &malloced_buffer

	mov [ebp - 8], eax ; allocated area

	;; on recopie la chaine dans le malloc
	push [ebp - 12]
	push [ebp + 8]
	push eax
	call crt_memcpy

	mov esi, [ebp + 8] 	;eax
	mov edi, [ebp + 8]	;eax
	mov ecx, [ebp - 12]
	mov ebx, [ebp + 16]
	xor edx, edx

crypting:
	lodsb
	cmp [ebx],  edx
	jne further2
	sub ebx, [ebp - 4]
further2:
	xor eax, [ebx]
	stosb
	inc ebx
	loop crypting

	mov eax, [ebp + 8]
	pop ebx
	leave
	ret 12			; on retourne l'adresse de la chaine malloc

malloc_error:
	push 1
	call ExitProcess

start:				; on crypte
	;; invoke crt_printf, offset printf_str, mycode
	push cle
	push cle
	push mycode
	call crypt

	push cle		; on decrypte
	mov ebx, mycode
	mov edx, cle
	sub edx, ebx
	mov ecx, eax
	add ecx, edx
	push ecx
	push eax
	call crypt
	;; invoke crt_printf, offset printf_str, eax
	jmp eax

myend:
	;; invoke crt_printf, offset printf_str, eax
	push 0
	call ExitProcess
	;; invoke ExitProcess, 0
	endstart
