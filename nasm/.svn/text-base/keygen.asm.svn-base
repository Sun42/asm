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
	;; keygen.asm
	;; -----------

	.const
	
	CRLF			equ	13d, 10d
	MAXRAND	equ	127
	.data
	;; Struct _SYSTEMTIME
	_SYSTEMTIME		STRUC
		Year					dw	?
		Month				dw	?
		DayOfWeek		dw	?
		Day					dw	?
		Hour					dw	?
		Minute				dw	?
		Second				dw	?
		Milliseconds		dw	?
	_SYSTEMTIME		ENDS
	
	STime	_SYSTEMTIME	<>

	;; printf patterns
	printf_int			db 	"int = %d", CRLF, 0
	printf_str			db 	"str = %s", CRLF, 0
	printf_ptr			db 	"ptr = %p", CRLF, 0
	printf_exa			db   "exa = %x", CRLF, 0
	
	;; error messages
	smalloc_error	db	"Malloc failed", CRLF, 0
	end_msg			db	"Done.", CRLF, 0
	
	.code

malloc_error:

	invoke	crt_printf,  offset printf_str, offset smalloc_error
	invoke	ExitProcess, 0
	
rand			proc

	push	ecx
	push	edx
	mov	ecx, eax
	
	call		random
	xor		edx, edx
	div		ecx
	mov	eax, edx
	pop		edx
	pop		ecx

	ret

rand 		endp

random		proc

	pusha
	push	offset STime
	call		GetSystemTime
	popa
	
	xor		eax, eax
	mov	ax, [STime.Milliseconds]
	shl		eax, 16
	mov	ax, [STime.Second]
	
	ret
	
random		endp

keygen:
	push	ebp
	mov	ebp, esp
	push	ebx
	
	push	[ebp + 8]
	call		crt_malloc
	or		eax,	eax
	jz			malloc_error
	mov	edi, eax ; &buffer
	
	xor		ecx, ecx
	keygen_loop:
	mov	eax, offset MAXRAND
	call		rand
	add		eax, 1
	
	mov	[edi + ecx], eax
	inc		ecx
	
	pusha
	push	100
	call		Sleep
	popa
	
	cmp	ecx, [ebp + 8] ; [ebp + 8] = longeur de la clef de cryptage
	jne		keygen_loop
	
	mov	edx, 0
	inc		ecx
	mov	[edi + ecx], edx ; null termited
	
	mov	eax, edi
	leave
	ret
	
start:
	push	42
	call		keygen
	
	invoke	crt_printf,  offset printf_str, eax
	invoke	ExitProcess, 0
	
	end start
