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

.const
	
	CRLF			equ	13d, 10d
	
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
	
	; printf patterns
	printf_int			db 	"int = %d", CRLF, 0
	printf_str			db 	"str = %s", CRLF, 0
	printf_ptr			db 	"ptr = %p", CRLF, 0
	printf_exa			db   "exa = %x", CRLF, 0
	
	;; error messages
	smalloc_error	db	"Malloc failed", CRLF, 0
	end_msg			db	"Done.", CRLF, 0
	
 .code

;	Registres:
_deltaRegisters:
dword		0d		; 0	eax
dword		3d		; 4	ebx
dword		1d		; 8	ecx
dword		2d		; 12	edx
dword		6d		; 16	esi
dword		7d		; 20	edi
dword		5d		; 24	ebp
dword		4d		; 28	esp

;  Encodage des operations
_deltaOperations:
dword		139d		; 0	mov + register
dword		80d		; 4	push + register
dword		3d		; 8	add + register
dword		51d		; 12	xor + register (sauf esi , edi)
dword		64d		; 16	inc + register
dword		72d		; 20	dec + register
dword		132d		; 24	test
dword		117d		; 28	jnz
dword		233d		; 32	jmp

; uncrypt (start, end, key)
SetUp:
	; mov reg1, StartOfCode
	db	0
	; mov reg2, StartOfGene
	db	0
	; mov reg3, SizeOfCode
	db	0
	; mov reg4, SizeOfGene
	db	0
SaveGeneParams:
	; push reg2
	db	0
	; push reg4
	db	0
DecryptLoop:
	; mov reg5, byte ptr[reg2]
	db	0
	; xor byte ptr[reg1], reg5
	db	0
	; dec reg3
	db	0
	; dec reg4
	db	0
	; inc reg1
	db	0
	; inc reg2
	db	0
	; test reg4, reg4
	db	0
	; jnz DecryptNext
	db	0
	; pop reg4
	db	0
	; pop reg2
	db	0
	; jmp SaveGeneParams
	db	0
DecryptNext:
	; test reg3, reg3
	db	0
	; jnz DecryptLoop
	db	0
StartOfCode:
	; add esp, 8
	db	0

; Generation partie setup
generateSetUp:
	push	ebp
	mov	ebp, esp
	push	ebx

	lea		eax, [_deltaOperations] ; mov
	mov	edi, offset SetUp
	stosb
	
	invoke	crt_printf, offset printf_str, offset SetUp
	invoke	ExitProcess, 0
	
	mov	ecx, 4	
getRandomRegister:
	push	ecx				; maxrand
	call		randomize
	; Store new register value
	imul	eax, 4
	mov	edx, ecx
	imul	edx, 4
	lea		edi, 	[SetUp + edx]
	lea		eax, [_deltaRegisters + edx]
	stosb
	dec		ecx
	cmp	ecx, 3
	
	jne		getRandomRegister
	
	; mov	edi, offset SetUp
	; mov	eax, RNDMAX
	; call		rand
	; or		al, 0B8h
	; stosb
	; call		random
	; stosd
	; mov	al,0c3h
	;ret opcode
	; stosb
	; push	offset _end
	; jmp		codebuffer

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

randomize:
	push	ebp
	mov	ebp, esp
	push	ebx
	
	pusha
	push	10
	call		Sleep
	popa
	
	mov	eax, [ebp + 8]
	call		rand
	add		eax, 1
	
	leave
	ret		4
	
start:
	call	generateSetUp
	
	invoke	crt_printf, offset printf_str, SetUp
	invoke	ExitProcess, 0

end start