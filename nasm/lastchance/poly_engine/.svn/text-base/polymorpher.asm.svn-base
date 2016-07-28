;polymorpher.asm
; generates call 0
	
.586
.model	flat, stdcall
option	casemap :none 

	include \masm32\include\windows.inc
	include \masm32\include\user32.inc
	include \masm32\include\kernel32.inc
	include \masm32\include\msvcrt.inc


	includelib \masm32\lib\user32.lib
	includelib \masm32\lib\kernel32.lib
	includelib \masm32\lib\msvcrt.lib
	

.data   

	_SYSTEMTIME 	STRUC
	Year		dw	?
	Month		dw	?
	DayOfWeek	dw	?
	Day		dw	?
	Hour		dw	?
	Minute		dw	?
	Second		dw	?
	Milliseconds	dw	?
	_SYSTEMTIME 	ENDS

	STime	_SYSTEMTIME	<>

	RNDMAX	equ	5

	_EAX	equ	0
	_ECX	equ	1
	_EDX	equ	2
	_EBX	equ	3
	_ESI    equ     4
	
	
patterndeci	db "val => %i  ", 13,10,0
patternchar	db "%c  ",0


.code

start:
	jmp	realstart

codebuffer:
	byte	0		; call E8 --
	dword	0		; un_delta 00000000 ??--
	byte	0		; pop ebx 5B --
	word	0		; mov	eax, ebx 8BC3 --
	word	0		;sub	eax   83E8 --
	byte	0		;02 --
	word	0		;0040100B   . 8BC8           MOV ECX,EAX --
	word	0		;83E9	sub ecx			--			
	byte	0		;4 --
	byte	0		;BA MOV EDX --
	dword	0		;1F000000  [un_end - un_delta] ??--
	word	0		;00401015   . 03D3           ADD EDX,EBX
	word	0		;00401017   . 03CA           ADD ECX,EDX
	word	0		;00401019   > 8B32           MOV ESI,DWORD PTR DS:[EDX]
	word	0		;0040101B   . 3330           XOR ESI,DWORD PTR DS:[EAX]
	word	0		;0040101D   . 8932           MOV DWORD PTR DS:[EDX],ESI
	byte	0		;0040101F   . 42             INC EDX
	word	0		;00401020   . 3BD1           CMP EDX,ECX
	word	0		;00401022   .75 F5          JNZ SHORT decrypt.00401019
realstart:
	;invoke	crt_printf
	;push	1
	push	realstart - codebuffer
	call	crt_malloc
	;add	esp,8
	;mov	edi, offset codebuffer
	mov	edi , eax

	;!!!!!call	un_delta => E8 0000 0000
	xor	eax, eax
	or	al, 0E8h
	stosb

	xor	eax, eax
	stosd

	;pop	ebx
	xor	eax, eax
	or	al,05Bh 	
	stosb
	
	; mov	eax, ebx 8BC3   ax:[al/8B || ah/C3]
	xor	eax, eax
	or	al, 8Bh			;mov
	or	ah, 0C3h		;eax, ebx
	stosw
	
	; sub eax  83E8
	xor	eax, eax
	or	al, 83h
	or	ah, 0E8h
	stosw

	;2
	xor	eax, eax
	or	al, 02d
	stosb

	
	;mov ecx, eax 8BC8
	xor	eax, eax
	or	al, 8Bh
	or	ah, 0C8h
	stosw
	
	
	;83E9	sub ecx
	xor	eax, eax
	or	al, 83h
	or	ah, 0E9h
	stosw
	
	;4
	xor	eax, eax
	or	al, 04d
	stosb
	
	;BA MOV EDX
	xor	eax, eax
	or	al, 0BAh	
	stosb
	;!!!!!!! un_end - un_delta a changer
	xor	eax, eax
	or	al, 1Fh
	stosd
	
	;. 03D3           ADD EDX,EBX
	xor eax, eax
	or al, 03h
	or ax, 0D3h
	stosw
	
	; 03CA           ADD ECX,EDX
	xor	eax, eax
	or	al,03h
	or 	ah,0CAh
	stosw
	
	; 8B32           MOV ESI,DWORD PTR DS:[EDX]
	xor	eax, eax
	or	al,8Bh
	or	ah,32h
	stosw
	
	;0040101B   . 3330           XOR ESI,DWORD PTR DS:[EAX]
	xor	eax, eax
	or	al, 33h
	or	ah, 30h
	stosw
	
	;0040101D   . 8932           MOV DWORD PTR DS:[EDX],ESI
	xor	eax, eax
	or	al,89h
	or	ah,32h
	stosw
		
	;0040101F   . 42             INC EDX
	xor	eax, eax
	or	al,42h
	stosb
	;00401020   . 3BD1           CMP EDX,ECX
	xor	eax, eax
	or	al, 3Bh
	or	ah, 0D1h
	stosw
	;00401022   .75 F5          JNZ SHORT decrypt.00401019
	xor	eax, eax
	or	al,75h
	or	ah, 0F5h
	stosw
	;Parameters dest New buffer src Buffer to copy from count
	push	realstart - codebuffer
	sub	edi, realstart - codebuffer
	push	edi
	
	push	offset codebuffer
	call	crt_memcpy
	;add	esp, 12
_end:	
	push	42
	call	ExitProcess

;Modulo(int number, int max),
modulo:
push	ebp
mov	ebp, esp
push	edx

xor	ebx, ebx
xor	ecx, ecx
xor	edx, edx

mov	eax, [ebp + 8]
mov	ecx, [ebp + 12]
div	ecx
mov	eax, edx

pop	edx
leave
ret	8

;get_random(int max)
get_random:
	push	ebp
	mov	ebp, esp
	push	ecx
	push	edx
	
	mov	ecx, [ebp + 8]
	call	random
	xor	edx,edx
	div	ecx
	mov	eax,edx
	
	pop	edx
	pop	ecx
	leave
	ret	4
;

random	proc

	pusha
	push 	offset STime
	call 	GetSystemTime
	popa
	xor	eax,eax
	mov 	ax,[STime.Milliseconds]
	shl	eax,16
	mov 	ax,[STime.Second]	
	ret

random	endp

invoke ExitProcess, 42
end	start
