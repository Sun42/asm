extern	ExitProcess
import	ExitProcess	kernel32.dll

extern	printf
import	printf		msvcrt.dll

[section .data align=4 use32]

patternkernel32		db	"address of Kernel32.dll  => %p", 13, 10, 0
pattern2		db	"address of GetProcAddr => %p", 13, 10, 0
pattern3		db	"address of LoadLibraryExA => %p", 13, 10, 0
pattern4		db	"address of ExPortTable => %p", 13, 10, 0
patternptr		db	"address of ptr => %p", 13, 10, 0
patternregister		db	"value of register => %p", 13, 10, 0

[section .text    code  align=16 use32]

;get the Kernel32 address stored in PEB
;IN	NOTHING
;OUT	eax:::KERNEL32ADDRESS : INT
;void* __stdcall__GetKernel32Address()
GetKernel32Address:
push	ebp						; prologue
mov	ebp, esp					; prologue	

push	esi
xor	eax, eax
xor	esi, esi

mov	eax,[fs:30h]					; PEB      TIB[30h] => Linear address of Process Environment Block (PEB)
mov	eax, [eax+0Ch]					; LOADER    aka _PEB_LDR_DATA
mov	esi, [eax+1Ch]					; InitializationOrderModuleList
lodsd
mov	eax, [eax+8]					; InInitializationOrderModuleList(3) <=> kernel32

pop	esi

mov	esp, ebp					;epilogue
pop	ebp						;epilogue
ret							;GetKernel32Address endp

;get the export table in a dll wich contains  adresses of provided functions
;IN	dllAddress : dword
;OUT	eax::ExportTableAddress : dword
;void* __stdcall__GetExportTableAddress(void *dllAddr)
GetExportTableAddress:
push	ebp						; prologue
mov	ebp, esp					; prologue

push	ebx
xor	ebx, ebx
xor	eax, eax

mov	eax, [ebp+8d]					; dllAddr<=>ImageBase
mov	ebx, [eax+3Ch]					; += RVA of  PE header
add	ebx, eax 					; == PE HEADER

mov	ebx, [ebx+78h]					; += IMAGE_EXPORT_DIRECTORY in PE HEADER

add	ebx, eax					; == ExportTable
mov	eax, ebx

pop	ebx

mov	esp, ebp					;epilogue
pop	ebp						;epilogue
ret	4						;GetExportTableAddress endp

;	get the address of a function stored in a dll
;IN	kernel32Addr : dword, exportTableAddress : dword, sAddrFuncName: dword
;OUT	eax::FuncAddr : dword
;void* __stdcall__GetFuncAddr(void* dllImageBase, void* exportTable, char* sAddrFuncName)
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

mov	edx, [ebp+8]					;edx = dllImageBase
mov	ebx, [ebp+12]					;ebx = exportTable



mov	esi, [ebx+20h]					;table of "pointeurs de noms" (AddressOfNames) en rva 
add	esi, edx					;+ ImageBase

FindFunc:						;seeking Function indice in AddressOfNAmes, store result in ecx
lodsd
add	eax, edx					;+ ImageBase because each NamesPointers addr are RVA
mov	edi, eax
push	esi
mov	esi, [ebp+16]					;sAddrFuncName

StringCmp:
cmpsb							;cmp byte ds:esi, byte ds:edi
jne	NextFunction
;cmp	byte ptr [edi], 0
cmp	byte [edi], byte 0
je	FuncFound
jmp	StringCmp

NextFunction:
pop	esi
inc	ecx
jmp	FindFunc
;							;ordinalTable(ecx) == &Func
FuncFound:						;indice of Func is now in ecx
xor	eax, eax
mov	esi, [ebx+24h]					;&ordinalTable
shl	ecx, 1
add	esi, ecx
add	esi, edx
;mov	ax, word ptr [esi]
mov	ax, word [esi]
shl	eax, 2
add	eax, [ebx+1Ch]
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

@@sGetProcAddress:
db	"GetProcAddress", 0
@@sLoadLibraryExA:
db	"LoadLibraryExA", 0
@@sCreateFileA:
db	"sCreateFileA", 0
@@sCreateFileMappingA:
db	"CreateFileMappingA", 0
@@sExitProcess:
db	"sExitProcess", 0
@@sFindFirstFileExA:
db	"sFindFirstFileExA", 0
@@sGetCurrentDirectoryA:
db	"GetCurrentDirectoryA", 0
@@slstrcat:
db	"lstrcat", 0
@@sMapViewOfFile:
db	"MapViewOfFile", 0
@@sSetFilePointer:
db	"SetFilePointer", 0
@@sUnmapViewOfFile:
db	"UnmapViewOfFile", 0
@@sWriteFile:
db	"WriteFile", 0
@@sUser32:
db	"User32", 0
@@sMessageBoxA:
db	"MessageBoxA", 0
@@smsvcrt:
db	"msvcrt", 0
@@smemcmp:
db	"memcmp", 0
@@smemcpy:
db	"memcpy", 0
@@sprintf:
db	"printf", 0
@@sstrcpy:
db	"strcpy", 0
@@sstrncmp:
db	"strncmp", 0
@@sShlwapi:
db	"Shlwapi", 0
@@sStrDupA:
db	"StrDupA", 0


	;---------------------------------------------------------------------------------
	; EBP					4
	;---------------------------------------------------------------------------------
	; HANDLE				4	Kernel32.dll
	; HANDLE				8	Kernel32 exportTable
	; HANDLE 				12	LoadLibraryA
	; HANDLE				16      GetProcAddr
	;---------------------------------------------------------------------------------
        ; DLLS
	;---------------------------------------------------------------------------------
	; HANDLE				20	User32
	; HANDLE				24	msvcrt.dll
	; HANDLE				28	Shlwapi.dll
	;---------------------------------------------------------------------------------
	; Kernel32 Functions
	;---------------------------------------------------------------------------------
	; HANDLE				32	CreateFileA
	; HANDLE				36	CreateFileMappingA
	; HANDLE				40	ExitProcess
	; HANDLE				44	FindFirstFileExA
	; HANDLE				48	GetCurrentDirectoryA
	; HANDLE				52	lstrcat
	; HANDLE				56	MapViewOfFile
	; HANDLE				60	SetFilePointer
	; HANDLE				64	UnmapViewOfFile
	; HANDLE				68	WriteFile
	;---------------------------------------------------------------------------------
	; User32 Functions
	;---------------------------------------------------------------------------------
	; HANDLE				72	MessageBoxA
	;---------------------------------------------------------------------------------
	; msvcrt Functions
	;---------------------------------------------------------------------------------
	; HANDLE				72	memcmp
	; HANDLE				76	memcpy
	; HANDLE				80	printf
	; HANDLE				84	strcpy
	; HANDLE				88	strncmp
	;---------------------------------------------------------------------------------
	; Shlwapi.dll Functions
	;---------------------------------------------------------------------------------
	; HANDLE				92	StrDupA
	;--------------------------------------------------------------------------------
..start:
sub	esp, 128

;GetKernel32Adress()
call	GetKernel32Address
mov	[ebp - 4], eax					; saving &kernel32

mov	eax, [ebp - 4]
push	eax
push	dword patternkernel32
call	[printf]

;GetExportTableAdress(&kernel32)
mov	eax, [ebp-4]
push	eax
call	GetExportTableAddress
mov	[ebp - 8], eax					; saving &exportTable

push	eax
push	pattern4
call	[printf]

;GetFuncAddr(&kernel32, &exportTable, "GetProcAddress")
push	@@sGetProcAddress
mov	eax,[ebp - 8]
push	eax

mov	eax,[ebp - 4]
push	eax
call	GetFuncAddr

mov    [ebp - 16], eax					;saving GetProcAddr

push	eax
push	pattern2
call	[printf]

;GetFundAddr(&kernel32, &exportTable, "LoadLibraryExA")
push	@@sLoadLibraryExA
mov	eax, [ebp - 8]
push	eax
mov	eax, [ebp - 4]
push	eax
call	GetFuncAddr
mov	[ebp - 12], eax

push	eax
push	pattern3
call	[printf]

;LoadLibraryExA("User32", 0, 0);
push	0
push	0
push	@@sUser32
mov	eax, [ebp-12]
call	eax
mov	[ebp - 20], eax


;LoadLibraryExA("msvcrt", 0, 0);
push	0
push	0
push	@@smsvcrt
mov	eax, [ebp-12]
call	eax
mov	[ebp - 24], eax

;LoadLibraryExA("Shlwapi", 0, 0);
push	0
push	0
push	@@sShlwapi
mov	eax, [ebp-12]
call	eax
mov	[ebp - 28], eax


;GetProcAddress(&User32, "MessageBoxA")
push	@@sMessageBoxA
mov	eax, [ebp-20]
push	eax
mov	eax, [ebp-16]
call	eax
mov	[ebp-72], eax


add	esp, 128
push	dword 0
call [ExitProcess]



