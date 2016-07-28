.386
.model		flat, stdcall
option		casemap:none

include		c:\masm32\include\windows.inc

include		c:\masm32\include\kernel32.inc
include		c:\masm32\include\user32.inc
include		c:\masm32\include\msvcrt.inc

includelib	c:\masm32\lib\kernel32.lib
includelib	c:\masm32\lib\user32.lib
includelib	c:\masm32\lib\msvcrt.lib

;TODO
; retourner un tableau des fonctions sur le tas
; get le tableau de fonctions avec appel d'un fichier different
; synthaxe nasm

.data
pattern		db	"address of Kernel32.dll  => %p", 13, 10, 0
pattern2	db	"address of GetProcAddr => %p", 13, 10, 0
pattern3	db	"address of LoaLibraryExA => %p", 13, 10, 0
pattern4	db	"address of ExPortTable => %p", 13, 10, 0
patternptr	db	"address of ptr => %p", 13, 10, 0
patternMsgBox	db	"address of msgbox => %p", 13, 10, 0
patternebx	db	"value of ebx => %p", 13, 10, 0
.code

;get the Kernel32 address stored in PEB
;IN	NOTHING
;OUT	eax:::KERNEL32ADDRESS : INT
;void* __stdcall__GetKernel32Address()
GetKernel32Address:
push	ebp
mov	ebp, esp

push	esi
xor	eax, eax
xor	esi, esi

assume	fs:nothing					; bypass masm protection
mov	eax, fs:[30h]					; PEB      TIB[30h] => Linear address of Process Environment Block (PEB)
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
push	ebp
mov	ebp, esp

push	ebx
xor	ebx, ebx

mov	eax, [ebp+8]					;dllAddr<=>ImageBase
mov	ebx, [eax+3Ch]					; += RVA of  PE header
add	ebx, eax 					; == PE HEADER

mov	ebx, [ebx+78h]					; += IMAGE_EXPORT_DIRECTORY in PE HEADER
add	ebx, eax					; == ExportTable
mov	eax, ebx

invoke	crt_printf, offset patternebx, eax
invoke ExitProcess, 0

pop	ebx

mov	esp, ebp					;epilogue
pop	ebp
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
mov	esi, [ebx+24h]					;&ordinalTable
shl	ecx, 1
add	esi, ecx
add	esi, edx
mov	ax, word ptr [esi]
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
db "GetProcAddress", 0
@@sLoadLibraryExA:
db "LoadLibraryExA", 0
@@sUser32dll:
db "User32", 0
@@sMessageBoxA:
db "MessageBoxA", 0

start:
sub	esp, 128
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
	;---------------------------------------------------------------------------------

	
call	GetKernel32Address
mov	[ebp - 4], eax					; saving &kernel32

push	[ebp - 4]
push	offset pattern
call	crt_printf

push	[ebp - 4]
call	GetExportTableAddress
mov	[ebp - 8], eax					; saving &exportTable
invoke	crt_printf, offset pattern4, eax

;GetFuncAddr(&kernel32, &exportTable, "GetProcAddress")
lea	eax, @@sGetProcAddress
push	eax
push	[ebp - 8]
push	[ebp - 4]
call	GetFuncAddr

mov    [ebp - 16], eax					;saving GetProcAddr
invoke	crt_printf, offset pattern2, eax

;GetFundAddr(&kernel32, &exportTable, "LoadLibraryExA")
lea	eax, @@sLoadLibraryExA
push	eax
push	[ebp - 8]
push	[ebp - 4]
call	GetFuncAddr
mov	[ebp - 12], eax

invoke	crt_printf, offset pattern3, eax

;LoadLibraryExA("User32", 0, 0);
push	0
push	0
lea	eax, @@sUser32dll
push	eax
mov	eax, [ebp -12]
call	eax
mov	[ebp - 20], eax					;saving user32.dll

;GetProcAddress(&User32, "MessageBoxA")
lea	ecx, @@sMessageBoxA
push	ecx
push	[ebp - 20]
mov	eax, [ebp - 16]
call	eax
mov	[ebp - 72], eax					;saving MessageBoxA

invoke	crt_printf, offset patternMsgBox, eax
add	esp, 128
invoke	ExitProcess, 0
end	start