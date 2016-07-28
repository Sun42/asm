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
