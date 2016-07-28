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
; ne plus stocker sGetProcAddr et sLoadLibraryExA en data
; retourner un tableau des fonctions sur le tas
; get le tableau de fonctions avec appel d'un fichier different
; synthaxe nasm

.data
patternptr	db	"address of ptr => %s   %p", 13, 10, 0
patternint db	"%i " , 13, 10, 0
patternstack	db	"address of ptr =>  %p", 13, 10, 0

.code

@@var1:
db	"lol",0
@@var2:
db	"mystring2",0
@@var3:
dd	?

start:
; lea		eax, @@var1
; push	eax
; push	eax
; push	offset patternptr
; call		crt_printf

; lea		eax, @@var2
; push	eax
; push	eax
; push	offset patternptr
; call		crt_printf

; lea		eax, @@var1
; add		eax, 4
; push	eax
; push	eax
; push	offset patternptr
; call		crt_printf

;pop		42
push	42
pop		eax
push	eax


push	eax
push 	offset patternstack
call		crt_printf
add		esp, 4

; push	42
; call		crt_iswdigit
; add		esp, 4


; push	1
; call		Sleep


;push	42
;pop		eax
;push	eax
;pop		eax

;push	eax
push 	offset patternstack
call		crt_printf
;add		esp, 4




push	0
call ExitProcess
end start