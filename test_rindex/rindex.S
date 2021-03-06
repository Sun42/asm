/*
** a tester en minilibc, surtout vis a vis du push et pop avant/apres le strlen
** char *myrindex(const char *s, int c);
*/

#include		"asm.h"


GLOBAL_FUNC(myrindex)
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	pushl	%ebx

	movl	8(%ebp), %ebx	/* ebx = str*/
	movl	12(%ebp), %edx	/* edx = n */
	movl	%ebx, %ecx

	pushl	%edx
	pushl	%ecx
	call	strlen
	popl	%ecx
	popl	%edx
	addl	%eax, %ebx
	decl	%ebx
boucle:
	cmpb	(%ebx), %dl	/*if *str == n */
	je	ok		/* goto ok*/
	cmpl	%ecx, %ebx	/* if *str == premier indice */
	je	error
	decl	%ebx		/* str++*/
	jmp	boucle

ok:
	movl	%ebx, %eax
	jmp	fin

error:
	xorl	%eax, %eax

fin :
	popl	%ebx
	leave
	ret
FUNC_END(myrindex)
