/*
**	void *memcpy (void *dest, const void *src, size_t n) ;
**	test : ls , firefox, gimp ok
*/

#include		"asm.h"

/* %eax, %ecx, %edx ready for use*/

GLOBAL_FUNC(memcpy)

	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	pushl	%ebx		/* ebx not rdy for use*/

	movl	8(%ebp), %ebx	/* ebx = dest */
	movl	12(%ebp), %ecx	/* ecx = src*/
	movl	16(%ebp), %edx	/* esi = n*/

boucle:
	cmpl	$0, %edx	/* if n == 0*/
	je	fin		/* goto fin */
	xorl	%eax, %eax
	movb	(%ecx), %al	/* eax = *src */
	movb	%al, (%ebx)	/* *dest = *src*/
	decl	%edx		/* n-- */
	incl	%ebx		/* dest++*/
	incl	%ecx		/* src++*/
	jmp	boucle

fin:
	movl	8(%ebp), %eax

	popl	%ebx		/* restaure ebx*/
	leave
	ret

FUNC_END(memcpy)
