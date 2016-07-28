/*
**	void *memset(void *s, int c, size_t n) ;
**	test : gimp, firefox ok
*/

#include		"asm.h"

/* %esi %edi*/
/* %eax, %ecx, %edx ready for use*/

GLOBAL_FUNC(memset)

	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	pushl	%ebx		/* ebx not rdy for use*/
	movl	8(%ebp), %ebx	/* ebx = s */
	movl	12(%ebp), %ecx	/* ecx = c */
	movl	16(%ebp), %edx	/* esi = n*/

boucle:
	cmpl	$0, %edx	/* if n == 0*/
	je	fin		/* goto fin */
	movb	%cl, (%ebx)	/* *s = n */
	decl	%edx		/* n-- */
	incl	%ebx		/* dest++*/
	jmp	boucle

fin:
	movl	8(%ebp), %eax

	popl	%ebx		/* restaure ebx*/
	leave
	ret

FUNC_END(memset)
