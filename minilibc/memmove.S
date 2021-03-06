/*
void *mymemmove(void *dest, const void *src, size_t n);
**	test firefox, gimp : ok
*/

#include		"asm.h"

	/* %esi %edi*/
/* %eax, %ecx, %edx ready for use*/

GLOBAL_FUNC(memmove)

	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	pushl	%ebx		/* ebx not rdy for use*/

	movl	8(%ebp), %ebx	/* ebx = dest */
	movl	12(%ebp), %ecx	/* ecx = src*/
	movl	16(%ebp), %edx	/* esi = n*/

	cmpl	%ebx, %ecx	/*if src == dest return src*/
	je	fin		/* if src < dest goto tryoverlap*/
	jl	tryoverlap
	jmp	bouclememcpy


tryoverlap:
	addl	%edx, %ecx	/* src +=n */
	cmpl	%ecx, %ebx	/*if src + n > dest*/
	jle	prememmove	/* on copie a l'envers*/
	subl	%edx, %ecx
	jmp	bouclememcpy

/* cas overlap */
prememmove:
	addl	%edx, %ebx	/* dest += n*/
	decl	%ebx
	decl	%ecx

bouclememmove:
	cmpl	$0, %edx	/* if n == 0*/
	jle	fin		/* goto fin */
	xorl	%eax, %eax
	movb	(%ecx), %al	/* eax = *src */
	movb	%al, (%ebx)	/* *dest = *src*/
	decl	%edx		/* n-- */
	decl	%ebx		/* dest--*/
	decl	%ecx		/* src--*/
	jmp	bouclememmove


bouclememcpy:
	cmpl	$0, %edx	/* if n == 0*/
	je	fin		/* goto fin */
	xorl	%eax, %eax
	movb	(%ecx), %al	/* eax = *src */
	movb	%al, (%ebx)	/* *dest = *src*/
	decl	%edx		/* n-- */
	incl	%ebx		/* dest++*/
	incl	%ecx		/* src++*/
	jmp	bouclememcpy

fin:
	movl	8(%ebp), %eax
	popl	%ebx		/* restore ebx*/
	leave
	ret

FUNC_END(memmove)
