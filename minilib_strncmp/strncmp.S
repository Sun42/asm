/*
* int strncmp(const char *s1, const char *s2, size_t n);
*/

#include		"asm.h"

/*%esi %edi*/

GLOBAL_FUNC(strncmp)
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	pushl	%ebx
	pushl	%edi
	pushl	%esi

	xorl	%esi, %esi
	movl	8(%ebp), %ebx	/* ebx = s1 */
	movl	12(%ebp), %ecx	/* ecx = s2*/
	movl	16(%ebp), %edi	/* edi = n*/
	cmpl	$0, %edi	/* if n == 0 return 0*/
	jle	fineq

boucle:
	incl	%esi
	movb	(%ebx), %dl	/* dl = *s1 */
	cmpb	%dl, (%ecx)
	je	suiv		/* if *s2 == *s1 goto next */
	jmp	findif		/* else */

suiv:
	cmpl	%esi, %edi
	je	fineq		/* if cpt == n goto return 0 */
	cmpb	$0, (%ecx)
	je	fineq		/* if (*s2 == '\0') || (*s1 == '\0') => return 0*/
	incl	%ebx		/* s1++*/
	incl	%ecx		/* s2++ */
	jmp	boucle


fineq:
	xorl	%eax, %eax
	jmp	fin

findif:

	subb	(%ecx), %dl
	movsbl	%dl, %eax

fin:

	popl	%esi
	popl	%edi
	popl	%ebx
	leave
	ret

FUNC_END(strncmp)
