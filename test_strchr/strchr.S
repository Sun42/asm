/*
** char *strchr(char *str, int n)
*/

#include		"asm.h"


GLOBAL_FUNC(mystrchr)
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	movl	8(%ebp), %ecx	/* ecx = str*/
	movl	12(%ebp), %edx	/* edx = n */

boucle :
	cmpb	(%ecx), %dl	/*if *str == n */
	je	ok		/* goto ok*/
	cmpb	$0, (%ecx)	/* if *str == 0 */
	je	error
	incl	%ecx		/* str++*/
	jmp	boucle

ok :
	movl	%ecx, %eax
	jmp	fin

error:
	xorl	%eax, %eax

fin :
	leave
	ret
FUNC_END(mystrchr)
