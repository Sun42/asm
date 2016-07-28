/*
size_t strcspn(const char *s, const char *reject);
*/

#include		"asm.h"


GLOBAL_FUNC(mystrcspn)
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	pushl	%ebx
	pushl	%esi
	movl	8(%ebp), %ecx	/* ecx = str*/
	movl	12(%ebp), %edx	/* edx = reject */
	xorl	%ebx, %ebx	/* cpt = 0*/
	movl	%edx, %esi	/*save du ptr reject*/
	jmp	boucle

incrreject:
	incl	%edx


bouclereject:
	movb	(%edx), %al
	cmpb	$0, %al
	je	incrboucle	/* if reject == '\0'*/
	cmpb	%al, (%ecx)
	jne	incrreject	/* if str != reject*/
	je	fin		/*else return cpt*/

incrboucle:
	incl	%ecx
	incl	%ebx

boucle:
	movl	%esi, %edx		/*restore reject*/
	movb	(%ecx), %al
	cmp	$0, %al		/* if *str1 == '\0' return*/
	je	fin
	cmp	(%edx), %al
	je	fin
	jmp	bouclereject


fin:

	movl	%ebx, %eax
	popl	%esi
	popl	%ebx
	leave
	ret
FUNC_END(mystrcspn)
