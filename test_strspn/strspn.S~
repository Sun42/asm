/*
char *strstr(const char *meule_de_foin, const char *aiguille) ;
**	trouver un prog qui uitilise this damn func
*/

#include		"asm.h"


GLOBAL_FUNC(strspn)
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	pushl	%ebx
	pushl	%esi
	movl	8(%ebp), %ecx	/* ecx = meuledefoin*/
	movl	12(%ebp), %edx	/* edx = aguille */
	xorl	%ebx, %ebx	/* cpt = 0*/
	movl	%edx, %esi	/*save du ptr aiguille*/
	jmp	boucle

incraiguille:
	incl	%edx

boucleaiguille:
	cmpb	$0, (%edx)		/*if *str2 == '\0' return*/
	je	fin
	movb	(%edx), %al
	cmpb	%al, (%ecx)
	je	match
	jmp	incraiguille


match:
	incl	%ebx
	incl	%ecx


boucle:
	movl	%esi, %edx	/*restaure aiguille*/
	movb	(%ecx), %al
	cmp	$0, %ecx		/* if *str1 == '\0' return*/
	je	fin
	jmp	boucleaiguille


fin:

	movl	%ebx, %eax
	popl	%esi
	popl	%ebx
	leave
	ret
FUNC_END(strspn)
