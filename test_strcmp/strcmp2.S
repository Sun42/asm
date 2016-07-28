#include "asm.h"

GLOBAL_FUNC(strcmp)

	pushl	%ebp	/* prologue */
	movl	%esp, %ebp /* prologue*/
	subl	$4, %esp
	jmp	debut
.L4:
	movl	8(%ebp), %edx /* edx = s1*/
	movzbl	(%edx), %eax	/* eax = *s1 */
	testb	%al, %al	/* test sil al  != NULL*/
	sete	%al		/* set if equal */
	addl	$1, 8(%ebp)	/**/
	testb	%al, %al
	je	.L2
	movl	$0, -4(%ebp)
	jmp	fin

debut:
	movl	8(%ebp), %ecx
	movzbl	(%ecx), %eax
	movl	12(%ebp), %ecx
	movzbl	(%ecx), %edx
	cmpb	%dl, %al
	sete	%al
	addl	$1, 12(%ebp)
	testb	%al, %al
	jne	.L4
	movl	8(%ebp), %eax
	movzbl	(%eax), %eax
	movzbl	%al, %edx
	movl	12(%ebp), %eax
	subl	$1, %eax
	movzbl	(%eax), %eax
	movzbl	%al, %eax
	movl	%edx, %ecx
	subl	%eax, %ecx
	movl	%ecx, -4(%ebp)
fin:
	movl	-4(%ebp), %eax
	leave
	ret
FUNC_END(strcmp)
