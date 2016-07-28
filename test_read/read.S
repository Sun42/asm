/*
** ssize_t myread(int fd, const void *buf, size_t count);
*/

#include "asm.h"

GLOBAL_FUNC(myread)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	%ebx
	movl	8(%ebp), %ebx /* ebx, arg 1*/
	movl	12(%ebp), %ecx /* ecx, le buffer arg 2*/
	movl	16(%ebp), %edx	/* le nombre de chars arg 3*/

	movl	$3, %eax
	int	$0x80

	popl	%ebx

	leave
	ret
FUNC_END(myread)
