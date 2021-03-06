/*
** ssize_t read(int fd, const void *buf, size_t count);
**  todo,emacs  gimp firefox : failed
*/

#include "asm.h"

GLOBAL_FUNC(read)
	.global errno
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	movl	8(%ebp), %ebx /* ebx, arg 1*/
	movl	12(%ebp), %ecx /* ecx, le buffer arg 2*/
	movl	16(%ebp), %edx	/* le nombre de chars arg 3*/
	movl	$3, %eax	/*Num appel systeme a read */
	int	$0x80		/*interuption 0x80*/
	jb	error
	jmp	end

error:
	movl %eax, errno
	movl  $-1, %eax

end:
	popl	%ebx
	leave
	ret
FUNC_END(read)
