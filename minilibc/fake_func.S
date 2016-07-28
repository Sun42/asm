/*
** size_t strlen(const char *str)
**
*/

#include	"asm.h"

/*fake*/
GLOBAL_FUNC(read)
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax
	pushl	%eax

end :
	movl	%ecx, %eax	/* return (eax)*/
	leave
	ret
FUNC_END(read)
