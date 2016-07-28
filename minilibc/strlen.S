/*
** size_t strlen(const char *str)
** tested ok : firefox, gimp , ls, top
*/

#include	"asm.h"


GLOBAL_FUNC(strlen)

	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	movl	8(%ebp), %edx	/* edx = str*/
	xorl	%ecx, %ecx	/* ecx = 0*/
	xorl	%eax, %eax	/* eax = 0*/
	cmpb	$0, (%edx)	/* (if *edx == 0)*/
	je	end		/* goto end*/
cpt :
	incl	%ecx		/*ecx++ */
	addl	$1, %edx	/* edx++ */
	cmpb	$0, (%edx)	/* if (*edx != 0)*/
	jne	cpt		/* goto cpt*/
end :
	movl	%ecx, %eax	/* return (eax)*/
	leave
	ret
FUNC_END(strlen)
