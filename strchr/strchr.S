/**
**/

#include		"strchr.h"

STATIC_CONST(message)
	        .asciz "salut\0" 
OBJECT_END(message)


	
GLOBAL_FUNC(main)		
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp    /*prologue*/
	pushl	$79		
	pushl	$message
	call	strchr
	pushl   $1
	pushl   %eax
	pushl	$1
	call	write
	leave		
	ret		
FUNC_END(main)

/*char *strchr(char *str, int n)*/
GLOBAL_FUNC(strchr)
	pushl	%ebp        /* prologue*/
	movl	%esp, %ebp  /* prologue*/
	movl	8(%ebp), %ebx /* ebx = str*/
	movl	12(%ebp), %edx /*%edx = n */
boucle :
	cmpb	(%ebx), %dl	/*if *str == n */	
	je	ok		/* goto ok*/
	//cmpb	(%ebx), %dl	/* goto error*/
	cmpb	$0, (%ebx) /* if *str == 0 */
	je	error
	incl	%ebx		/* str++*/
	jmp	boucle
ok :	
	movl	%ebx, %eax
	jmp	fin

error:
	xorl	%eax, %eax
fin :	
	leave
	ret
FUNC_END(strchr)	
	
GLOBAL_FUNC(mystrlen)

	pushl	%ebp        /* prologue*/
	movl	%esp, %ebp  /* prologue*/

	movl	8(%ebp), %ebx /* ebx = str*/
	xorl	$0, %ecx      /* ecx = 0*/
	xorl     %eax, %eax     /* eax = 0*/
	cmpb	$0, (%ebx)   /* (if *ebx == 0)*/
	je	end	      /* goto end*/
cpt :
	incl	%ecx           /*ecx++ */
	addl	$1, %ebx       /* ebx++ */
	cmpb	$0, (%ebx)    /* if (*ebx != 0)*/
	jne	cpt            /* goto cpt*/
end :
	movl	%ecx, %eax      /* return (eax)*/
	leave
	ret
FUNC_END(mystrlen)	
	
GLOBAL_FUNC(aff_str)
	pushl	%ebp
	movl	%esp, %ebp
	movl	8(%ebp), %ebx
	pushl	%ebx
	call	mystrlen
	popl	%ebx
	pushl	%eax
	pushl	%ebx
	pushl	$1
	call	write
	popl	%eax
	popl	%ebx
	leave
	ret
FUNC_END(aff_str)
