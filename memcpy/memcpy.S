/**
**/

#include		"memcpy.h"

STATIC_CONST(message)
	        .asciz "salut" 
OBJECT_END(message)



GLOBAL_FUNC(main)
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/*prologue*/
	pushl	$6
	call	malloc
	movl	%eax, %edi
	pushl	$5
	pushl	$message
	pushl	%edi
	call	memcpy
	movl	%eax, %edx
	pushl	$5
	pushl	%edx
	pushl	$1
	call	write
	leave
	ret
FUNC_END(main)

/* %esi %edi */
/*void *memcpy (void *dest, const void *src, size_t n) ;*/
GLOBAL_FUNC(memcpy)
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/
	movl	8(%esp), %ebx	/*ebx = dest */
	pushl	%ebx		/* push dest sur la pile */
	movl	12(%esp), %edx	/* edx = src*/
	movl	16(%esp), %esi	/* esi = n*/

boucle:
	cmpl	$0, %esi	/* if n == 0*/
 	je	fin		/*goto fin */

	movl	(%edx), %eax
	movl	%eax, (%ebx)	/* *dest = *src*/
	decl	%esi		/*n--*/
	incl	%ebx		/* dest++*/
	incl	%edx		/* src++*/
fin :
	popl	%eax		/* pop dest*/
	leave
	ret
FUNC_END(memcpy)

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
