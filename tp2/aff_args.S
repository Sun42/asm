/**
**/

#include		"aff_args.h"

STATIC_CONST(message)
	        .asciz "!\12" 
OBJECT_END(message)

GLOBAL_FUNC(main) pushl	%ebp		/* prologue*/
	movl	%esp, %ebp    /*prologue*/
	movl	8(%ebp), %edx /*put ac dans edx */
	movl	$0, %ecx /* ecx = 0*/
	cmpl	%edx, %ecx /* if ac == 0*/
	je	fin
	movl  12(%ebp), %ebx   /* argv[0]*/
top :
	pushl	%ecx	/* save ecx*/
	pushl	%edx	/* save edx*/
	pushl 	%ebx	/* save ebx*/
	pushl	(%ebx)	/* dereference ebx*/
	call	aff_str
	addl	$4, %esp  /* remonte le pointeur instrucution stack*/
	popl	%ebx	  /*repop nos var*/
	popl	%edx
	popl	%ecx
	incl	%ecx           /* cpt++*/
	addl	$4, %ebx	/* argv + 1*/	
	cmpl	%edx , %ecx    /*if ac(%edx) != cpt(%ecx)*/
	jne	top           /* goto top*/
fin:
	leave
	ret		
FUNC_END(main)

GLOBAL_FUNC(aff_char)
	pushl   %ebp
	movl    %esp, %ebp
	pushl   $2
	pushl	$message
	pushl	$1
	call	write
	popl	%eax
	leave
	ret
FUNC_END(aff_char)

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
