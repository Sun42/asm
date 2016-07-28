/**
**/

#include		"count_args.h"

STATIC_CONST(message)           // static const char message[] =
	        .asciz "!\12" // "hello world\n";
OBJECT_END(message)
	
GLOBAL_FUNC(main)		
	pushl	%ebp		
	movl	%esp, %ebp
	movl	8(%ebp), %ebx
	movl	$0, %ecx
	cmp	%ebx, %ecx
	je	fin

top :
	pushl	$2
	pushl	$message
	pushl	$1
	call    write	      
	decl	%ebx
	cmp     %ebx , %ecx
	jne	top
fin:	
	leave		
	ret		
FUNC_END(main)

