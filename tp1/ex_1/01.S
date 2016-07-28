#include		"01.h"


STATIC_CONST(message)		// static const char message[] =
	.asciz "hello world\12"	// "hello world\n";
OBJECT_END(message)


GLOBAL_FUNC(main)		
	pushl	%ebp		
	movl	%esp, %ebp
	movl    8(%ebp), %eax
	jmp labputstr
	leave
	ret
labputstr :
        	movl    12(%ebp), %ebx
	        movl    4(%ebx), %ebx
	        pushl   %ebx
	        call    myputstr
	       	movl	$0, %ebx
		leave
		ret	
FUNC_END(main)
	
STATIC_FUNC(myputstr)
	pushl	%ebp
	movl	%esp, %ebp
	movl	8(%esp), %ebx
	pushl	%ebx
	call	strlen
	pushl	%eax
	pushl	%ebx
	pushl	$1
	call	write
	leave
	ret
FUNC_END(myputstr)


STATIC_FUNC(my_strlen)
	pushl %ebp
	movl %esp, %ebp
	movl 8(%esp), %edx
	leave
	ret
FUNC_END(my_strlen)
