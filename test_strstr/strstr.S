/*
char *strstr(const char *meule_de_foin, const char *aiguille) ;
> ./test_strstr "sdfsdf" "sdfd"
	Official --> (null)
	Asm --> sdfsdf


big = ebx
save_big = ecx
little = edx
save_little = edi
ret = edi
*/



#include		"asm.h"

GLOBAL_FUNC(mystrstr)
	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/
	pushl	%ebx
	pushl	%edi
	pushl	%esi
	xorl	%esi, %esi	/*esi = 0*/
	movl	8(%ebp), %ebx	/*big*/
	movl	8(%ebp), %ecx	/*savebig*/
	movl	12(%ebp), %edx	/*little*/
	movl	12(%ebp), %edi	/*save_little*/
	cmpb	$0, (%edx)
	je	return_savebig	/*if *little == NULL return big*/
	jmp	bouclebig


incrbig:
	incl	%ebx	/*big++*/
	incl	%ecx	/*save_big++*/	
	jmp	bouclebig

bouclebig:
	movl	%ecx, %ebx	/*restore big  big = save_big*/
	movl	%edi, %edx	/*restore little  little = save_little*/
	movb	(%ebx), %al	/*al =*big */ 
	cmpb	$0, %al	
	je	fin		/* if *big = '\0' return %esi*/
	cmpb	%al, (%edx)
	je	bouclelittle
	jmp	incrbig


nextlittle:
	incl	%edx	/*little++*/
	incl	%ebx	/*big++*/
	
bouclelittle:
	movb	(%edx), %al	/*al = *little*/
	cmpb	$0, %al		/*if *little == '\0'*/
	je	return_savebig
	cmpb	%al, (%ebx)	/*if *little ==  *big*/ 
	je	nextlittle
	jmp	incrbig
	
return_savebig:
	movl	%ecx, %esi
	jmp	fin
	
	
fin:
	movl	%esi, %eax
	popl	%esi
	popl	%edi
	popl	%ebx
	leave
	ret

FUNC_END(mystrstr)
