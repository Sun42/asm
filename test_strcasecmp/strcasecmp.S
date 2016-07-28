/*
* int mystrcmp(const char *s1, const char *s2);
*/

#include		"asm.h"


GLOBAL_FUNC(mystrcasecmp)

	pushl	%ebp		/* prologue*/
	movl	%esp, %ebp	/* prologue*/

	pushl	%ebx		/*not ready for use */
	pushl	%edi
	pushl	%esi

	movl	8(%ebp), %edi	/* ebx = s1 */
	movl	12(%ebp), %esi	/* ecx = s2*/
	jmp	boucle

				/*if isupper(char c) => tolower*/
tolower1:
	cmpb	$45, %bl
	jl	tolower2	/*if c < 'A'(45)  =>  no need to convert*/
	cmpb	$90, %bl
	jg	tolower2	/*if c > 'Z'(90)  => no need to convert*/
	addb	$32, %bl		/*else c += 32  <==> */

tolower2:
	cmpb	$45, %cl
	jl	suiteboucle
	cmpb	$90, %cl
	jg	suiteboucle
	addb	$32, %cl
	jmp	suiteboucle

boucle:
	movb	(%edi), %bl
	movb	(%esi), %cl
	jmp	tolower1

suiteboucle:

	cmpb	%cl, %bl
	jne	fin		/* if *s1 != *s2 */
	cmpb	$0, %cl
	je	fin		/*if (*s2 == '\0') || (*s1 == '\0')*/
	incl	%edi
	incl	%esi
	jmp	boucle


fin:
	subb	%cl, %bl
	movsbl	%bl, %eax	/*return (*s2 - *s1)*/

	popl	%esi
	popl	%edi
	popl	%ebx		/*not ready for use */
	leave
	ret

FUNC_END(mystrcasecmp)
