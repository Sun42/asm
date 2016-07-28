	.file	"my_strlen.c"
	.text
.globl my_strlen
	.type	my_strlen, @function
my_strlen:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$16, %esp
	movl	$0, -4(%ebp)
	jmp	.L2
.L3:
	incl	-4(%ebp)
.L2:
	movl	-4(%ebp), %eax
	addl	8(%ebp), %eax
	movb	(%eax), %al
	testb	%al, %al
	jne	.L3
	movl	-4(%ebp), %eax
	leave
	ret
	.size	my_strlen, .-my_strlen
	.ident	"GCC: (GNU) 4.2.1 20070712 (prerelease)"
