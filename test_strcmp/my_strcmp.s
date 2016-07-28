	.file	"my_strcmp.c"
	.text
.globl strcmp
	.type	strcmp, @function
strcmp:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$4, %esp
	jmp	.L2
.L4:
	movl	8(%ebp), %edx
	movzbl	(%edx), %eax
	testb	%al, %al
	sete	%al
	addl	$1, 8(%ebp)
	testb	%al, %al
	je	.L2
	movl	$0, -4(%ebp)
	jmp	fin
.L2:
	movl	8(%ebp), %ecx
	movzbl	(%ecx), %eax
	movl	12(%ebp), %ecx
	movzbl	(%ecx), %edx
	cmpb	%dl, %al
	sete	%al
	addl	$1, 12(%ebp)
	testb	%al, %al
	jne	.L4
	movl	8(%ebp), %eax
	movzbl	(%eax), %eax
	movzbl	%al, %edx
	movl	12(%ebp), %eax
	subl	$1, %eax
	movzbl	(%eax), %eax
	movzbl	%al, %eax
	movl	%edx, %ecx
	subl	%eax, %ecx
	movl	%ecx, -4(%ebp)
fin:
	movl	-4(%ebp), %eax
	leave
	ret

