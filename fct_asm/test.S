 define N 16 .global _start
	.comm BUFF , N
_start: mov $3 , %eax
	mov $0 , %ebx
	mov $BUFF ,%ecx
	mov $N ,%edx
	int $0x80


	mov %eax , %edx
	mov $4 , %eax
	mov $1 , %ebx
	mov $BUFF , %ecx
	int $0x80


	mov $1, %eax
	mov $0 , %ebx
	int $0x80