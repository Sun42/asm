STATIC_FUNC(WRITE)
	movl $4, %eax
	int	$0x80
	ret
FUNC_END(WRITE)
STATIC_FUNC(READ)
	movl $3, %eax
	int	$0x80
	ret
FUNC_END(READ)
