#include               	"symbol_macros.h"
	.file		"my_write.S"
	.section	.rodata

STATIC_CONST(my_write)
	pushl	$4
	int	$0x80
OBJECT_END(my_write)
