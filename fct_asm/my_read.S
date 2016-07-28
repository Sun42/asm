#include               	"symbol_macros.h"
	.file		"my_read.S"
	.section	.rodata

STATIC_CONST(read)
	pushl	$3
	int	$0x80
OBJECT_END(read)
