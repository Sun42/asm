#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "asm.h"

#define BUF_SIZE 4

ssize_t myread(int fd, const void *buf, size_t count);

int	main(int ac, char **av)
{
  char	buf[BUF_SIZE];

  printf("nb lu %i \n", myread(0, buf, BUF_SIZE));

  return (0);
}
