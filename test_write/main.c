#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "asm.h"

ssize_t mywrite(int fd, const void *buf, size_t count);

int	main(int ac, char **av)
{
    if (ac == 2)
    {
      printf("nb write %i \n", mywrite(1, av[1], strlen(av[1])));
      printf("nb write %i \n", write(1, av[1], strlen(av[1])));
      /*write(1, av[1],strlen(av[1]));*/
      /*printf("\nFin write \n");*/
    }
  return (0);
}
