#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include "asm.h"

char *myrindex(const char *s, int c);

int	main(int ac, char **av)
{
  if (ac == 3)
    {
      printf("Official --> %s \n", rindex(av[1], av[2][0]));
      printf("Asm --> %s \n", myrindex(av[1], av[2][0]));
    }
  return (0);
}
