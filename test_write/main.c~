#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include "asm.h"

int	mystrcasecmp(const char *s1, const char *s2);

int	main(int ac, char **av)
{
    if (ac == 3)
    {
      printf("Official --> %i \n", strcasecmp(av[1], av[2]));
      printf("Asm --> %i \n", mystrcasecmp(av[1], av[2]));
    }
  return (0);
}
