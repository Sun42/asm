#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "asm.h"

size_t mystrspn(const char *s, const char *reject);

int	main(int ac, char **av)
{
  if (ac == 3)
    {
      printf("Official --> %i \n", strspn(av[1], av[2]));
      printf("Asm --> %i \n", mystrspn(av[1], av[2]));
    }
  return (0);
}

