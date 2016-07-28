#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "asm.h"

int	mystrncmp(const char *s1, const char *s2, size_t n);

int	main(int ac, char **av)
{
    if (ac == 3)
    {
      printf("Official --> %i \n", strncmp(av[1], av[2], strlen(av[1])));
      printf("Asm --> %i \n", mystrncmp(av[1], av[2], strlen(av[1])));
      printf("Official --> %i \n", strncmp(av[1], av[2], strlen(av[2])));
      printf("Asm --> %i \n", mystrncmp(av[1], av[2], strlen(av[2])));
    }
    return (0);
}
