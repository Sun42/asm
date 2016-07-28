#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "asm.h"


void *mymemset(void *s, int c, size_t n);
int	main(int ac, char **av)
{
  char	*str;
  char	*str2;
  int	n;

  if (ac == 3)
    {
      n = atoi(av[2]);
      str = malloc(sizeof(char) * n);
      str2 = malloc(sizeof(char) * n);
      printf("Official --> %s \n", memset((void *)str, av[1][0], n + 1));
      printf("Strlen official --> %i \n", strlen(str));
      printf("Asm --> %s \n", mymemset((void *)str2, av[1][0], n + 1));
      printf("Strlen Asm --> %i \n", strlen(str2));
    }
  return (0);
}
