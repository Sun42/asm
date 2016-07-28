#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "asm.h"

void *mymemcpy(void *dest, const void *src, size_t n);

int	main(int ac, char **av)
{
  char	*str;
  char	*str2;
  int	n1;
  int	n2;

  if (ac == 2)
    {
      n1 = strlen(av[1]) + 1;
      n2 = -1;
      str = malloc(sizeof(char) * n1);
      str2 = malloc(sizeof(char) * n1);
      printf("Official --> %s \n", memcpy(str, av[1], n1));
      printf("Official --> %s \n", str);
      printf("Strlen official --> %i \n", strlen(str));
      printf("Asm --> %s \n", mymemcpy(str2, av[1], n1 + 100));
      printf("Asm --> %s \n", str2);
      printf("Strlen Asm --> %i \n", strlen(str2));
    }
  return (0);
}
