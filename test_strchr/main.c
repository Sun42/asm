#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "asm.h"

char	*mystrchr(const char *s, int c);

int	main(int ac, char **av)
{
  int	i;
  char	tab[26] = "abcdefghijklmnopqrstuv";

  i = 0;
  if (ac == 2)
    {
      while (tab[i] != 'v')
	{
	  printf("Official --> %s \n", strchr(av[1], ""));
	  printf("Asm      --> %s \n", mystrchr(av[1], ""));
	  i++;
	}
    }
  return (0);
}
