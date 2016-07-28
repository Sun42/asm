/*
char *strstr(const char *meule_de_foin, const char *aiguille) ;
> ./test_strstr "sdfsdf" "sdfd"
	Official --> (null)
	Asm --> sdfsdf

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "asm.h"

char *mystrstr(const char *meule_de_foin, const char *aiguille);

int	main(int ac, char **av)
{
  if (ac == 3)
    {
      printf("Official --> %s \n", strstr(av[1], av[2]));
      printf("Asm --> %s \n", mystrstr(av[1], av[2]));
    }
  return (0);
}
