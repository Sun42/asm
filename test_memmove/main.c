#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "asm.h"


void *mymemmove(void *dest, const void *src, size_t n);

int	main(int ac, char **av)
{
  char	*str;
  char	*src;
  char	*str3;
  char	*str4;
  char	*src2;

  str = "123456789";
  src = malloc(sizeof(char)  * 11);
  src2 = malloc(sizeof(char)  * 11);
  str4 = malloc(sizeof(char) * 11);
  str3 = malloc(sizeof(char) * 11);
  src = memcpy(src, str, 11);
  src2 = memcpy(src2, str, 11);

  str3 = memmove(str3, src, 11);
  printf("memmove --> %s \n", str3);
  printf("-- %i> \n", str3);
  printf("dest : %i, src : %i \n", str4, src);
  str4 = mymemmove(src + 3, src, 11);
  printf("mymemove ---> %s \n", str4);
  printf("-- %i \n", str4);
  return (0);
}
