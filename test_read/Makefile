CC = gcc
NAME = test_read
CFLAGS += -W -Wall -ansi -pedantic -fno-builtin -nostdlib
RM = rm -rf
SRC1 = 	main.c

SRC2 = 	read.S


OBJ1 = $(SRC1:.c=.o)
OBJ2 =  $(SRC2:.S=.o)


$NAME : $(OBJ1) $(OBJ2)
	$(CC) -o $(NAME) $(OBJ1) $(OBJ2)

clean :
	$(RM) $(NAME)
	$(RM) $(OBJ1)
	$(RM) $(OBJ2)


