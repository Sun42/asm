CC = gcc
NAME = test_strlen
CFLAGS += -W -Wall -ansi -pedantic
RM = rm -rf
SRC1 = 	main.c

SRC2 = 	strlen.S

OBJ1 = $(SRC1:.c=.o)
OBJ2 = $(SRC2:.S=.o)


$NAME : $(OBJ1) $(OBJ2)
	$(CC) -o $(NAME) $(OBJ1) $(OBJ2)

clean :
	$(RM) $(NAME)



