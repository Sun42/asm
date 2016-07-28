CC = gcc
NAME = minilibc.so
CFLAGS += -W -Wall -ansi -pedantic -fno-builtin -nostdlib
RM = rm -rf

SRC = 	strncmp.S

OBJ = $(SRC:.S=.o)

NAME : $(OBJ)
	$(CC) -shared -o $(NAME) $(OBJ)

all:	$(NAME)

clean :
	$(RM) $(NAME)
	$(RM) $(OBJ)


#export LD_LIBRARY_PATH=.
#export LD_PRELOAD=minilibc.so