CC = gcc
NAME = minilibc.so
CFLAGS += -W -Wall -ansi -pedantic -fno-builtin -nostdlib
RM = rm -rf

SRC =	read.S
#fake_func.S
#strcasecmp.S

#	memmove.S
#	fake_func.S
#	strchr.S
#	strlen.S \
#	strspn.S
#	write.S
#	strstr.S
#	rindex.S
#	strncmp.S
#	memcpy.S
#	memset.S
#	strcmp.S
#	read.S -

OBJ =  $(SRC:.S=.o)


$NAME : $(OBJ)
	$(CC) -shared -o $(NAME) $(OBJ)

clean :
	$(RM) $(NAME)
	$(RM) $(OBJ)



#export LD_LIBRARY_PATH=.
#export LD_PRELOAD=minilibc.so
