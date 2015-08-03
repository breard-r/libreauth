NAME    = r2fa-test.bin
CHANNEL = debug
LIBDIR  = ../target/$(CHANNEL)/
INCDIR  = ../include/
SRC     = r2fa_test.c
OBJ     = $(SRC:.c=.o)
CC      = cc
CFLAGS  = -g -Wall -Wextra -ansi -pedantic -I$(INCDIR)
LDFLAGS = -L$(LIBDIR) -lr2fa
PYSRC   = r2fa_test.py


all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(LDFLAGS)

test: $(NAME)
	@(hash valgrind 2>/dev/null && LD_LIBRARY_PATH=$(LIBDIR) valgrind ./$(NAME)) || echo "Unable to locate  valgrind."
	@LD_LIBRARY_PATH=$(LIBDIR) ./$(NAME)
	@python -m unittest $(PYSRC)

clean:
	@rm -rf $(NAME) $(OBJ) $(R2FALIB) '__pycache__' *.pyc

re: clean all
