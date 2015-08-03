NAME    = r2fa-test.bin
CHANNEL = debug
LIBDIR  = ../target/$(CHANNEL)/
INCDIR  = ../include/
SRC     = r2fa_test.c
OBJ     = $(SRC:.c=.o)
CC      = cc
CFLAGS  = -g -Wall -Wextra -ansi -pedantic -I$(INCDIR)
LDFLAGS = -L$(LIBDIR) -lr2fa
PYSRC   = r2fa_test


all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(LDFLAGS)

test: $(NAME)
	@(hash valgrind 2>/dev/null && LD_LIBRARY_PATH=$(LIBDIR) valgrind ./$(NAME)) || echo "Unable to locate valgrind."
	@LD_LIBRARY_PATH=$(LIBDIR) ./$(NAME)
	@(hash python2 2>/dev/null && python2 --version && python2 -m unittest $(PYSRC)) || echo "Unable to locate python2."
	@(hash python3 2>/dev/null && python3 --version && python3 -m unittest $(PYSRC)) || echo "Unable to locate python3."

clean:
	@rm -rf $(NAME) $(OBJ) $(R2FALIB) '__pycache__' *.pyc

re: clean all
