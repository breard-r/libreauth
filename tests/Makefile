NAME    = libreauth-test.bin
CHANNEL = debug
LIBDIR  = ../target/$(CHANNEL)/
INCDIR  = ../include/
SRC     = test_libreauth.c \
		test_hotp.c \
		test_pass.c \
		test_totp.c
OBJ     = $(SRC:.c=.o)
CC      = cc
CFLAGS  = -g -Werror -Wall -Wextra -ansi -pedantic -I$(INCDIR)
LDFLAGS = -L$(LIBDIR) -llibreauth
PYSRC   = libreauth_test


all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(LDFLAGS)

test: $(NAME)
	@(hash valgrind 2>/dev/null && LD_LIBRARY_PATH=$(LIBDIR) valgrind ./$(NAME))
	@LD_LIBRARY_PATH=$(LIBDIR) ./$(NAME)
	@(hash python2 2>/dev/null && python2 --version && python2 -m unittest $(PYSRC))
	@(hash python3 2>/dev/null && python3 --version && python3 -m unittest $(PYSRC))

tests: test

clean:
	@rm -rf $(NAME) $(OBJ) '__pycache__' *.pyc

re: clean all

.PHONY: all test tests clean re
