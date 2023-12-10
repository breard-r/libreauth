NAME	= libreauth-test.bin
CHANNEL	= debug
LIBDIR	= ../target/$(CHANNEL)/
INCDIR	= ../include/
SRC		= test_libreauth.c \
		test_hotp.c \
		test_key.c \
		test_pass.c \
		test_totp.c
OBJ		= $(SRC:.c=.o)
CC		= clang
CFLAGS	= -std=c11 -g -Wall -Wextra -Wpedantic -Wshadow -Werror -Wstrict-overflow -fno-strict-aliasing -I$(INCDIR)
LDFLAGS	= -L$(LIBDIR) -llibreauth
PYSRC	= libreauth_test


all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(LDFLAGS)

test_valgrind: cc_version $(NAME)
	LD_LIBRARY_PATH=$(LIBDIR) valgrind ./$(NAME)

test: cc_version $(NAME)
	@LD_LIBRARY_PATH=$(LIBDIR) ./$(NAME)

tests: test

clean:
	@rm -rf $(NAME) $(OBJ)

cc_version:
	$(CC) --version

re: clean all

.PHONY: all test tests clean cc_version re
