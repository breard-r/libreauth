/*
 * SPDX-FileCopyrightText: Rodolphe Bréard
 * SPDX-License-Identifier: CECILL-C OR CECILL-2.1
 */


#include <stdint.h>
#include <stdio.h>
#include "libreauth_tests.h"


void test_name(const char *name) {
	printf("Running test: %s\n", name);
}

int main(void) {
	uint32_t nb_tests = 0;

	nb_tests += test_hotp();
	nb_tests += test_totp();
	nb_tests += test_pass();
	nb_tests += test_key();

	printf("Ran %d tests.\n", nb_tests);

	return 0;
}
