/*
 * SPDX-FileCopyrightText: Rodolphe Bréard
 * SPDX-License-Identifier: CECILL-C OR CECILL-2.1
 */


#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <libreauth.h>
#include "libreauth_tests.h"

#define KEY_SIZE 42

static uint32_t test_uniqueness(void) {
	test_name("key: test_uniqueness");

	char k1[KEY_SIZE] = {0};
	char k2[KEY_SIZE] = {0};

	int32_t r1 = libreauth_keygen(k1, KEY_SIZE);
	int32_t r2 = libreauth_keygen(k2, KEY_SIZE);

	assert(r1 == EXIT_SUCCESS);
	assert(r2 == EXIT_SUCCESS);
	assert(strncmp(k1, k2, KEY_SIZE) != 0);

	return 1;
}

static uint32_t test_null_ptr(void) {
	test_name("key: test_null_ptr");

	assert(libreauth_keygen(NULL, 42) != EXIT_SUCCESS);

	return 1;
}

static uint32_t test_zero_len(void) {
	test_name("key: test_zero_len");

	char k[KEY_SIZE] = {0};
	assert(libreauth_keygen(k, 0) != EXIT_SUCCESS);

	return 1;
}

uint32_t test_key(void) {
	int nb_tests = 0;

	nb_tests += test_uniqueness();
	nb_tests += test_null_ptr();
	nb_tests += test_zero_len();

	return nb_tests;
}
