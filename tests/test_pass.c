/*
 * SPDX-FileCopyrightText: Rodolphe Bréard
 * SPDX-License-Identifier: CECILL-C OR CECILL-2.1
 */


#include <assert.h>
#include <libreauth.h>
#include <string.h>
#include "libreauth_tests.h"


static uint32_t test_valid_pass(void) {
	test_name("pass: test_valid_pass");

	struct libreauth_pass_cfg cfg1, cfg2;
	const char password[] = "correct horse battery staple";
	const char invalid_pass[] = "123456";
	char storage[LIBREAUTH_PASSWORD_STORAGE_LEN];

	uint32_t ret = libreauth_pass_init(&cfg1);
	assert(ret == LIBREAUTH_PASS_SUCCESS);
	assert(cfg1.min_len == 8);
	assert(cfg1.max_len == 128);
	assert(cfg1.salt_len == 16);
	assert(cfg1.version == 0);
	assert(cfg1.algorithm == LIBREAUTH_PASS_ARGON2);
	assert(cfg1.length_calculation == LIBREAUTH_PASS_CODEPOINTS);
	assert(cfg1.normalization == LIBREAUTH_PASS_NFKC);
	assert(cfg1.standard == LIBREAUTH_PASS_NOSTANDARD);

	ret = libreauth_pass_hash(&cfg1, password, storage, LIBREAUTH_PASSWORD_STORAGE_LEN);
	assert(ret == LIBREAUTH_PASS_SUCCESS);

	ret = libreauth_pass_init_from_phc(&cfg2, storage);
	assert(ret == LIBREAUTH_PASS_SUCCESS);
	assert(cfg2.min_len == 8);
	assert(cfg2.max_len == 128);
	assert(cfg2.salt_len == 16);
	assert(cfg2.version == 0);
	assert(cfg2.algorithm == LIBREAUTH_PASS_ARGON2);
	assert(cfg2.length_calculation == LIBREAUTH_PASS_CODEPOINTS);
	assert(cfg2.normalization == LIBREAUTH_PASS_NFKC);
	assert(cfg2.standard == LIBREAUTH_PASS_NOSTANDARD);

	assert(libreauth_pass_is_valid(password, storage));
	assert(!libreauth_pass_is_valid(invalid_pass, storage));

	return 1;
}

static uint32_t test_nist_pass(void) {
	test_name("pass: test_nist_pass");

	struct libreauth_pass_cfg   cfg1, cfg2;
	const char password[] = "correct horse battery staple";
	const char invalid_pass[] = "123456";
	char storage[LIBREAUTH_PASSWORD_STORAGE_LEN];

	uint32_t ret = libreauth_pass_init_std(&cfg1, LIBREAUTH_PASS_NIST80063B);
	assert(ret == LIBREAUTH_PASS_SUCCESS);
	assert(cfg1.min_len == 8);
	assert(cfg1.max_len == 128);
	assert(cfg1.salt_len == 16);
	assert(cfg1.version == 0);
	assert(cfg1.algorithm == LIBREAUTH_PASS_PBKDF2);
	assert(cfg1.length_calculation == LIBREAUTH_PASS_CODEPOINTS);
	assert(cfg1.normalization == LIBREAUTH_PASS_NFKC);
	assert(cfg1.standard == LIBREAUTH_PASS_NIST80063B);
	cfg1.version = 42;

	ret = libreauth_pass_hash(&cfg1, password, storage, LIBREAUTH_PASSWORD_STORAGE_LEN);
	assert(ret == LIBREAUTH_PASS_SUCCESS);

	ret = libreauth_pass_init_from_phc(&cfg2, storage);
	assert(ret == LIBREAUTH_PASS_SUCCESS);
	assert(cfg2.min_len == 8);
	assert(cfg2.max_len == 128);
	assert(cfg2.salt_len == 16);
	assert(cfg2.version == 42);
	assert(cfg2.algorithm == LIBREAUTH_PASS_PBKDF2);
	assert(cfg2.length_calculation == LIBREAUTH_PASS_CODEPOINTS);
	assert(cfg2.normalization == LIBREAUTH_PASS_NFKC);
	// If built from PHC, the standard is irrelevant.
	assert(cfg2.standard == LIBREAUTH_PASS_NOSTANDARD);

	assert(libreauth_pass_is_valid(password, storage));
	assert(!libreauth_pass_is_valid(invalid_pass, storage));

	return 1;
}

static uint32_t test_invalid_pass(void) {
	test_name("pass: test_invalid_pass");

	struct libreauth_pass_cfg   cfg;
	const char password[] = "invalid password";
	const char reference[] = "$pbkdf2$hmac=sha256,iter=21000$RSF4Aw$pgenLCySNXpFaLmYxfcI+AHwsf+66iBTV+COTTJYMMk";

	uint32_t ret = libreauth_pass_init_from_phc(&cfg, reference);
	assert(ret == LIBREAUTH_PASS_SUCCESS);
	assert(cfg.min_len == 8);
	assert(cfg.max_len == 128);
	assert(cfg.salt_len == 4);
	assert(cfg.version == 0);
	assert(cfg.algorithm == LIBREAUTH_PASS_PBKDF2);
	assert(cfg.length_calculation == LIBREAUTH_PASS_CODEPOINTS);
	assert(cfg.normalization == LIBREAUTH_PASS_NFKC);
	assert(cfg.standard == LIBREAUTH_PASS_NOSTANDARD);

	assert(!libreauth_pass_is_valid(password, reference));

	return 1;
}

static uint32_t test_xhmac(void) {
	test_name("pass: test_xhmac");

	struct libreauth_pass_cfg   cfg;
	const char password[] = "correct horse battery staple";
	char storage[LIBREAUTH_PASSWORD_STORAGE_LEN];

	uint32_t ret = libreauth_pass_init(&cfg);
	assert(ret == LIBREAUTH_PASS_SUCCESS);
	cfg.xhmac_type = LIBREAUTH_PASS_XHMAC_AFTER;
	cfg.xhmac_alg = LIBREAUTH_HASH_SHA_384;
	cfg.pepper = "123";
	cfg.pepper_len = 3;

	ret = libreauth_pass_hash(&cfg, password, storage, LIBREAUTH_PASSWORD_STORAGE_LEN);
	assert(ret == LIBREAUTH_PASS_SUCCESS);
	assert(strstr(storage, "xhmac=after") != NULL);
	assert(strstr(storage, "xhmac-alg=sha384") != NULL);

	assert(libreauth_pass_is_valid_xhmac(password, storage, cfg.pepper, cfg.pepper_len));
	assert(!libreauth_pass_is_valid_xhmac(password, storage, cfg.pepper, cfg.pepper_len - 1));
	assert(!libreauth_pass_is_valid(password, storage));

	return 1;
}

uint32_t test_pass(void) {
	int nb_tests = 0;

	nb_tests += test_valid_pass();
	nb_tests += test_nist_pass();
	nb_tests += test_invalid_pass();
	nb_tests += test_xhmac();

	return nb_tests;
}
