/*
 * Copyright (c) 2015 Rodolphe Breard
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <strings.h>
#include <string.h>
#include <assert.h>
#include <r2fa.h>
#include "r2fa_tests.h"


static int test_basic_hotp(void) {
  struct r2fa_hotp_cfg cfg;
  char code[] = "qwerty", key[] = "12345678901234567890";
  int ret;

  test_name("hotp: test_basic_hotp");

  ret = r2fa_hotp_init(&cfg);
  assert(ret == R2FA_OATH_SUCCESS);
  assert(cfg.key == NULL);
  assert(cfg.key_len == 0);
  assert(cfg.counter == 0);
  assert(cfg.output_len == 6);
  assert(cfg.output_base == NULL);
  assert(cfg.output_base_len == 0);
  assert(cfg.hash_function == R2FA_OATH_SHA_1);

  cfg.key = key;
  cfg.key_len = sizeof(key);

  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_SUCCESS);
  assert(strlen(code) == 6);
  assert(strncmp(code, "755224", 7) == 0);

  assert(r2fa_hotp_is_valid(&cfg, "755224"));
  assert(!r2fa_hotp_is_valid(NULL, "755224"));
  assert(!r2fa_hotp_is_valid(&cfg, "755225"));
  assert(!r2fa_hotp_is_valid(&cfg, "4755224"));
  assert(!r2fa_hotp_is_valid(&cfg, "!@#$%^"));
  assert(!r2fa_hotp_is_valid(&cfg, ""));
  assert(!r2fa_hotp_is_valid(&cfg, NULL));

  return 1;
}

static int test_init_null_ptr(void) {
  int ret = r2fa_hotp_init(NULL);
  test_name("hotp: test_init_null_ptr");
  assert(ret == R2FA_OATH_CFG_NULL_PTR);
  return 1;
}

static int test_generate_null_ptr(void) {
  struct r2fa_hotp_cfg cfg;
  char code[] = "qwerty", key[] = "12345678901234567890";
  int ret;

  test_name("hotp: test_generate_null_ptr");
  r2fa_hotp_init(&cfg);

  ret = r2fa_hotp_generate(NULL, code);
  assert(ret == R2FA_OATH_CFG_NULL_PTR);
  assert(strcmp(code, "qwerty") == 0);

  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_KEY_NULL_PTR);

  cfg.key = key;

  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_INVALID_KEY_LEN);

  cfg.key_len = sizeof(key);

  ret = r2fa_hotp_generate(&cfg, NULL);
  assert(ret == R2FA_OATH_CODE_NULL_PTR);

  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_SUCCESS);

  return 1;
}

static int test_invalid_base(void) {
  struct r2fa_hotp_cfg cfg;
  char code[] = "qwerty", key[] = "12345678901234567890", base[] = "0123456789ABCDEF";
  int ret;

  test_name("hotp: test_invalid_base");
  r2fa_hotp_init(&cfg);

  cfg.key = key;
  cfg.key_len = sizeof(key);
  cfg.output_base = base;

  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_INVALID_BASE_LEN);
  cfg.output_base_len = 1;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_INVALID_BASE_LEN);

  cfg.output_base_len = sizeof(base);

  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_SUCCESS);

  return 1;
}

static int test_invalid_code(void) {
  struct r2fa_hotp_cfg cfg;
  char code[21],
    key[] = "12345678901234567890",
    base10[] = "0123456789",
    base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    base64[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
  int ret;

  test_name("hotp: test_invalid_code");
  r2fa_hotp_init(&cfg);

  cfg.key = key;
  cfg.key_len = strlen(key);

  /* Base 10 */
  cfg.output_base = base10;
  cfg.output_base_len = strlen(base10);

  cfg.output_len = 5;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_CODE_TOO_SMALL);

  cfg.output_len = 6;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_SUCCESS);
  assert(strlen(code) == 6);

  cfg.output_len = 9;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_SUCCESS);
  assert(strlen(code) == 9);

  cfg.output_len = 10;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_CODE_TOO_BIG);

  cfg.output_len = 0xffffff;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_CODE_TOO_BIG);

  /* Base 32 */
  cfg.output_base = base32;
  cfg.output_base_len = strlen(base32);

  cfg.output_len = 3;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_CODE_TOO_SMALL);

  cfg.output_len = 4;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_SUCCESS);
  assert(strlen(code) == 4);

  cfg.output_len = 6;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_SUCCESS);
  assert(strlen(code) == 6);

  cfg.output_len = 7;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_CODE_TOO_BIG);

  cfg.output_len = 0xffffff;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_CODE_TOO_BIG);

  /* Base 64 */
  cfg.output_base = base64;
  cfg.output_base_len = strlen(base64);

  cfg.output_len = 3;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_CODE_TOO_SMALL);

  cfg.output_len = 4;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_SUCCESS);
  assert(strlen(code) == 4);

  cfg.output_len = 5;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_SUCCESS);
  assert(strlen(code) == 5);

  cfg.output_len = 6;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_CODE_TOO_BIG);

  cfg.output_len = 0xffffff;
  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == R2FA_OATH_CODE_TOO_BIG);

  return 1;
}

int test_hotp(void) {
  int nb_tests = 0;

  nb_tests += test_basic_hotp();
  nb_tests += test_init_null_ptr();
  nb_tests += test_generate_null_ptr();
  nb_tests += test_invalid_base();
  nb_tests += test_invalid_code();

  return nb_tests;
}
