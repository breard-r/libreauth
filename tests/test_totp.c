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


static int test_basic_totp(void) {
  struct r2fa_totp_cfg cfg;
  char code[] = "qwerty", key[] = "12345678901234567890";
  int ret;

  test_name("totp: test_basic_totp");

  ret = r2fa_totp_init(&cfg);
  assert(ret == R2FA_OTP_SUCCESS);
  assert(cfg.key == NULL);
  assert(cfg.key_len == 0);
  assert(cfg.timestamp != 0);
  assert(cfg.period == 30);
  assert(cfg.initial_time == 0);
  assert(cfg.output_len == 6);
  assert(cfg.output_base == NULL);
  assert(cfg.output_base_len == 0);
  assert(cfg.hash_function == R2FA_OTP_SHA_1);

  cfg.key = key;
  cfg.key_len = sizeof(key);

  ret = r2fa_totp_generate(&cfg, code);
  assert(ret == R2FA_OTP_SUCCESS);
  assert(strlen(code) == 6);
  assert(!r2fa_totp_is_valid(NULL, "755224"));
  assert(!r2fa_totp_is_valid(&cfg, "4755224"));
  assert(!r2fa_totp_is_valid(&cfg, "!@#$%^"));
  assert(!r2fa_totp_is_valid(&cfg, ""));
  assert(!r2fa_totp_is_valid(&cfg, NULL));

  return 1;
}

static int test_advanced_totp(void) {
  struct r2fa_totp_cfg cfg;
  char code[9], key[] = "12345678901234567890123456789012";
  int ret;

  test_name("totp: test_advanced_totp");
  ret = r2fa_totp_init(&cfg);
  assert(ret == R2FA_OTP_SUCCESS);

  cfg.key = key;
  cfg.key_len = sizeof(key);
  cfg.timestamp = 1111111109;
  cfg.output_len = 8;
  cfg.hash_function = R2FA_OTP_SHA_256;

  ret = r2fa_totp_generate(&cfg, code);
  assert(ret == R2FA_OTP_SUCCESS);
  assert(strlen(code) == 8);
  assert(strncmp(code, "68084774", 9) == 0);

  assert(r2fa_totp_is_valid(&cfg, "68084774"));
  assert(!r2fa_totp_is_valid(NULL, "68084774"));
  assert(!r2fa_totp_is_valid(&cfg, "68084775"));
  assert(!r2fa_totp_is_valid(&cfg, "46808477"));
  assert(!r2fa_totp_is_valid(&cfg, "!@#$%^&*"));
  assert(!r2fa_totp_is_valid(&cfg, ""));
  assert(!r2fa_totp_is_valid(&cfg, NULL));

  return 1;
}

static int test_init_null_ptr(void) {
  int ret = r2fa_totp_init(NULL);
  test_name("totp: test_init_null_ptr");
  assert(ret == R2FA_OTP_CFG_NULL_PTR);
  return 1;
}

static int test_generate_null_ptr(void) {
  struct r2fa_totp_cfg cfg;
  char code[] = "qwerty", key[] = "12345678901234567890";
  int ret;

  test_name("totp: test_generate_null_ptr");
  r2fa_totp_init(&cfg);

  ret = r2fa_totp_generate(NULL, code);
  assert(ret == R2FA_OTP_CFG_NULL_PTR);
  assert(strcmp(code, "qwerty") == 0);

  ret = r2fa_totp_generate(&cfg, code);
  assert(ret == R2FA_OTP_KEY_NULL_PTR);

  cfg.key = key;

  ret = r2fa_totp_generate(&cfg, code);
  assert(ret == R2FA_OTP_INVALID_KEY_LEN);

  cfg.key_len = sizeof(key);

  ret = r2fa_totp_generate(&cfg, NULL);
  assert(ret == R2FA_OTP_CODE_NULL_PTR);

  ret = r2fa_totp_generate(&cfg, code);
  assert(ret == R2FA_OTP_SUCCESS);

  return 1;
}

static int test_invalid_base(void) {
  struct r2fa_totp_cfg cfg;
  char code[] = "qwerty", key[] = "12345678901234567890", base[] = "0123456789ABCDEF";
  int ret;

  test_name("totp: test_invalid_base");
  r2fa_totp_init(&cfg);

  cfg.key = key;
  cfg.key_len = sizeof(key);
  cfg.output_base = base;

  ret = r2fa_totp_generate(&cfg, code);
  assert(ret == R2FA_OTP_INVALID_BASE_LEN);
  cfg.output_base_len = 1;
  ret = r2fa_totp_generate(&cfg, code);
  assert(ret == R2FA_OTP_INVALID_BASE_LEN);

  cfg.output_base_len = sizeof(base);

  ret = r2fa_totp_generate(&cfg, code);
  assert(ret == R2FA_OTP_SUCCESS);

  return 1;
}

int test_totp(void) {
  int nb_tests = 0;

  nb_tests += test_basic_totp();
  nb_tests += test_advanced_totp();
  nb_tests += test_init_null_ptr();
  nb_tests += test_generate_null_ptr();
  nb_tests += test_invalid_base();

  return nb_tests;
}
