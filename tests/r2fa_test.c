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
#include <stdio.h>
#include <r2fa.h>


void test_hotp(void) {
  struct r2fa_hotp_cfg cfg;
  char code[7], key[] = "12345678901234567890";
  int ret;

  ret = r2fa_hotp_init(&cfg);
  assert(ret == 0);
  assert(cfg.key == NULL);
  assert(cfg.key_len == 0);
  assert(cfg.counter == 0);
  assert(cfg.output_len == 6);
  assert(cfg.output_base == NULL);
  assert(cfg.output_base_len == 0);
  assert(cfg.hash_function == R2FA_OTP_SHA_1);

  cfg.key = key;
  cfg.key_len = sizeof(key);

  ret = r2fa_hotp_generate(&cfg, code);
  assert(ret == 0);
  assert(strlen(code) == 6);
  assert(strncmp(code, "755224", 7) == 0);
}

void test_totp(void) {
  struct r2fa_totp_cfg cfg;
  char code[7], key[] = "12345678901234567890";
  int ret;

  ret = r2fa_totp_init(&cfg);
  assert(ret == 0);
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
  assert(ret == 0);
  assert(strlen(code) == 6);
}

void test_advanced_totp(void) {
  struct r2fa_totp_cfg cfg;
  char code[9], key[] = "12345678901234567890123456789012";
  int ret;

  ret = r2fa_totp_init(&cfg);
  assert(ret == 0);

  cfg.key = key;
  cfg.key_len = sizeof(key);
  cfg.timestamp = 1111111109;
  cfg.output_len = 8;
  cfg.hash_function = R2FA_OTP_SHA_256;

  ret = r2fa_totp_generate(&cfg, code);
  assert(ret == 0);
  assert(strlen(code) == 8);
  assert(strncmp(code, "68084774", 9) == 0);
}

int main(void) {
  test_hotp();
  test_totp();
  test_advanced_totp();
  return 0;
}
