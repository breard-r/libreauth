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

#ifndef R2FA_20150802_H
#define R2FA_20150802_H

#include <stddef.h>
#include <stdint.h>


/*
 * OTP module
 */

typedef enum {
  R2FA_OTP_SHA_1   = 1,
  R2FA_OTP_SHA_256 = 2,
  R2FA_OTP_SHA_512 = 3
} r2fa_otp_hash_function;

typedef enum {
  R2FA_OTP_SUCCESS           = 0,

  R2FA_OTP_CFG_NULL_PTR      = 1,
  R2FA_OTP_CODE_NULL_PTR     = 2,
  R2FA_OTP_KEY_NULL_PTR      = 3,

  R2FA_OTP_INVALID_BASE_LEN  = 10,
  R2FA_OTP_INVALID_KEY_LEN   = 11,
  R2FA_OTP_CODE_TOO_SMALL    = 12,
  R2FA_OTP_CODE_TOO_BIG      = 13,

  R2FA_OTP_INVALID_KEY       = 20,
  R2FA_OTP_INVALID_PERIOD    = 21,

  R2FA_OTP_CODE_INVALID_UTF8 = 30
} r2fa_otp_errno;

/* HOTP */

struct r2fa_hotp_cfg {
  const void            *key;
  size_t                 key_len;
  uint64_t               counter;
  size_t                 output_len;
  const char            *output_base;
  size_t                 output_base_len;
  r2fa_otp_hash_function hash_function;
};

r2fa_otp_errno r2fa_hotp_init(struct r2fa_hotp_cfg *cfg);
r2fa_otp_errno r2fa_hotp_generate(const struct r2fa_hotp_cfg *cfg, char *code);
int32_t        r2fa_hotp_is_valid(const struct r2fa_hotp_cfg *cfg, const char *code);

/* TOTP */

struct r2fa_totp_cfg {
  const void            *key;
  size_t                 key_len;
  int64_t                timestamp;
  uint32_t               period;
  uint64_t               initial_time;
  size_t                 output_len;
  const char            *output_base;
  size_t                 output_base_len;
  r2fa_otp_hash_function hash_function;
};

r2fa_otp_errno r2fa_totp_init(struct r2fa_totp_cfg *cfg);
r2fa_otp_errno r2fa_totp_generate(const struct r2fa_totp_cfg *cfg, char *code);
int32_t        r2fa_totp_is_valid(const struct r2fa_totp_cfg *cfg, const char *code);

#endif /* R2FA_20150802_H */
