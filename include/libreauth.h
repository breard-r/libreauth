/*
 * Copyright Rodolphe Breard (2015)
 * Author: Rodolphe Breard (2015)
 *
 * This software is a computer library whose purpose is to offer a
 * collection of tools for user authentication.
 *
 * This software is governed by the CeCILL  license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL license and that you accept its terms.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Hash module
 */

typedef enum {
    LIBREAUTH_HASH_SHA_1                = 1,
    LIBREAUTH_HASH_SHA_224              = 2,
    LIBREAUTH_HASH_SHA_256              = 3,
    LIBREAUTH_HASH_SHA_384              = 4,
    LIBREAUTH_HASH_SHA_512              = 5,
    LIBREAUTH_HASH_SHA_512_TRUNC_224    = 6,
    LIBREAUTH_HASH_SHA_512_TRUNC_256    = 7,
    LIBREAUTH_HASH_SHA_3_224            = 8,
    LIBREAUTH_HASH_SHA_3_256            = 9,
    LIBREAUTH_HASH_SHA_3_384            = 10,
    LIBREAUTH_HASH_SHA_3_512            = 11,
    LIBREAUTH_HASH_KECCAK_224           = 12,
    LIBREAUTH_HASH_KECCAK_256           = 13,
    LIBREAUTH_HASH_KECCAK_384           = 14,
    LIBREAUTH_HASH_KECCAK_512           = 15,
} libreauth_hash_function;


/*
 * Key generation module
 */

int32_t libreauth_keygen(void *buff, size_t buff_len);


/*
 * PASS module
 */

#define LIBREAUTH_PASSWORD_STORAGE_LEN  512

typedef enum {
    LIBREAUTH_PASS_ARGON2   = 0,
    LIBREAUTH_PASS_PBKDF2   = 1
} libreauth_pass_algo;

typedef enum {
    LIBREAUTH_PASS_SUCCESS                  = 0,
    LIBREAUTH_PASS_PASSWORD_TOO_SHORT       = 1,
    LIBREAUTH_PASS_PASSWORD_TOO_LONG        = 2,
    LIBREAUTH_PASS_INVALID_PASSWORD_FORMAT  = 10,
    LIBREAUTH_PASS_INCOMPATIBLE_OPTION      = 11,
    LIBREAUTH_PASS_NOT_ENOUGH_SPACE         = 20,
    LIBREAUTH_PASS_NULL_PTR                 = 12,
    LIBREAUTH_PASS_INVALID_KEY_LEN          = 22
} libreauth_pass_errno;

typedef enum {
    LIBREAUTH_PASS_BYTES        = 0,
    LIBREAUTH_PASS_CHARACTERS   = 1
} libreauth_pass_len_calc;

typedef enum {
    LIBREAUTH_PASS_NO_NORMALIZATION = 0,
    LIBREAUTH_PASS_NFD              = 1,
    LIBREAUTH_PASS_NFKD             = 2,
    LIBREAUTH_PASS_NFC              = 3,
    LIBREAUTH_PASS_NFKC             = 4,
} libreauth_pass_normalization;

typedef enum {
    LIBREAUTH_PASS_NOSTANDARD   = 0,
    LIBREAUTH_PASS_NIST80063B   = 1
} libreauth_pass_standard;

typedef enum {
    LIBREAUTH_PASS_XHMAC_NONE   = 0,
    LIBREAUTH_PASS_XHMAC_BEFORE = 1,
    LIBREAUTH_PASS_XHMAC_AFTER  = 2,
} libreauth_pass_xhmac;

struct libreauth_pass_cfg {
    size_t                          min_len;
    size_t                          max_len;
    size_t                          salt_len;
    libreauth_pass_algo             algorithm;
    libreauth_pass_len_calc         length_calculation;
    libreauth_pass_normalization    normalization;
    libreauth_pass_standard         standard;
    size_t                          version;
    libreauth_pass_xhmac            xhmac_type;
    libreauth_hash_function         xhmac_alg;
    const void                     *xhmac_key;
    size_t                          xhmac_key_len;
};

libreauth_pass_errno    libreauth_pass_init(struct libreauth_pass_cfg *cfg);
libreauth_pass_errno    libreauth_pass_init_std(struct libreauth_pass_cfg *cfg, libreauth_pass_standard std);
libreauth_pass_errno    libreauth_pass_init_from_phc(struct libreauth_pass_cfg *cfg, const char *phc);
libreauth_pass_errno    libreauth_pass_hash(const struct libreauth_pass_cfg *cfg, const char *pass, char *hash, size_t hash_len);
int32_t                 libreauth_pass_is_valid(const char *pass, const char *ref);
int32_t                 libreauth_pass_is_valid_xhmac(const char *pass, const char *ref, const void *key, size_t key_len);


/*
 * OATH module
 */

typedef enum {
    LIBREAUTH_OATH_SUCCESS           = 0,

    LIBREAUTH_OATH_NULL_PTR          = 1,
    LIBREAUTH_OATH_NOT_ENOUGH_SPACE  = 2,

    LIBREAUTH_OATH_INVALID_BASE_LEN  = 10,
    LIBREAUTH_OATH_INVALID_KEY_LEN   = 11,
    LIBREAUTH_OATH_CODE_TOO_SMALL    = 12,
    LIBREAUTH_OATH_CODE_TOO_BIG      = 13,

    LIBREAUTH_OATH_INVALID_KEY       = 20,
    LIBREAUTH_OATH_INVALID_PERIOD    = 21,

    LIBREAUTH_OATH_INVALID_UTF8      = 30
} libreauth_oath_errno;

/* HOTP */

struct libreauth_hotp_cfg {
    const void                   *key;
    size_t                        key_len;
    uint64_t                      counter;
    size_t                        output_len;
    const char                   *output_base;
    libreauth_hash_function  hash_function;
};

libreauth_oath_errno libreauth_hotp_init(struct libreauth_hotp_cfg *cfg);
libreauth_oath_errno libreauth_hotp_generate(const struct libreauth_hotp_cfg *cfg, char *code);
libreauth_oath_errno libreauth_hotp_get_uri(const struct libreauth_hotp_cfg *cfg, const char *issuer, const char *account_name, char *uri_buff, size_t uri_buff_len);
int32_t              libreauth_hotp_is_valid(const struct libreauth_hotp_cfg *cfg, const char *code);

/* TOTP */

struct libreauth_totp_cfg {
    const void                   *key;
    size_t                        key_len;
    int64_t                       timestamp;
    uint64_t                      positive_tolerance;
    uint64_t                      negative_tolerance;
    uint32_t                      period;
    uint64_t                      initial_time;
    size_t                        output_len;
    const void                   *output_base;
    libreauth_hash_function  hash_function;
};

libreauth_oath_errno libreauth_totp_init(struct libreauth_totp_cfg *cfg);
libreauth_oath_errno libreauth_totp_generate(const struct libreauth_totp_cfg *cfg, void *code);
libreauth_oath_errno libreauth_totp_get_uri(const struct libreauth_totp_cfg *cfg, const char *issuer, const char *account_name, char *uri_buff, size_t uri_buff_len);
int32_t              libreauth_totp_is_valid(const struct libreauth_totp_cfg *cfg, const void *code);
