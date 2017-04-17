/*
 * Copyright Rodolphe Breard (2015)
 * Author: Rodolphe Breard (2015)
 *
 * This software is a computer program whose purpose is to [describe
 * functionalities and technical features of your software].
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
 * OATH module
 */

typedef enum {
    LIBREAUTH_OATH_SHA_1   = 1,
    LIBREAUTH_OATH_SHA_256 = 2,
    LIBREAUTH_OATH_SHA_512 = 3
} libreauth_oath_hash_function;

typedef enum {
    LIBREAUTH_OATH_SUCCESS           = 0,

    LIBREAUTH_OATH_CFG_NULL_PTR      = 1,
    LIBREAUTH_OATH_CODE_NULL_PTR     = 2,
    LIBREAUTH_OATH_KEY_NULL_PTR      = 3,

    LIBREAUTH_OATH_INVALID_BASE_LEN  = 10,
    LIBREAUTH_OATH_INVALID_KEY_LEN   = 11,
    LIBREAUTH_OATH_CODE_TOO_SMALL    = 12,
    LIBREAUTH_OATH_CODE_TOO_BIG      = 13,

    LIBREAUTH_OATH_INVALID_KEY       = 20,
    LIBREAUTH_OATH_INVALID_PERIOD    = 21,

    LIBREAUTH_OATH_CODE_INVALID_UTF8 = 30
} libreauth_oath_errno;

/* HOTP */

struct libreauth_hotp_cfg {
    const void                   *key;
    size_t                        key_len;
    uint64_t                      counter;
    size_t                        output_len;
    const char                   *output_base;
    size_t                        output_base_len;
    libreauth_oath_hash_function  hash_function;
};

libreauth_oath_errno libreauth_hotp_init(struct libreauth_hotp_cfg *cfg);
libreauth_oath_errno libreauth_hotp_generate(const struct libreauth_hotp_cfg *cfg, char *code);
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
    size_t                        output_base_len;
    libreauth_oath_hash_function  hash_function;
};

libreauth_oath_errno libreauth_totp_init(struct libreauth_totp_cfg *cfg);
libreauth_oath_errno libreauth_totp_generate(const struct libreauth_totp_cfg *cfg, void *code);
int32_t              libreauth_totp_is_valid(const struct libreauth_totp_cfg *cfg, const void *code);
