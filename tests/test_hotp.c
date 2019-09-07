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


#include <strings.h>
#include <string.h>
#include <assert.h>
#include <libreauth.h>
#include "libreauth_tests.h"

#define DEFAULT_BUFF_LEN     6
#define DEFAULT_URI_BUFF_LEN 1024


static uint32_t test_basic_hotp(void) {
    test_name("hotp: test_basic_hotp");

    struct libreauth_hotp_cfg cfg;
    const char key[] = "12345678901234567890";
    char code[DEFAULT_BUFF_LEN + 1];

    uint32_t ret = libreauth_hotp_init(&cfg);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(cfg.key == NULL);
    assert(cfg.key_len == 0);
    assert(cfg.counter == 0);
    assert(cfg.output_len == DEFAULT_BUFF_LEN);
    assert(cfg.output_base == NULL);
    assert(cfg.hash_function == LIBREAUTH_HASH_SHA_1);

    cfg.key = key;
    cfg.key_len = strlen(key);

    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strlen(code) == DEFAULT_BUFF_LEN);
    assert(strncmp(code, "755224", DEFAULT_BUFF_LEN + 1) == 0);

    assert(libreauth_hotp_is_valid(&cfg, "755224"));
    assert(!libreauth_hotp_is_valid(NULL, "755224"));
    assert(!libreauth_hotp_is_valid(&cfg, "755225"));
    assert(!libreauth_hotp_is_valid(&cfg, "4755224"));
    assert(!libreauth_hotp_is_valid(&cfg, "!@#$%^"));
    assert(!libreauth_hotp_is_valid(&cfg, ""));
    assert(!libreauth_hotp_is_valid(&cfg, NULL));

    return 1;
}

static uint32_t test_basic_key_uri(void) {
    test_name("hotp: test_basic_key_uri");

    struct libreauth_hotp_cfg cfg;
    const char key[] = "12345678901234567890";
    char uri_buff[DEFAULT_URI_BUFF_LEN + 1];

    uint32_t ret = libreauth_hotp_init(&cfg);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    cfg.key = key;
    cfg.key_len = strlen(key);

    ret = libreauth_hotp_get_uri(&cfg, "Provider1", "alice@example.com", NULL, 42);
    assert(ret == LIBREAUTH_OATH_NULL_PTR);
    ret = libreauth_hotp_get_uri(&cfg, "Provider1", "alice@example.com", uri_buff, 5);
    assert(ret == LIBREAUTH_OATH_NOT_ENOUGH_SPACE);
    ret = libreauth_hotp_get_uri(&cfg, "Provider1", "alice@example.com", uri_buff, sizeof(uri_buff));
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strncmp(uri_buff, "otpauth://hotp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&counter=0", DEFAULT_URI_BUFF_LEN) == 0);

    return 1;
}

static uint32_t test_init_null_ptr(void) {
    test_name("hotp: test_init_null_ptr");

    uint32_t ret = libreauth_hotp_init(NULL);
    assert(ret == LIBREAUTH_OATH_NULL_PTR);

    return 1;
}

static uint32_t test_generate_null_ptr(void) {
    test_name("hotp: test_generate_null_ptr");

    struct libreauth_hotp_cfg cfg;
    const char key[] = "12345678901234567890";
    char code[] = "qwerty";
    uint32_t ret;

    libreauth_hotp_init(&cfg);

    ret = libreauth_hotp_generate(NULL, code);
    assert(ret == LIBREAUTH_OATH_NULL_PTR);
    assert(strcmp(code, "qwerty") == 0);

    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_NULL_PTR);

    cfg.key = key;

    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_INVALID_KEY_LEN);

    cfg.key_len = strlen(key);

    ret = libreauth_hotp_generate(&cfg, NULL);
    assert(ret == LIBREAUTH_OATH_NULL_PTR);

    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);

    return 1;
}

static uint32_t test_invalid_base(void) {
    test_name("hotp: test_invalid_base");

    struct libreauth_hotp_cfg cfg;
    const char key[] = "12345678901234567890", base[] = "0123456789ABCDEF";
    char code[DEFAULT_BUFF_LEN + 1];

    libreauth_hotp_init(&cfg);

    cfg.key = key;
    cfg.key_len = strlen(key);
    cfg.output_base = "";

    uint32_t ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_INVALID_BASE_LEN);

    cfg.output_base = base;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);

    return 1;
}

static uint32_t test_invalid_code(void) {
    test_name("hotp: test_invalid_code");

    struct libreauth_hotp_cfg cfg;
    const char key[] = "12345678901234567890",
          base10[] = "0123456789",
          base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
          base64[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
    char code[21]; /* Must be strictly superior than the highest code lentgh tested. */

    libreauth_hotp_init(&cfg);

    cfg.key = key;
    cfg.key_len = strlen(key);

    /* Base 10 */
    cfg.output_base = base10;

    cfg.output_len = 5;
    uint32_t ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_CODE_TOO_SMALL);

    cfg.output_len = 6;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strlen(code) == 6);

    cfg.output_len = 9;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strlen(code) == 9);

    cfg.output_len = 10;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_CODE_TOO_BIG);

    cfg.output_len = 0xffffff;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_CODE_TOO_BIG);

    /* Base 32 */
    cfg.output_base = base32;

    cfg.output_len = 3;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_CODE_TOO_SMALL);

    cfg.output_len = 4;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strlen(code) == 4);

    cfg.output_len = 6;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strlen(code) == 6);

    cfg.output_len = 7;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_CODE_TOO_BIG);

    cfg.output_len = 0xffffff;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_CODE_TOO_BIG);

    /* Base 64 */
    cfg.output_base = base64;

    cfg.output_len = 3;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_CODE_TOO_SMALL);

    cfg.output_len = 4;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strlen(code) == 4);

    cfg.output_len = 5;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strlen(code) == 5);

    cfg.output_len = 6;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_CODE_TOO_BIG);

    cfg.output_len = 0xffffff;
    ret = libreauth_hotp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_CODE_TOO_BIG);

    return 1;
}

uint32_t test_hotp(void) {
    uint32_t nb_tests = 0;

    nb_tests += test_basic_hotp();
    nb_tests += test_basic_key_uri();
    nb_tests += test_init_null_ptr();
    nb_tests += test_generate_null_ptr();
    nb_tests += test_invalid_base();
    nb_tests += test_invalid_code();

    return nb_tests;
}
