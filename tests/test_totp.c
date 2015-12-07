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


#include <strings.h>
#include <string.h>
#include <assert.h>
#include <libreauth.h>
#include "libreauth_tests.h"


static int test_basic_totp(void) {
  struct libreauth_totp_cfg cfg;
  char code[] = "qwerty", key[] = "12345678901234567890";
  int ret;

  test_name("totp: test_basic_totp");

  ret = libreauth_totp_init(&cfg);
  assert(ret == LIBREAUTH_OATH_SUCCESS);
  assert(cfg.key == NULL);
  assert(cfg.key_len == 0);
  assert(cfg.timestamp != 0);
  assert(cfg.period == 30);
  assert(cfg.initial_time == 0);
  assert(cfg.output_len == 6);
  assert(cfg.output_base == NULL);
  assert(cfg.output_base_len == 0);
  assert(cfg.hash_function == LIBREAUTH_OATH_SHA_1);

  cfg.key = key;
  cfg.key_len = sizeof(key);

  ret = libreauth_totp_generate(&cfg, code);
  assert(ret == LIBREAUTH_OATH_SUCCESS);
  assert(strlen(code) == 6);
  assert(!libreauth_totp_is_valid(NULL, "755224"));
  assert(!libreauth_totp_is_valid(&cfg, "4755224"));
  assert(!libreauth_totp_is_valid(&cfg, "!@#$%^"));
  assert(!libreauth_totp_is_valid(&cfg, ""));
  assert(!libreauth_totp_is_valid(&cfg, NULL));

  return 1;
}

static int test_advanced_totp(void) {
  struct libreauth_totp_cfg cfg;
  char code[9], key[] = "12345678901234567890123456789012";
  int ret;

  test_name("totp: test_advanced_totp");
  ret = libreauth_totp_init(&cfg);
  assert(ret == LIBREAUTH_OATH_SUCCESS);

  cfg.key = key;
  cfg.key_len = sizeof(key);
  cfg.timestamp = 1111111109;
  cfg.output_len = 8;
  cfg.hash_function = LIBREAUTH_OATH_SHA_256;

  ret = libreauth_totp_generate(&cfg, code);
  assert(ret == LIBREAUTH_OATH_SUCCESS);
  assert(strlen(code) == 8);
  assert(strncmp(code, "68084774", 9) == 0);

  assert(libreauth_totp_is_valid(&cfg, "68084774"));
  assert(!libreauth_totp_is_valid(NULL, "68084774"));
  assert(!libreauth_totp_is_valid(&cfg, "68084775"));
  assert(!libreauth_totp_is_valid(&cfg, "46808477"));
  assert(!libreauth_totp_is_valid(&cfg, "!@#$%^&*"));
  assert(!libreauth_totp_is_valid(&cfg, ""));
  assert(!libreauth_totp_is_valid(&cfg, NULL));

  return 1;
}

static int test_init_null_ptr(void) {
  int ret = libreauth_totp_init(NULL);
  test_name("totp: test_init_null_ptr");
  assert(ret == LIBREAUTH_OATH_CFG_NULL_PTR);
  return 1;
}

static int test_generate_null_ptr(void) {
  struct libreauth_totp_cfg cfg;
  char code[] = "qwerty", key[] = "12345678901234567890";
  int ret;

  test_name("totp: test_generate_null_ptr");
  libreauth_totp_init(&cfg);

  ret = libreauth_totp_generate(NULL, code);
  assert(ret == LIBREAUTH_OATH_CFG_NULL_PTR);
  assert(strcmp(code, "qwerty") == 0);

  ret = libreauth_totp_generate(&cfg, code);
  assert(ret == LIBREAUTH_OATH_KEY_NULL_PTR);

  cfg.key = key;

  ret = libreauth_totp_generate(&cfg, code);
  assert(ret == LIBREAUTH_OATH_INVALID_KEY_LEN);

  cfg.key_len = sizeof(key);

  ret = libreauth_totp_generate(&cfg, NULL);
  assert(ret == LIBREAUTH_OATH_CODE_NULL_PTR);

  ret = libreauth_totp_generate(&cfg, code);
  assert(ret == LIBREAUTH_OATH_SUCCESS);

  return 1;
}

static int test_invalid_base(void) {
  struct libreauth_totp_cfg cfg;
  char code[] = "qwerty", key[] = "12345678901234567890", base[] = "0123456789ABCDEF";
  int ret;

  test_name("totp: test_invalid_base");
  libreauth_totp_init(&cfg);

  cfg.key = key;
  cfg.key_len = sizeof(key);
  cfg.output_base = base;

  ret = libreauth_totp_generate(&cfg, code);
  assert(ret == LIBREAUTH_OATH_INVALID_BASE_LEN);
  cfg.output_base_len = 1;
  ret = libreauth_totp_generate(&cfg, code);
  assert(ret == LIBREAUTH_OATH_INVALID_BASE_LEN);

  cfg.output_base_len = sizeof(base);

  ret = libreauth_totp_generate(&cfg, code);
  assert(ret == LIBREAUTH_OATH_SUCCESS);

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
