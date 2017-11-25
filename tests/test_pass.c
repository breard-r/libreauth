/*
 * Copyright Rodolphe Breard (2016)
 * Author: Rodolphe Breard (<year>)
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


#include <assert.h>
#include <libreauth.h>
#include "libreauth_tests.h"


static uint32_t test_valid_pass(void) {
    test_name("pass: test_valid_pass");

    const char password[] = "correct horse battery staple",
          invalid_pass[] = "123456";
    uint8_t storage[LIBREAUTH_PASSWORD_STORAGE_LEN];

    uint32_t ret = libreauth_password_hash(password, storage, LIBREAUTH_PASSWORD_STORAGE_LEN);
    assert(ret == LIBREAUTH_PASS_SUCCESS);
    assert(libreauth_password_is_valid(password, storage));
    assert(!libreauth_password_is_valid(invalid_pass, storage));

    return 1;
}

static uint32_t test_nist_pass(void) {
    test_name("pass: test_nist_pass");

    const char password[] = "correct horse battery staple",
          invalid_pass[] = "123456";
    uint8_t storage[LIBREAUTH_PASSWORD_STORAGE_LEN];

    uint32_t ret = libreauth_password_hash_standard(password, storage, LIBREAUTH_PASSWORD_STORAGE_LEN, LIBREAUTH_PASS_NIST80063B);
    assert(ret == LIBREAUTH_PASS_SUCCESS);
    assert(libreauth_password_is_valid(password, storage));
    assert(!libreauth_password_is_valid(invalid_pass, storage));

    return 1;
}

static uint32_t test_invalid_pass(void) {
    test_name("pass: test_invalid_pass");

    const char password[] = "invalid password",
          reference[] = "$pbkdf2$hash=sha256,iter=21000$RSF4Aw$pgenLCySNXpFaLmYxfcI+AHwsf+66iBTV+COTTJYMMk";
    assert(!libreauth_password_is_valid(password, reference));

    return 1;
}

uint32_t test_pass(void) {
    int nb_tests = 0;

    nb_tests += test_valid_pass();
    nb_tests += test_nist_pass();
    nb_tests += test_invalid_pass();

    return nb_tests;
}
