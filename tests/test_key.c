/*
 * Copyright Rodolphe Breard (2018)
 * Author: Rodolphe Breard (2018)
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
#include <stdlib.h>
#include <string.h>
#include <libreauth.h>
#include "libreauth_tests.h"

#define KEY_SIZE 42

static uint32_t test_uniqueness(void) {
    test_name("key: test_uniqueness");

    char k1[KEY_SIZE + 1] = {0};
    char k2[KEY_SIZE + 1] = {0};

    int32_t r1 = libreauth_keygen(k1, KEY_SIZE);
    int32_t r2 = libreauth_keygen(k2, KEY_SIZE);

    assert(r1 == EXIT_SUCCESS);
    assert(r2 == EXIT_SUCCESS);
    assert(strncmp(k1, k2, KEY_SIZE) != 0);

    return 1;
}

static uint32_t test_null_ptr(void) {
    test_name("key: test_null_ptr");

    assert(libreauth_keygen(NULL, 42) != EXIT_SUCCESS);

    return 1;
}

static uint32_t test_zero_len(void) {
    test_name("key: test_zero_len");

    char k[KEY_SIZE + 1] = {0};
    assert(libreauth_keygen(k, 0) != EXIT_SUCCESS);

    return 1;
}

uint32_t test_key(void) {
    int nb_tests = 0;

    nb_tests += test_uniqueness();
    nb_tests += test_null_ptr();
    nb_tests += test_zero_len();

    return nb_tests;
}
