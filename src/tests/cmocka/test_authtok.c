/*
    SSSD

    authtok - Utilities tests

    Authors:
        Pallavi Jha <pallavikumarijha@gmail.com>

    Copyright (C) 2013 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

#include "util/authtok.h"


struct test_state
{
    struct sss_auth_token *authtoken;
};

static void setup(void **state)
{
    struct test_state *ts = NULL;

    ts = talloc(NULL, struct test_state);
    assert_non_null(ts);

    ts->authtoken = sss_authtok_new(ts);
    assert_non_null(ts->authtoken);

    *state = (void *)ts;
}

static void teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    talloc_free(ts);
}

static void test_sss_authtok_new(void **state)
{
    TALLOC_CTX *mem_ctx;
    struct sss_auth_token *authtoken;

    mem_ctx = talloc_new(NULL);
    if (mem_ctx == NULL) {
        return ENOMEM;
    }

    authtoken = sss_authtok_new(mem_ctx);
    assert_non_null(authtoken);

    talloc_free(mem_ctx);
}

static void test_sss_authtok_set(void **state)
{
    size_t len;
    errno_t ret;
    uint8_t *data;
    enum sss_authtok_type type;

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
 
    data = strdup("password");
    len = strlen(data) + 1;

    /* Test when type has value SSS_AUTHTOK_TYPE_PASSWORD */
    type = SSS_AUTHTOK_TYPE_PASSWORD;
    ret = sss_authtok_set(ts->authtoken, type, data, len);

    assert_int_equal(ret, EOK);

    ret = sss_authtok_set(ts->authtoken, type, data, 0);
    assert_int_equal(ret, EOK);

    /*ret = sss_authtok_set(ts->authtoken, type, '\0', 0);
    assert_int_not_equal(ret, EINVAL);*/

 

    /* Test when type has value SSS_AUTHTOK_TYPE_CCFILE */
    type = SSS_AUTHTOK_TYPE_PASSWORD;
    ret = sss_authtok_set(ts->authtoken, type, data, len);

    assert_int_equal(ret, EOK);

    ret = sss_authtok_set(ts->authtoken, type, data, 0);
    assert_int_equal(ret, EOK);

    /*ret = sss_authtok_set(ts->authtoken, type, '\0', 0);
    assert_int_equal(ret, EINVAL);*/

    /* Test when type has value SSS_AUTHTOK_TYPE_EMPTY*/
    type = SSS_AUTHTOK_TYPE_EMPTY;
    ret = sss_authtok_set(ts->authtoken, type, data, len);

    assert_int_equal(ret, EOK);

    ret = sss_authtok_set(ts->authtoken, type, '\0', 0);
    assert_int_equal(ret, EOK);

    /* Test when authtoken is NULL */
    //ret = sss_authtok_set(NULL, type, data, len);
    //assert_int_equal(ret, EINVAL);
}

/* @test_authtok : tests following functions -
 * sss_authtok_get_type
 * sss_authtok_get_size
 * sss_authtok_get_data
 * sss_authtok_get_password
 * sss_authtok_get_ccfile
 */
static void test_sss_authtok(void **state)
{
    size_t len;
    errno_t ret;
    uint8_t *data;
    enum sss_authtok_type type;

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);

    data = strdup("password");
    len = strlen(data) + 1;
 
 
    /* Test with NULL authtoken */
    /*type = SSS_AUTHTOK_TYPE_PASSWORD;
    ret = sss_authtok_set(NULL, type, data, len);

    assert_int_equal(ret, EINVAL);
    assert_int_equal(EINVAL, sss_authtok_get_type(NULL));
    assert_int_equal(EINVAL, sss_authtok_get_size(ts->authtoken));
    assert_string_equal(EINVAL, sss_authtok_get_data(ts->authtoken));
    */

    /* test when type is SSS_AUTHTOK_TYPE_PASSWORD */
    type = SSS_AUTHTOK_TYPE_PASSWORD;
    ret = sss_authtok_set(ts->authtoken, type, data, len);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(len, sss_authtok_get_size(ts->authtoken));
    assert_string_equal(data, sss_authtok_get_data(ts->authtoken));

    size_t *ret_len = (size_t *)malloc(sizeof(size_t *));
    const char **pwd = (const char **)malloc(sizeof(const char **));

    ret = sss_authtok_get_password(ts->authtoken, pwd, ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(data, *pwd);
    assert_int_equal(len - 1, *ret_len);

    ret = sss_authtok_get_ccfile(ts->authtoken, pwd, ret_len);
    assert_int_equal(ret, EACCES);

    /* test when type is SSS_AUTHTOK_TYPE_CCFILE */
    type = SSS_AUTHTOK_TYPE_CCFILE;
    ret = sss_authtok_set(ts->authtoken, type, data, len);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(len, sss_authtok_get_size(ts->authtoken));
    assert_string_equal(data, sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_get_password(ts->authtoken, pwd, ret_len);
 
    assert_int_equal(ret, EACCES);

    ret = sss_authtok_get_ccfile(ts->authtoken, pwd, ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(data, *pwd);
    assert_int_equal(len - 1, *ret_len);

    /* test when type is SSS_AUTHTOK_TYPE_EMPTY */
    type = SSS_AUTHTOK_TYPE_EMPTY;
    ret = sss_authtok_set(ts->authtoken, type, data, len);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(0, sss_authtok_get_size(ts->authtoken));
    assert_null(sss_authtok_get_data(ts->authtoken));
 
    ret = sss_authtok_get_password(ts->authtoken, pwd, ret_len);

    assert_int_equal(ret, ENOENT);

    ret = sss_authtok_get_ccfile(ts->authtoken, pwd, ret_len);

    assert_int_equal(ret, ENOENT);

    free(pwd);
    free(ret_len);
}

static void test_sss_authtok_wipe_password(void **state)
{
    size_t len;
    errno_t ret;
    uint8_t *data;
    enum sss_authtok_type type;
 
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
 
    data = strdup("password");
    len = strlen(data) + 1;
    type = SSS_AUTHTOK_TYPE_PASSWORD;

    /* Test with NULL authtoken */
    /*ret = sss_wipe_password(NULL);

    assert_int_equal(ret, EINVAL);
    */

    ret = sss_authtok_set(ts->authtoken, type, data, len);

    assert_int_equal(ret, EOK);

    sss_authtok_wipe_password(ts->authtoken);

    size_t *ret_len = malloc(sizeof(size_t));
    const char **pwd = malloc(sizeof(const char));

    ret = sss_authtok_get_password(ts->authtoken, pwd, ret_len);
 
    assert_int_equal(ret, EOK);
    assert_string_equal(*pwd, "");
    assert_int_equal(len - 1, *ret_len);

    free(ret_len);
    free(pwd);
}

static void test_sss_authtok_copy(void **state)
{
    size_t len;
    errno_t ret;
    uint8_t *data;
    enum sss_authtok_type type;
 
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
 
    TALLOC_CTX *mem_ctx;
    struct sss_auth_token *dest_authtoken;

    mem_ctx = talloc_new(NULL);
    if (mem_ctx == NULL) {
        return ENOMEM;
    }

    dest_authtoken = sss_authtok_new(mem_ctx);
    assert_non_null(dest_authtoken);

    data = strdup("password");
    len = strlen(data) + 1;
    type = SSS_AUTHTOK_TYPE_EMPTY;
    ret = sss_authtok_set(ts->authtoken, type, data, len);

    assert_int_equal(ret, EOK);
    assert_int_equal(EOK, sss_authtok_copy(ts->authtoken, dest_authtoken));

    type = SSS_AUTHTOK_TYPE_PASSWORD;
    ret = sss_authtok_set(ts->authtoken, type, data, len);

    assert_int_equal(ret, EOK);

    ret = sss_authtok_copy(ts->authtoken, dest_authtoken);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(dest_authtoken));
    assert_string_equal(data, sss_authtok_get_data(dest_authtoken));
    assert_int_equal(len, sss_authtok_get_size(dest_authtoken));

    talloc_free(mem_ctx);
}

int main(void)
{
    const UnitTest tests[] = {
        unit_test(test_sss_authtok_new),
        unit_test_setup_teardown(test_sss_authtok_set, setup, teardown),
        unit_test_setup_teardown(test_sss_authtok, setup, teardown),
        unit_test_setup_teardown(test_sss_authtok_wipe_password, setup,
                                 teardown),
        unit_test_setup_teardown(test_sss_authtok_copy, setup, teardown)
    };

    return run_tests(tests);
}
