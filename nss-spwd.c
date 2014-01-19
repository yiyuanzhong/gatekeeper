/* Copyright 2014 yiyuanzhong@gmail.com (Yiyuan Zhong)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <nss.h>
#include <shadow.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "nss-common.h"
#include "user.h"

static int nss_fill_spwd(struct user_t *user,
                         struct spwd *pwd,
                         char *buffer,
                         size_t buflen)
{
    pwd->sp_lstchg  = 16071;
    pwd->sp_min     = 0;
    pwd->sp_max     = 99999;
    pwd->sp_warn    = 7;
    pwd->sp_inact   = -1;
    pwd->sp_expire  = -1;
    pwd->sp_flag    = -1;
    pwd->sp_pwdp    = nss_strdup("*",               &buffer, &buflen);
    pwd->sp_namp    = nss_strdup(user->username,    &buffer, &buflen);

    if (!pwd->sp_namp || !pwd->sp_pwdp) {
        return -1;
    }

    return 0;
}

NSS_METHOD(setspent)(int stayopen)
{
    if (user_open_shadow()) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

NSS_METHOD(endspent)(void)
{
    if (user_close_shadow()) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

NSS_METHOD(getspnam_r)(const char *name,
                       struct spwd *pwd,
                       char *buffer,
                       size_t buflen,
                       int *errnop)
{
    struct user_t *user;

    user = user_get_user_by_username(name);
    if (!user) {
        return NSS_STATUS_NOTFOUND;
    }

    if (nss_fill_spwd(user, pwd, buffer, buflen)) {
        user_free(user);
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    user_free(user);
    return NSS_STATUS_SUCCESS;
}

NSS_METHOD(getspent_r)(struct spwd *pwd,
                       char *buffer,
                       size_t buflen,
                       int *errnop)
{
    struct user_t *user;

    user = user_get_next_shadow();
    if (!user) {
        return NSS_STATUS_NOTFOUND;
    }

    if (nss_fill_spwd(user, pwd, buffer, buflen)) {
        user_free(user);
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    user_free(user);
    return NSS_STATUS_SUCCESS;
}
