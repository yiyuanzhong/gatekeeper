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
#include <pwd.h>
#include <string.h>
#include <unistd.h>

#include "login.h"
#include "nss-common.h"
#include "user.h"

static int nss_fill_passwd(struct user_t *user,
                           struct passwd *pwd,
                           char *buffer,
                           size_t buflen)
{
    pwd->pw_uid     = user->uid;
    pwd->pw_gid     = user->gid;
    pwd->pw_passwd  = nss_strdup("x",               &buffer, &buflen);
    pwd->pw_name    = nss_strdup(user->username,    &buffer, &buflen);
    pwd->pw_gecos   = nss_strdup(user->service,     &buffer, &buflen);
    pwd->pw_dir     = nss_strdup(user->home,        &buffer, &buflen);
    pwd->pw_shell   = nss_strdup(user->shell,       &buffer, &buflen);

    if (!pwd->pw_name   ||
        !pwd->pw_passwd ||
        !pwd->pw_gecos  ||
        !pwd->pw_dir    ||
        !pwd->pw_shell  ){

        return -1;
    }

    return 0;
}

static enum nss_status nss_return_user(struct user_t *user,
                                       struct passwd *pwd,
                                       char *buffer,
                                       size_t buflen,
                                       int *errnop)
{
    if (!user) {
        return NSS_STATUS_NOTFOUND;
    }

    if (nss_fill_passwd(user, pwd, buffer, buflen)) {
        user_free(user);
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    user_free(user);
    return NSS_STATUS_SUCCESS;
}

NSS_METHOD(setpwent)(int stayopen)
{
    if (user_open_passwd()) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

NSS_METHOD(endpwent)(void)
{
    if (user_close_passwd()) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

NSS_METHOD(getpwnam_r)(const char *name,
                       struct passwd *pwd,
                       char *buffer,
                       size_t buflen,
                       int *errnop)
{
    struct user_t *user;

    user = NULL;
    if (login_is_valid_loginname(name)) {
        user = login_get_user_by_loginname(name);
    } else if (user_is_valid_username(name)) {
        user = user_get_user_by_username(name);
    }

    return nss_return_user(user, pwd, buffer, buflen, errnop);
}

NSS_METHOD(getpwuid_r)(uid_t uid,
                       struct passwd *pwd,
                       char *buffer,
                       size_t buflen,
                       int *errnop)
{
    struct user_t *user;
    user = user_get_user_by_uid(uid);
    return nss_return_user(user, pwd, buffer, buflen, errnop);
}

NSS_METHOD(getpwent_r)(struct passwd *pwd,
                       char *buffer,
                       size_t buflen,
                       int *errnop)
{
    struct user_t *user;
    user = user_get_next_passwd();
    return nss_return_user(user, pwd, buffer, buflen, errnop);
}
