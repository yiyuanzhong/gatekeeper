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

#ifndef __GATEKEEPER_USER_H__
#define __GATEKEEPER_USER_H__

#include <sys/types.h>
#include <limits.h>
#include <stdint.h>

typedef struct user_t {
    uid_t uid;
    gid_t gid;
    char *home;
    char *shell;
    char *service;
    char *username;
} user_t;

extern int user_open_passwd(void);
extern int user_close_passwd(void);
extern struct user_t *user_get_next_passwd(void);

extern int user_open_shadow(void);
extern int user_close_shadow(void);
extern struct user_t *user_get_next_shadow(void);

extern struct user_t *user_get_user_by_username(const char *username);
extern struct user_t *user_get_user_by_id(uint64_t h, uint64_t l);
extern struct user_t *user_get_user_by_uid(uid_t uid);
extern void user_free(struct user_t *user);

extern int user_get_username_by_uid(uid_t uid, void *buffer, size_t length);
extern uid_t user_get_uid_by_username(const char *username);

/** @return bool */
extern int user_is_valid_username(const char *username);

/** @return bool */
extern int user_is_valid_uid(uid_t uid);

/* publen must be valid before calling, and set properly upon return. */
extern int user_get_public_key(const char *remote_host, uint64_t h, uint64_t l,
                               void *pubkey, size_t *publen);

extern int user_get_localhost_by_id(uint64_t h, uint64_t l, char *local, size_t locallen);

/** @return bool */
extern int user_is_authorized(uint64_t fh, uint64_t fl, uint64_t th, uint64_t tl);

#endif /* __GATEKEEPER_USER_H__ */
