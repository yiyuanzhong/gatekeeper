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

#include "user.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define GATEKEEPER_UID_INITIAL 81000
#define GATEKEEPER_UID_COUNT   10
#define GATEKEEPER_GID         81000

#define GATEKEEPER_UID_MINIMUM (GATEKEEPER_UID_INITIAL + 1)
#define GATEKEEPER_UID_MAXIMUM (GATEKEEPER_UID_INITIAL + GATEKEEPER_UID_COUNT)
#define GATEKEEPER_UID_INVALID (GATEKEEPER_UID_MAXIMUM + 1)

#define GATEKEEPER_USERNAME_PREFIX "app_"
#define GATEKEEPER_USERNAME_PRELEN 4
#define GATEKEEPER_USERNAME_LENGTH 9

#define GATEKEEPER_JAIL_PATH        "/bin/sh"

struct unode_t {
    struct unode_t *next;
    struct user_t *user;
    uint64_t h;
    uint64_t l;
};

struct hnode_t {
    struct hnode_t *next;
    uint64_t h;
    uint64_t l;
    void *pubkey;
    size_t publen;
    time_t timestamp;
    char host[INET6_ADDRSTRLEN];
};

static pthread_mutex_t g_mutex_user = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutex_host = PTHREAD_MUTEX_INITIALIZER;

static struct hnode_t *g_db_host_ptr    = NULL;
static struct unode_t *g_db_passwd_ptr  = NULL;
static struct unode_t *g_db_shadow_ptr  = NULL;
static struct unode_t *g_db_user_ptr    = NULL;

static int g_db_passwd_ref  = 0;
static int g_db_shadow_ref  = 0;
static int g_db_user_ref    = 0;

/* TODO(yiyuanzhong): just for fun, not for production codes. */
static const unsigned char kDemoPublicKey[] = {
    0x4E, 0xCB, 0x4A, 0x71, 0x0B, 0x76, 0x1B, 0xA1,
    0x9E, 0xE4, 0x95, 0x6B, 0x15, 0x3A, 0x9D, 0xD3,
    0x26, 0xE7, 0x09, 0x42, 0xEB, 0xC7, 0x1C, 0x02,
    0xFF, 0xD5, 0x7A, 0x0B, 0x44, 0x8B, 0x38, 0x8D,
    0x2E, 0x6D, 0xE9, 0x68, 0xC1, 0x49, 0x0E, 0x37,
    0xED, 0xC6, 0x6A, 0x9D, 0xD3, 0x46, 0xAE, 0xBF,
    0x3F, 0xE0, 0x89, 0xD5, 0x91, 0xA0, 0xF2, 0x01,
    0x65, 0x19, 0xAE, 0x45, 0x4B, 0x43, 0x86, 0x72,
    0xDD, 0xE9, 0xCB, 0x56, 0xE8, 0x6A, 0xA4, 0x72,
    0x7F, 0xE3, 0x2A, 0x48, 0x8A, 0xC1, 0x79, 0xC7,
    0x79, 0x01, 0x8F, 0x23, 0x72, 0x95, 0x74, 0xB4,
    0xC0, 0x52, 0x04, 0x9C, 0x16, 0x5A, 0xE9, 0xB5,
    0xB1, 0xAA, 0xB0, 0x2F, 0x18, 0x83, 0xD0, 0x05,
    0x9F, 0x11, 0x92, 0x1B, 0x11, 0xA5, 0xF8, 0x87,
    0x39, 0xE2, 0x9F, 0xAC, 0xD4, 0x7B, 0x0D, 0x08,
    0xEB, 0xF6, 0x01, 0xEA, 0x3A, 0x95, 0xD4, 0xB9,
    0x1D, 0xE7, 0x95, 0x94, 0x9D, 0xC8, 0xB2, 0xA0,
    0xFF, 0xE9, 0x83, 0xB0, 0x7B, 0x27, 0xEF, 0xEF,
    0x24, 0xEC, 0xA7, 0xC9, 0xBE, 0x46, 0x46, 0xB7,
    0xEB, 0x83, 0x04, 0x8C, 0x14, 0xB4, 0x9C, 0xF0,
    0xBA, 0x3D, 0x30, 0x45, 0x99, 0xE7, 0xAF, 0xC5,
};

static int user_is_super_user(void)
{
    int flags;
    int fd;

    flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = open("/etc/shadow", flags);
    if (fd < 0) {
        return 0;
    }

    close(fd);
    return 1;
}

static int user_do_close_database(void)
{
    struct unode_t *p;
    struct unode_t *q;

    for (p = g_db_user_ptr; p; p = q) {
        q = p->next;
        user_free(p->user);
        free(p);
    }

    g_db_user_ptr = NULL;
    return 0;
}

static int user_do_close_host(void)
{
    struct unode_t *p;
    struct unode_t *q;

    for (p = g_db_user_ptr; p; p = q) {
        q = p->next;
        free(p);
    }

    g_db_host_ptr = NULL;
    return 0;
}

__attribute__ ((destructor)) static void user_do_close_database_on_unload(void)
{
    pthread_mutex_lock(&g_mutex_user);
    user_do_close_database();
    pthread_mutex_unlock(&g_mutex_user);

    pthread_mutex_lock(&g_mutex_host);
    user_do_close_host();
    pthread_mutex_unlock(&g_mutex_host);

    pthread_mutex_destroy(&g_mutex_user);
    pthread_mutex_destroy(&g_mutex_host);
}

static int user_do_open_database(void)
{
    char buf[NAME_MAX];
    struct unode_t *m;
    struct unode_t *n;
    struct user_t *u;
    uid_t uid;

    assert(!g_db_user_ptr);

    /* TODO(yiyuanzhong): the real one.
     * Get all local user accounts from a daemon or a locked file.
     */

    m = NULL;
    for (uid = GATEKEEPER_UID_MINIMUM; uid <= GATEKEEPER_UID_MAXIMUM; ++uid) {
        if (user_get_username_by_uid(uid, buf, sizeof(buf))) {
            user_do_close_database();
            return -1;
        }

        n = (struct unode_t *)malloc(sizeof(*n));
        u = (struct user_t *)malloc(sizeof(*u));
        if (!n || !u) {
            user_do_close_database();
            user_free(u);
            free(n);
            return -1;
        }

        memset(u, 0, sizeof(*u));
        n->next = NULL;
        n->user = u;

        n->h            = 0xb922a62746eac276;
        n->l            = uid - GATEKEEPER_UID_MINIMUM;

        u->uid          = uid;
        u->gid          = GATEKEEPER_GID;
        u->home         = strdup("/home");
        u->shell        = strdup(GATEKEEPER_JAIL_PATH);
        u->service      = strdup("GATEKEEPER");
        u->username     = strdup(buf);

        if (!u->home || !u->shell || !u->service || !u->username) {
            user_do_close_database();
            user_free(u);
            free(n);
            return -1;
        }

        if (m) {
            m->next = n;
            m = m->next;
        } else {
            g_db_user_ptr = n;
            m = g_db_user_ptr;
        }
    }

    return 0;
}

static int user_open_database_nolock(void)
{
    if (!g_db_user_ref) {
        if (user_do_open_database()) {
            return -1;
        }
    }

    ++g_db_user_ref;
    return 0;
}

static int user_close_database_nolock(void)
{
    if (!g_db_user_ref) {
        return 0;
    }

    --g_db_user_ref;
    if (g_db_user_ref) {
        return 0;
    }

    return user_do_close_database();
}

static struct user_t *user_clone(const struct user_t *o)
{
    struct user_t *u;
    u = (struct user_t *)malloc(sizeof(*u));
    if (!u) {
        return NULL;
    }

    u->uid = o->uid;
    u->gid = o->gid;
    u->home = strdup(o->home);
    u->shell = strdup(o->shell);
    u->service = strdup(o->service);
    u->username = strdup(o->username);

    if (!u->home || !u->shell || !u->service || !u->username) {
        user_free(u);
        return NULL;
    }

    return u;
}

static struct user_t *user_get_user_by_uid_nolock(uid_t uid)
{
    struct unode_t *n;
    struct user_t *r;

    if (user_open_database_nolock()) {
        return NULL;
    }

    r = NULL;
    for (n = g_db_user_ptr; n; n = n->next) {
        if (n->user->uid == uid) {
            r = user_clone(n->user);
            break;
        }
    }

    if (user_close_database_nolock()) {
        user_free(r);
        return NULL;
    }

    return r;
}

static struct user_t *user_get_user_by_id_nolock(uint64_t h, uint64_t l)
{
    struct unode_t *n;
    struct user_t *r;

    if (user_open_database_nolock()) {
        return NULL;
    }

    r = NULL;
    for (n = g_db_user_ptr; n; n = n->next) {
        if (n->h == h && n->l == l) {
            r = user_clone(n->user);
            break;
        }
    }

    if (user_close_database_nolock()) {
        user_free(r);
        return NULL;
    }

    return r;
}

static struct user_t *user_get_next_user_nolock(struct unode_t **ptr)
{
    user_t *u;

    if (!*ptr) {
        return NULL;
    }

    u = (*ptr)->user;
    *ptr = (*ptr)->next;
    return user_clone(u);
}

static int user_open_userdb(struct unode_t **ptr, int *ref)
{
    pthread_mutex_lock(&g_mutex_user);
    if (*ref) {
        pthread_mutex_unlock(&g_mutex_user);
        return 0;
    }

    if (user_open_database_nolock()) {
        pthread_mutex_unlock(&g_mutex_user);
        return -1;
    }

    *ref = 1;
    *ptr = g_db_user_ptr;
    pthread_mutex_unlock(&g_mutex_user);
    return 0;
}

static int user_close_userdb(struct unode_t **ptr, int *ref)
{
    pthread_mutex_lock(&g_mutex_user);
    if (!*ref) {
        pthread_mutex_unlock(&g_mutex_user);
        return 0;
    }

    if (user_close_database_nolock()) {
        pthread_mutex_unlock(&g_mutex_user);
        return -1;
    }

    *ref = 0;
    *ptr = NULL;
    pthread_mutex_unlock(&g_mutex_user);
    return 0;
}

static struct user_t *user_get_next_userdb(struct unode_t **ptr)
{
    user_t *user;
    pthread_mutex_lock(&g_mutex_user);
    user = user_get_next_user_nolock(ptr);
    pthread_mutex_unlock(&g_mutex_user);
    return user;
}

int user_open_passwd(void)
{
    return user_open_userdb(&g_db_passwd_ptr, &g_db_passwd_ref);
}

int user_close_passwd(void)
{
    return user_close_userdb(&g_db_passwd_ptr, &g_db_passwd_ref);
}

struct user_t *user_get_next_passwd(void)
{
    return user_get_next_userdb(&g_db_passwd_ptr);
}

int user_open_shadow(void)
{
    if (!user_is_super_user()) {
        return -1;
    }

    return user_open_userdb(&g_db_shadow_ptr, &g_db_shadow_ref);
}

int user_close_shadow(void)
{
    return user_close_userdb(&g_db_shadow_ptr, &g_db_shadow_ref);
}

struct user_t *user_get_next_shadow(void)
{
    return user_get_next_userdb(&g_db_shadow_ptr);
}

struct user_t *user_get_user_by_uid(uid_t uid)
{
    if (!user_is_valid_uid(uid)) {
        return NULL;
    }

    user_t *user;
    pthread_mutex_lock(&g_mutex_user);
    user = user_get_user_by_uid_nolock(uid);
    pthread_mutex_unlock(&g_mutex_user);
    return user;
}

struct user_t *user_get_user_by_id(uint64_t h, uint64_t l)
{
    user_t *user;
    pthread_mutex_lock(&g_mutex_user);
    user = user_get_user_by_id_nolock(h, l);
    pthread_mutex_unlock(&g_mutex_user);
    return user;
}

struct user_t *user_get_user_by_username(const char *username)
{
    uid_t uid;

    uid = user_get_uid_by_username(username);
    if (!user_is_valid_uid(uid)) {
        return NULL;
    }

    return user_get_user_by_uid(uid);
}

void user_free(struct user_t *user)
{
    if (!user) {
        return;
    }

    free(user->username);
    free(user->service);
    free(user->shell);
    free(user->home);
    free(user);
}

int user_is_valid_username(const char *username)
{
    size_t len;

    if (strlen(username) != GATEKEEPER_USERNAME_LENGTH) {
        return 0;
    }

    if (memcmp(username,
               GATEKEEPER_USERNAME_PREFIX,
               GATEKEEPER_USERNAME_PRELEN)) {

        return 0;
    }

    for (len = GATEKEEPER_USERNAME_PRELEN;
         len < GATEKEEPER_USERNAME_LENGTH; ++len) {

        if (!isdigit(username[len])) {
            return 0;
        }
    }

    return 1;
}

int user_is_valid_uid(uid_t uid)
{
    if (uid < GATEKEEPER_UID_MINIMUM || uid > GATEKEEPER_UID_MAXIMUM) {
        return 0;
    }

    return 1;
}

int user_get_username_by_uid(uid_t uid, void *buffer, size_t length)
{
    int ret;

    ret = snprintf((char *)buffer, length, "%s%05u",
                   GATEKEEPER_USERNAME_PREFIX, uid);

    if (ret < 0 || (size_t)ret >= length) {
        return -1;
    }

    return 0;
}

uid_t user_get_uid_by_username(const char *username)
{
    unsigned long uid;
    char *endptr;

    if (!user_is_valid_username(username)) {
        return GATEKEEPER_UID_INVALID;
    }

    uid = strtoul(username + GATEKEEPER_USERNAME_PRELEN, &endptr, 10);
    if (*endptr || !user_is_valid_uid(uid)) {
        return GATEKEEPER_UID_INVALID;
    }

    return (uid_t)uid;
}

static int user_get_public_key_nolock(const char *remote_host, uint64_t h, uint64_t l,
                                      void *pubkey, size_t *publen)
{
    /* TODO(yiyuanzhong): the real one.
     * 1. Get expected host by id and validate that it matches the remote host.
     * 2. Get public key by host (keys belong to host, not service).
     */
    if (*publen < sizeof(kDemoPublicKey)) {
        return -1;
    }

    memcpy(pubkey, kDemoPublicKey, sizeof(kDemoPublicKey));
    *publen = sizeof(kDemoPublicKey);
    return 0;
}

int user_get_localhost_by_id(uint64_t h, uint64_t l, char *local, size_t locallen)
{
    /* TODO(yiyuanzhong): the real one.
     * Get expected host by id and validate that it's the localhost.
     */
    if (locallen < 4) {
        return -1;
    }

    memcpy(local, "::1", 4);
    return 0;
}

int user_get_public_key(const char *remote_host, uint64_t h, uint64_t l,
                        void *pubkey, size_t *publen)
{
    int ret;

    if (!remote_host || !*remote_host || !pubkey || !publen) {
        return -1;
    }

    pthread_mutex_lock(&g_mutex_host);
    ret = user_get_public_key_nolock(remote_host, h, l, pubkey, publen);
    pthread_mutex_unlock(&g_mutex_host);
    return ret;
}

int user_is_authorized(uint64_t fh, uint64_t fl, uint64_t th, uint64_t tl)
{
    /* TODO(yiyuanzhong): the real one.
     * Is remote requester <fh, fl> authorized to access local responder <th, tl>?
     */

    return 1;
}
