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

#include "login.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <byteswap.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"
#include "user.h"

#define GATEKEEPER_LOGINNAME_PREFIX "g_"
#define GATEKEEPER_LOGINNAME_PRELEN 2
#define GATEKEEPER_LOGINNAME_LENGTH 30
#define GATEKEEPER_LOGINPASS_LENGTH 72

#define GATEKEEPER_TIMESTAMP_NOT_BEFORE      -5000000000ll  /* 5s   */
#define GATEKEEPER_TIMESTAMP_NOT_AFTER      120000000000ll  /* 2min */

#pragma pack(push, 1)
typedef struct login_id_t {
#if WORDS_BIGENDIAN
    uint64_t h;             /*   0:63 , target user id, high part   */
    uint64_t l;             /*  64:127, target user id, low part    */
#else
    uint64_t l;             /*   0:63 , target user id, low part    */
    uint64_t h;             /*  64:127, target user id, high part   */
#endif
    uint16_t f;             /* 128:143, flags, reserved, expect 0   */
} login_id_t;

typedef struct login_pass_t {
#if WORDS_BIGENDIAN
    uint64_t h;             /*   0:63 , source user id, high part   */
    uint64_t l;             /*  64:127, source user id, low part    */
#else
    uint64_t l;             /*   0:63 , source user id, low part    */
    uint64_t h;             /*  64:127, source user id, high part   */
#endif
    uint64_t t;             /* 128:191, nanoseconds from epoch      */
    unsigned char s[32];    /* 192:447, signature                   */
    uint16_t r;             /* 448:463, random padding              */
} login_pass_t;

typedef struct login_sign_t {
    char local[64];
    char remote[64];
    struct login_id_t id;
    struct login_pass_t pass;
} login_sign_t;
#pragma pack(pop)

typedef int __compile_assert_id  [sizeof(login_id_t)   == 18 ? 1 : -1];
typedef int __compile_assert_pass[sizeof(login_pass_t) == 58 ? 1 : -1];

static int login_normalize_remote_host(const char *remote_host, char *host, size_t len)
{
    struct sockaddr_in6 *inp6;
    struct sockaddr_in *inp4;
    struct addrinfo *res;
    int result;

    if (getaddrinfo(remote_host, NULL, NULL, &res)) {
        return -1;
    }

    if (!res || !res->ai_addr) {
        freeaddrinfo(res);
        return -1;
    }

    /* Should be only one unless remote_host is a hostname, then the first one. */
    result = -1;
    if (res->ai_family == AF_INET6) {
        inp6 = (struct sockaddr_in6 *)res->ai_addr;
        if (inet_ntop(inp6->sin6_family, &inp6->sin6_addr, host, (socklen_t)len)) {
            result = 0;
        }

    } else if (res->ai_family == AF_INET) {
        inp4 = (struct sockaddr_in *)res->ai_addr;
        if (inet_ntop(inp4->sin_family, &inp4->sin_addr, host, (socklen_t)len)) {
            result = 0;
        }
    }

    freeaddrinfo(res);
    return result;
}

static int login_get_id_from_loginname_decode_only(const char *loginname,
                                                   login_id_t *id)
{
    char lowname[GATEKEEPER_LOGINNAME_LENGTH];
    int i;

    if (!login_is_valid_loginname(loginname)) {
        return -1;
    }

    for (i = GATEKEEPER_LOGINNAME_PRELEN; i < GATEKEEPER_LOGINNAME_LENGTH; ++i) {
        lowname[i] = tolower(loginname[i]);
    }

    if (crypto_base36_decode(lowname + GATEKEEPER_LOGINNAME_PRELEN,
                             GATEKEEPER_LOGINNAME_LENGTH - GATEKEEPER_LOGINNAME_PRELEN,
                             id, sizeof(*id))) {

        return -1;
    }

    /* TODO(yiyuanzhong): this field is reserved now and must be 0. */
    if (id->f) {
        return -1;
    }

    return 0;
}

static void login_swap_login_id_t(login_id_t *id)
{
#if WORDS_BIGENDIAN
    id->l = bswap_64(id->l);
    id->h = bswap_64(id->h);
    id->f = bswap_16(id->f);
    id->l ^= id->h;
    id->h ^= id->l;
    id->l ^= id->h;
#endif
}

static void login_swap_login_pass_t(login_pass_t *pass)
{
#if WORDS_BIGENDIAN
    pass->l = bswap_64(pass->l);
    pass->h = bswap_64(pass->h);
    pass->l ^= pass->h;
    pass->h ^= pass->l;
    pass->l ^= pass->h;

    pass->t = bswap_64(pass->t);
    pass->r = bswap_16(pass->r);
#endif
}

static int login_get_id_from_loginname(const char *loginname, login_id_t *id)
{
    if (login_get_id_from_loginname_decode_only(loginname, id)) {
        return -1;
    }

    login_swap_login_id_t(id);
    return 0;
}

static int login_get_pass_from_loginpass_decode_only(const char *loginpass,
                                                     login_pass_t *pass)
{
    if (!login_is_valid_loginpass(loginpass)) {
        return -1;
    }

    if (crypto_base88_decode(loginpass, GATEKEEPER_LOGINPASS_LENGTH,
                             pass, sizeof(*pass))) {

        return -1;
    }

    return 0;
}

int login_is_valid_loginpass(const char *loginpass)
{
    if (strlen(loginpass) != GATEKEEPER_LOGINPASS_LENGTH) {
        return 0;
    }

    return 1;
}

int login_is_valid_loginname(const char *loginname)
{
    if (strlen(loginname) != GATEKEEPER_LOGINNAME_LENGTH) {
        return 0;
    }

    if (memcmp(loginname,
               GATEKEEPER_LOGINNAME_PREFIX,
               GATEKEEPER_LOGINNAME_PRELEN)) {

        return 0;
    }

    return 1;
}

struct user_t *login_get_user_by_loginname(const char *loginname)
{
    login_id_t id;
    if (login_get_id_from_loginname(loginname, &id)) {
        return NULL;
    }

    return user_get_user_by_id(id.h, id.l);
}

static int64_t login_get_timestamp(void)
{
    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp)) {
        return -1;
    }

    return (int64_t)tp.tv_sec * 1000000000 + (int64_t)tp.tv_nsec;
}

static int login_is_within_time_period(uint64_t timestamp)
{
    int64_t now;

    if ((int64_t)timestamp < 0) { /* overflow */
        return 0;
    }

    now = login_get_timestamp();
    if (now < 0) { /* The hell? */
        return 0;
    }

    now -= (int64_t)timestamp;
    if (now >= GATEKEEPER_TIMESTAMP_NOT_AFTER  ||
        now <= GATEKEEPER_TIMESTAMP_NOT_BEFORE ){

        return 0;
    }

    return 1;
}

struct user_t *login_with_credentials(const char *loginname,
                                      const char *loginpass,
                                      const char *remote_host)
{
    unsigned char pubkey[512];
    struct user_t *user;
    size_t publen;

    char remote[INET6_ADDRSTRLEN];
    char local[INET6_ADDRSTRLEN];
    login_sign_t sign;
    login_pass_t pass;
    login_id_t id;

    if (login_get_id_from_loginname_decode_only(loginname, &id)) {
        return NULL;
    }

    if (login_get_pass_from_loginpass_decode_only(loginpass, &pass)) {
        return NULL;
    }

    memset(&sign, 0, sizeof(sign));
    memcpy(&sign.id, &id, sizeof(id));
    memcpy(&sign.pass, &pass, sizeof(pass));
    memset(sign.pass.s, 0, sizeof(sign.pass.s));

    /* Swap after I've copied id and pass into sign as it's the wire format. */
    login_swap_login_id_t(&id);
    login_swap_login_pass_t(&pass);

    /* Not really necessary but what if SA didn't set 'UseDNS no' in sshd? */
    if (login_normalize_remote_host(remote_host, remote, sizeof(remote))) {
        return NULL;
    }

    /* How did he find me? Use the same way to get my remote access address. */
    if (user_get_localhost_by_id(id.h, id.l, local, sizeof(local))) {
        return NULL;
    }

    /* Remember that I see the opposite direction as the initiator. */
    memcpy(sign.remote, local, strlen(local));
    memcpy(sign.local, remote, strlen(remote));

    /* By having matching public key, <fh, fl> is really scheduled on <remote>. */
    publen = sizeof(pubkey);
    if (user_get_public_key(remote, pass.h, pass.l, pubkey, &publen)) {
        syslog(LOG_AUTHPRIV | LOG_INFO,
               "gatekeeper: failed to find legitimate public key from [%s]", remote);

        return NULL;
    }

    if (crypto_verify(&sign, sizeof(sign), pass.s, sizeof(pass.s), pubkey, publen)) {
        syslog(LOG_AUTHPRIV | LOG_INFO, "gatekeeper: invalid signature from %s", remote);
        return NULL;
    }

    if (!login_is_within_time_period(pass.t)) {
        syslog(LOG_AUTHPRIV | LOG_INFO, "gatekeeper: replay attack from %s", remote);
        return NULL;
    }

    /* TODO(yiyuanzhong): is it a replay or abuse? */

    /* Do I have a local user identified by <id.h, id.l>? */
    user = user_get_user_by_id(id.h, id.l);
    if (!user) { /* Shouldn't be since I just looked up the localhost from id. */
        return NULL;
    }

    /* This is the authenticating stage, why do I do authorization here? Ask PAM. */
    if (!user_is_authorized(pass.h, pass.l, id.h, id.l)) {
        user_free(user);
        return NULL;
    }

    /*
     * What have I done?
     * 1. The request is genuine. (cryptography verified, remote root trusted)
     * 2. The request is made by service <fh, fl> on <remote>. (have matching pubkey)
     * 3. The request is for <th, tl> on <local>. (having local user)
     * 4. The request is not a replay. (created recently and not obviously abusing)
     * 5. <fh, fl> is authorized to access <th, tl>.
     * So, I hereby give the permission.
     */
    return user;
}

static uint16_t login_get_random_number(void)
{
    uint16_t result;
    ssize_t ret;
    ssize_t r;
    int fd;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        do {
            ret = read(fd, &result, sizeof(result));
        } while (ret < 0 && errno == EINTR);

        do {
            r = close(fd);
        } while (r < 0 && errno == EINTR);

        if (ret == sizeof(uint16_t)) {
            return result;
        }
    }

    return (uint16_t)rand();
}

int login_demo_generate_credentials(uint64_t fh, uint64_t fl, const char *fa,
                                    uint64_t th, uint64_t tl, const char *ta,
                                    uint16_t flags,
                                    char *loginname, size_t namelen,
                                    char *loginpass, size_t passlen)
{
    /* TODO(yiyuanzhong): just for fun, not for production codes. */
    static const unsigned char kDemoPrivateKey[] = {
        0x43, 0x5D, 0x51, 0xD1, 0xC2, 0xC5, 0x16, 0x18,
        0xD0, 0x75, 0x62, 0x8C, 0xBB, 0x31, 0x4E, 0x2C,
        0x37, 0x00, 0x11, 0x19, 0xA0, 0x39, 0x37, 0xC7,
        0x97, 0x83, 0xEA, 0x08,
    };

    login_sign_t sign;
    int r;

    /* TODO(yiyuanzhong): this field is reserved now and must be 0. */
    if (flags) {
        return -1;
    }

    if (namelen < GATEKEEPER_LOGINNAME_LENGTH + 1 ||
        passlen < GATEKEEPER_LOGINPASS_LENGTH + 1 ){

        return -1;
    }

    memset(&sign, 0, sizeof(sign));
    sign.id.h = th;
    sign.id.l = tl;
    sign.id.f = flags;
    sign.pass.h = fh;
    sign.pass.l = fl;
    sign.pass.t = login_get_timestamp();
    sign.pass.r = login_get_random_number();
    snprintf(sign.local, sizeof(sign.local), "%s", fa);
    snprintf(sign.remote, sizeof(sign.remote), "%s", ta);

    r = crypto_sign(&sign, sizeof(sign),
                    sign.pass.s, sizeof(sign.pass.s),
                    kDemoPrivateKey, sizeof(kDemoPrivateKey));

    if (r < 0) {
        return -1;
    }

    memcpy(loginname, GATEKEEPER_LOGINNAME_PREFIX, GATEKEEPER_LOGINNAME_PRELEN);
    if (crypto_base36_encode(&sign.id, sizeof(sign.id),
                             loginname + GATEKEEPER_LOGINNAME_PRELEN,
                             GATEKEEPER_LOGINNAME_LENGTH - GATEKEEPER_LOGINNAME_PRELEN)) {

        return -1;
    }

    if (crypto_base88_encode(&sign.pass, sizeof(sign.pass),
                             loginpass, GATEKEEPER_LOGINPASS_LENGTH)) {

        return -1;
    }

    loginname[GATEKEEPER_LOGINNAME_LENGTH] = '\0';
    loginpass[GATEKEEPER_LOGINPASS_LENGTH] = '\0';
    return 0;
}
