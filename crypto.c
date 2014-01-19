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

#include "crypto.h"

#include <openssl/sha.h>
#include <pbc/pbc.h>
#include <gmp.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "config.h"

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Alphabet and digits. */
static const unsigned char BASE36_TABLE[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
};

/* Printable ASCII (95 of them) without SPACE ! ' " $ ` \ */
/* Safe to type encoded string in shell even when double quoted. */
static const unsigned char BASE88_TABLE[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
    's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '#', '%', '&', '(',
    ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=',
    '>', '?', '@', '[', ']', '^', '_', '{', '|', '}', '~',
};

/* 496649-224-224 */
static const char BLS_PARAM[] =
"type d\n"
"q 15028799613985034465755506450771565229282832217860390155996483840017\n"
"n 15028799613985034465755506450771561352583254744125520639296541195021\n"
"h 1\n"
"r 15028799613985034465755506450771561352583254744125520639296541195021\n"
"a 1871224163624666631860092489128939059944978347142292177323825642096\n"
"b 9795501723343380547144152006776653149306466138012730640114125605701\n"
"k 6\n"
"nk 11522474695025217370062603013790980334538096429455689114222024912184432319"
   "22839320465038366178186480607624725955637835054166999434487843013620271494"
   "57614883858906199255534576681585042027865805599709459366576368553467135988"
   "88067516214634859330554634505767198415857150479345944721710356274047707536"
   "15629621557341276373513560095386541900039892029253521575729153930752563967"
   "5204597938919504807427238735811520\n"
"hk 51014915936684265604900487195256160848193571244274648855332475661658304506"
   "31630100611288717727734501086401298812782965544925642487102450036859798946"
   "23738130621892741509165526892628526032540112485023560412065442627554817791"
   "37398040376281542938513970473990787064615734720\n"
"coeff0 11975189258259697166257037825227536931446707944682470951111859446192\n"
"coeff1 13433042200347934827742738095249546804006687562088254057411901362771\n"
"coeff2 8327464521117791238079105175448122006759863625508043495770887411614\n"
"nqr 142721363302176037340346936780070353538541593770301992936740616924\n";

static const unsigned char BLS_G[] = {
    0x1E, 0x35, 0xD7, 0x10, 0xE2, 0x8D, 0x86, 0xB8,
    0xFC, 0x69, 0xF5, 0x96, 0x76, 0xFA, 0xB1, 0xE5,
    0x55, 0xE6, 0x07, 0x59, 0x6D, 0xBB, 0x84, 0x39,
    0xFA, 0xBE, 0xEA, 0x33, 0x09, 0x6D, 0x22, 0x10,
    0x5B, 0xFB, 0xCE, 0x48, 0x4E, 0xDA, 0x3F, 0x79,
    0x34, 0xB2, 0x30, 0x31, 0x3E, 0x82, 0xF3, 0x89,
    0x32, 0x3F, 0xDB, 0xF5, 0xF1, 0xB6, 0x53, 0x34,
    0x43, 0xF4, 0xB3, 0x83, 0x9C, 0x33, 0x66, 0xA8,
    0x8F, 0xBA, 0x2F, 0x44, 0xC6, 0x1B, 0xD0, 0x6D,
    0x47, 0xD1, 0xDF, 0x52, 0x85, 0x72, 0xD1, 0x0C,
    0x6F, 0x54, 0x62, 0xCB, 0x19, 0x8A, 0xD4, 0xAF,
    0xD0, 0x58, 0xBD, 0x5A, 0xF9, 0xA4, 0x0E, 0x8B,
    0xD3, 0x9F, 0x13, 0x40, 0x74, 0x9E, 0xD3, 0xB8,
    0xB6, 0x99, 0x5E, 0xC2, 0x09, 0x81, 0x7A, 0x4A,
    0x50, 0xE2, 0x9E, 0x7D, 0x51, 0xD7, 0x27, 0x20,
    0x0F, 0xA1, 0x3F, 0x39, 0xC8, 0x2E, 0x7B, 0x79,
    0x55, 0x5B, 0xF2, 0x63, 0x78, 0xC9, 0xC4, 0x93,
    0xC4, 0x08, 0xBE, 0x1B, 0x45, 0x81, 0x4B, 0x31,
    0xC5, 0xBB, 0x92, 0x23, 0x08, 0x0C, 0x6F, 0xA1,
    0x1C, 0x76, 0xEF, 0xD0, 0xD9, 0x13, 0x93, 0xCE,
    0xB9, 0xE0, 0x04, 0xBC, 0x0F, 0x8C, 0x41, 0x74
};

static char BASE36_LOOKUP[256];
static char BASE88_LOOKUP[256];
static  int g_initialized = 0;

static void crypto_initialize(void)
{
    size_t i;
    char c;

    pthread_mutex_lock(&g_mutex);
    if (g_initialized) {
        pthread_mutex_unlock(&g_mutex);
        return;
    }

    memset(BASE36_LOOKUP, -1, sizeof(BASE36_LOOKUP));
    memset(BASE88_LOOKUP, -1, sizeof(BASE88_LOOKUP));

    c = 0;
    for (i = 0; i < sizeof(BASE36_TABLE); ++i) {
        BASE36_LOOKUP[BASE36_TABLE[i]] = c++;
    }

    c = 0;
    for (i = 0; i < sizeof(BASE88_TABLE); ++i) {
        BASE88_LOOKUP[BASE88_TABLE[i]] = c++;
    }

    g_initialized = 1;
    pthread_mutex_unlock(&g_mutex);
}

static void crypto_swap_limbs(void *buf, size_t length)
{
#if WORDS_BIGENDIAN
    unsigned char *p;
    unsigned char c;
    size_t i;

    p = (unsigned char *)buf;
    for (i = 0; i < length / 2; ++i) {
        c = p[i];
        p[i] = p[length - i - 1];
        p[length - i - 1] = c;
    }
#endif
}

int crypto_base36_encode(const void *input, size_t inlen,
                         void *output, size_t outlen)
{
    mp_limb_t r[18 / sizeof(mp_limb_t) + 2];
    mp_limb_t *rp;
    mp_size_t ret;

    unsigned char outbuf[(sizeof(r) / sizeof(*r) + 1) * sizeof(*r)];
    unsigned char *rout;
    unsigned char *out;
    unsigned char *in;
    size_t rc;
    size_t i;

    if (!input || !output || inlen != 18 || outlen != 28) {
        return -1;
    }

    crypto_initialize();

    out = (unsigned char *)output;
    rc = sizeof(r) / sizeof(*r);
    in = (unsigned char *)r;
    rout = outbuf;
    rp = r;

    memcpy(in, input, inlen);
    memset(in + inlen, 0, sizeof(r) - inlen);
    crypto_swap_limbs(r, sizeof(r));

    ret = mpn_get_str(outbuf, 36, rp, rc);
    if (ret == 0) {
        memset(output, *BASE36_TABLE, outlen);
        return 0;
    }

    for (i = 0; i < ret; ++i) {
        outbuf[i] = BASE36_TABLE[outbuf[i]];
    }

    if (ret > outlen) {
        rout += ret - outlen;
        ret = outlen; /* Drop most significant bits. */
    } else if (ret < outlen) {
        memset(output, *BASE36_TABLE, outlen - ret);
    }

    memcpy(out + outlen - ret, rout, ret);
    return 0;
}

/* Merely copy crypto_base36_encode() */
int crypto_base88_encode(const void *input, size_t inlen,
                         void *output, size_t outlen)
{
    mp_limb_t r[58 / sizeof(mp_limb_t) + 2];
    mp_limb_t *rp;
    mp_size_t ret;

    unsigned char outbuf[(sizeof(r) / sizeof(*r) + 1) * sizeof(*r)];
    unsigned char *rout;
    unsigned char *out;
    unsigned char *in;
    size_t rc;
    size_t i;

    if (!input || !output || inlen != 58 || outlen != 72) {
        return -1;
    }

    crypto_initialize();

    out = (unsigned char *)output;
    rc = sizeof(r) / sizeof(*r);
    in = (unsigned char *)r;
    rout = outbuf;
    rp = r;

    memcpy(in, input, inlen);
    memset(in + inlen, 0, sizeof(r) - inlen);
    crypto_swap_limbs(r, sizeof(r));

    ret = mpn_get_str(outbuf, 88, rp, rc);
    if (ret == 0) {
        memset(output, *BASE88_TABLE, outlen);
        return 0;
    }

    for (i = 0; i < ret; ++i) {
        outbuf[i] = BASE88_TABLE[outbuf[i]];
    }

    if (ret > outlen) {
        rout += ret - outlen;
        ret = outlen; /* Drop most significant bits. */
    } else if (ret < outlen) {
        memset(output, *BASE88_TABLE, outlen - ret);
    }

    memcpy(out + outlen - ret, rout, ret);
    return 0;
}

int crypto_base36_decode(const void *input, size_t inlen,
                         void *output, size_t outlen)
{
    mp_limb_t r[18 / sizeof(mp_limb_t) + 2];
    mp_limb_t *rp;
    mp_size_t ret;

    const unsigned char *in;
    unsigned char *out;
    char inbuf[28 + 1];
    size_t len;
    size_t i;

    if (!input || !output || inlen != 28 || outlen != 18) {
        return -1;
    }

    crypto_initialize();

    in = (const unsigned char *)input;
    out = (unsigned char *)output;
    rp = r;

    inbuf[0] = 0; /* Make sure it's positive. */
    for (i = 1; i <= inlen; ++i) {
        inbuf[i] = BASE36_LOOKUP[*in++];
        if (inbuf[i] < 0) {
            return -1;
        }
    }

    ret = mpn_set_str(r, (unsigned char *)inbuf, inlen + 1, 36);
    if (ret == 0) {
        memset(output, 0, outlen);
        return 0;
    }

    crypto_swap_limbs(rp, sizeof(*rp) * ret);

    len = sizeof(*rp) * ret;
    if (len > outlen) {
        len = outlen; /* Drop most significant bits. */
    } else if (len < outlen) {
        memset(out + len, 0, outlen - len);
    }

    memcpy(out, r, len);
    return 0;
}

/* Merely copy crypto_base36_decode() */
int crypto_base88_decode(const void *input, size_t inlen,
                         void *output, size_t outlen)
{
    mp_limb_t r[58 / sizeof(mp_limb_t) + 2];
    mp_limb_t *rp;
    mp_size_t ret;

    const unsigned char *in;
    unsigned char *out;
    char inbuf[72 + 1];
    size_t len;
    size_t i;

    if (!input || !output || inlen != 72 || outlen != 58) {
        return -1;
    }

    crypto_initialize();

    in = (const unsigned char *)input;
    out = (unsigned char *)output;
    rp = r;

    inbuf[0] = 0; /* Make sure it's positive. */
    for (i = 1; i <= inlen; ++i) {
        inbuf[i] = BASE88_LOOKUP[*in++];
        if (inbuf[i] < 0) {
            return -1;
        }
    }

    ret = mpn_set_str(r, (unsigned char *)inbuf, inlen + 1, 88);
    if (ret == 0) {
        memset(output, 0, outlen);
        return 0;
    }

    crypto_swap_limbs(rp, sizeof(*rp) * ret);

    len = sizeof(*rp) * ret;
    if (len > outlen) {
        len = outlen; /* Drop most significant bits. */
    } else if (len < outlen) {
        memset(out + len, 0, outlen - len);
    }

    memcpy(out, r, len);
    return 0;
}

#define LOAD(e,b,l) \
if (element_from_bytes((e), (unsigned char *)(b)) != (l)) break

#define LOADC(e,b,l) \
if (element_from_bytes_compressed((e), (unsigned char *)(b)) != (l)) break

static int crypto_sha224(const void *input, size_t inlen, unsigned char *md)
{
    SHA256_CTX ctx;
    if (SHA224_Init(&ctx) != 1) {
        return -1;
    }

    if (SHA224_Update(&ctx, input, inlen) != 1) {
        return -1;
    }

    if (SHA224_Final(md, &ctx) != 1) {
        return -1;
    }

    return 0;
}

ssize_t crypto_sign(const void *input, size_t inlen,
                    void *sign, size_t signlen,
                    const void *privkey, size_t privlen)
{
    unsigned char hash[SHA224_DIGEST_LENGTH];
    pairing_t pairing;
    int result;
    int len;

    element_t private_key;
    element_t sig;
    element_t g;
    element_t h;

    if (crypto_sha224(input, inlen, hash)) {
        return -1;
    }

    /* This one really costs due to super heavy memory operations. */
    if (pairing_init_set_buf(pairing, BLS_PARAM, sizeof(BLS_PARAM))) {
        return -1;
    }

    len = pairing_length_in_bytes_compressed_G1(pairing);
    if ((int)signlen < len) {
        pairing_clear(pairing);
        return -1;
    }

    element_init_G2(g, pairing);
    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);
    element_init_Zr(private_key, pairing);

    result = -1;
    do {
        LOAD(g, BLS_G, sizeof(BLS_G));
        element_from_hash(h, hash, sizeof(hash));

        LOAD(private_key, privkey, privlen);
        element_pow_zn(sig, h, private_key);

        result = element_to_bytes_compressed(sign, sig);

    } while (0);

    element_clear(h);
    element_clear(g);
    element_clear(sig);
    element_clear(private_key);
    pairing_clear(pairing);
    return result;
}

int crypto_verify(const void *input, size_t inlen,
                  const void *sign, size_t signlen,
                  const void *pubkey, size_t publen)
{
    unsigned char hash[SHA224_DIGEST_LENGTH];
    pairing_t pairing;
    int result;
    int len;

    element_t public_key;
    element_t expected;
    element_t actual;
    element_t sig;
    element_t g;
    element_t h;

    if (crypto_sha224(input, inlen, hash)) {
        return -1;
    }

    /* This one really costs due to super heavy memory operations. */
    if (pairing_init_set_buf(pairing, BLS_PARAM, sizeof(BLS_PARAM))) {
        return -1;
    }

    len = pairing_length_in_bytes_compressed_G1(pairing);
    if ((int)signlen < len) {
        pairing_clear(pairing);
        return -1;
    }

    element_init_G2(g, pairing);
    element_init_G2(public_key, pairing);
    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);
    element_init_GT(expected, pairing);
    element_init_GT(actual, pairing);

    result = -1;
    do {
        LOAD(g, BLS_G, sizeof(BLS_G));
        element_from_hash(h, hash, sizeof(hash));

        LOAD(public_key, pubkey, publen);
        LOADC(sig, sign, len);

        element_pairing(expected, sig, g);
        element_pairing(actual, h, public_key);
        if (element_cmp(expected, actual)) {
            break;
        }

        result = 0;
    } while (0);

    element_clear(h);
    element_clear(g);
    element_clear(sig);
    element_clear(actual);
    element_clear(expected);
    element_clear(public_key);
    pairing_clear(pairing);
    return result;
}

int crypto_generate(void *pubkey, size_t *publen, void *privkey, size_t *privlen)
{
    pairing_t pairing;
    int result;
    int pbl;
    int pkl;

    element_t private_key;
    element_t public_key;
    element_t g;

    /* This one really costs due to super heavy memory operations. */
    if (pairing_init_set_buf(pairing, BLS_PARAM, sizeof(BLS_PARAM))) {
        return -1;
    }

    pbl = pairing_length_in_bytes_G2(pairing);
    pkl = pairing_length_in_bytes_Zr(pairing);
    if ((int)*publen < pbl || (int)*privlen < pkl) {
        pairing_clear(pairing);
        return -1;
    }

    element_init_G2(g, pairing);
    element_init_G2(public_key, pairing);
    element_init_Zr(private_key, pairing);

    result = -1;
    do {
        LOAD(g, BLS_G, sizeof(BLS_G));

        element_random(private_key);
        element_pow_zn(public_key, g, private_key);

        element_to_bytes(pubkey, public_key);
        element_to_bytes(privkey, private_key);
        *privlen = (size_t)pkl;
        *publen = (size_t)pbl;
        result = 0;

    } while (0);

    element_clear(g);
    element_clear(public_key);
    element_clear(private_key);
    pairing_clear(pairing);
    return result;
}
