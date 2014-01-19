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

#ifndef __GATEKEEPER_CRYPTO_H__
#define __GATEKEEPER_CRYPTO_H__

#include <sys/types.h>

extern int crypto_base36_encode(const void *input, size_t inlen,
                                void *output, size_t outlen);

extern int crypto_base36_decode(const void *input, size_t inlen,
                                void *output, size_t outlen);

extern int crypto_base88_encode(const void *input, size_t inlen,
                                void *output, size_t outlen);

extern int crypto_base88_decode(const void *input, size_t inlen,
                                void *output, size_t outlen);

/** @return <0 for error, or bytes written to sign. */
extern ssize_t crypto_sign(const void *input, size_t inlen,
                           void *sign, size_t signlen,
                           const void *privkey, size_t privlen);

extern int crypto_verify(const void *input, size_t inlen,
                         const void *sign, size_t signlen,
                         const void *pubkey, size_t publen);

/** publen and privlen must be assigned the buffer size before calling. */
extern int crypto_generate(void *pubkey, size_t *publen,
                           void *privkey, size_t *privlen);

#endif /* __GATEKEEPER_CRYPTO_H__ */
