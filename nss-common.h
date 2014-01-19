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

#ifndef __GATEKEEPER_NSS_COMMON_H__
#define __GATEKEEPER_NSS_COMMON_H__

#include <stddef.h>

#define __NSS_CONCAT(a,b) a ## b
#define __NSS_METHOD(method) enum nss_status __NSS_CONCAT(_nss_, method)
#define _NSS_METHOD(soname,method) __NSS_METHOD(__NSS_CONCAT(soname, _ ## method))
#define NSS_METHOD(method) _NSS_METHOD(CONFIG_PACKAGE_NAME, method)

extern void *nss_malloc(size_t size, char **buffer, size_t *buflen);
extern char *nss_strdup(const char *str, char **buffer, size_t *buflen);

#endif /* __GATEKEEPER_NSS_COMMON_H__ */
