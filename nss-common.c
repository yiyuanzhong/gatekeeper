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

#include "nss-common.h"

#include <string.h>

void *nss_malloc(size_t size, char **buffer, size_t *buflen)
{
    char *result;

    if (!size || !buffer || !*buffer || !buflen) {
        return NULL;
    }

    if (*buflen < size) {
        return NULL;
    }

    result = *buffer;
    *buflen -= size;
    *buffer += size;
    return result;
}

char *nss_strdup(const char *str, char **buffer, size_t *buflen)
{
    char *result;
    size_t len;

    if (!str || !buffer || !*buffer || !buflen) {
        return NULL;
    }

    len = strlen(str) + 1;
    if (*buflen < len) {
        return NULL;
    }

    result = *buffer;
    *buflen -= len;
    *buffer += len;
    memcpy(result, str, len);
    return result;
}
