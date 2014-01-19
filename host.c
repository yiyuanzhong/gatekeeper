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

#include "host.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>

struct address_t *host_get_local_address(void)
{
    struct sockaddr_in6 *inp6;
    struct sockaddr_in *inp;
    struct address_t *h;
    struct address_t *r;
    struct address_t *n;
    struct ifaddrs *a;
    struct ifaddrs *p;

    if (getifaddrs(&a)) {
        return NULL;
    }

    h = r = NULL;
    for (p = a; p; p = p->ifa_next) {
        if (p->ifa_addr->sa_family != AF_INET  &&
            p->ifa_addr->sa_family != AF_INET6 ){
            continue;
        }

        n = (struct address_t *)malloc(sizeof(*n));
        if (!n) {
            host_free_address(h);
            freeifaddrs(a);
            return NULL;
        }

        memset(n, 0, sizeof(*n));
        n->family = p->ifa_addr->sa_family;
        if (r) {
            r->next = n;
            r = n;
        } else {
            h = r = n;
        }

        if (p->ifa_addr->sa_family == AF_INET) {
            inp = (struct sockaddr_in *)p->ifa_addr;
            if (!inet_ntop(AF_INET, &inp->sin_addr, n->address, sizeof(n->address))) {
                host_free_address(h);
                freeifaddrs(a);
                return NULL;
            }

        } else {
            inp6 = (struct sockaddr_in6 *)p->ifa_addr;
            if (!inet_ntop(AF_INET6, &inp6->sin6_addr, n->address, sizeof(n->address))) {
                host_free_address(h);
                freeifaddrs(a);
                return NULL;
            }
        }
    }

    freeifaddrs(a);
    return h;
}

void host_free_address(struct address_t *address)
{
    struct address_t *p;
    struct address_t *q;

    for (p = address; p; p = q)
    {
        q = p->next;
        free(q);
    }
}
