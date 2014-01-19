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

#ifndef __GATEKEEPER_HOST_H__
#define __GATEKEEPER_HOST_H__

struct address_t {
    struct address_t *next;
    int family;
    char address[64];
};

extern struct address_t *host_get_local_address(void);
extern void host_free_address(struct address_t *address);

#endif /* __GATEKEEPER_HOST_H__ */
