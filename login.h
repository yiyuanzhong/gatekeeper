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

#ifndef __GATEKEEPER_LOGIN_H__
#define __GATEKEEPER_LOGIN_H__

#include <sys/types.h>
#include <stdint.h>

struct user_t;

/* @return bool */
extern int login_is_valid_loginname(const char *loginname);

/* @return bool */
extern int login_is_valid_loginpass(const char *loginpass);

/* @return GATEKEEPER_UID_INVALID if invalid */
extern struct user_t *login_with_credentials(const char *loginname,
                                             const char *loginpass,
                                             const char *remote_host);

extern struct user_t *login_get_user_by_loginname(const char *loginname);

/* TODO(yiyuanzhong): only for demo purpose. */
extern int login_demo_generate_credentials(uint64_t fh, uint64_t fl, const char *fa,
                                           uint64_t th, uint64_t tl, const char *ta,
                                           uint16_t flags,
                                           char *loginname, size_t namelen,
                                           char *loginpass, size_t passlen);

#endif /* __GATEKEEPER_LOGIN_H__ */
