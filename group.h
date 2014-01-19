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

#ifndef __GATEKEEPER_GROUP_H__
#define __GATEKEEPER_GROUP_H__

#include <sys/types.h>
#include <limits.h>
#include <stdint.h>

typedef struct group_t {
    gid_t gid;
    const char *groupname;
} group_t;

extern int group_open_group(void);
extern int group_close_group(void);
extern struct group_t *group_get_next_group(void);

extern struct group_t *group_get_group_by_groupname(const char *groupname);
extern struct group_t *group_get_group_by_gid(gid_t gid);
extern void group_free(struct group_t *group);

#endif /* __GATEKEEPER_GROUP_H__ */
