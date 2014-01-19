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

#include <sys/types.h>
#include <errno.h>
#include <grp.h>
#include <nss.h>

#include "nss-common.h"
#include "group.h"

static int nss_fill_group(struct group_t *group,
                          struct group *grp,
                          char *buffer,
                          size_t buflen)
{
    grp->gr_gid     = group->gid;
    grp->gr_passwd  = nss_strdup("x",               &buffer, &buflen);
    grp->gr_name    = nss_strdup(group->groupname,  &buffer, &buflen);
    grp->gr_mem     = (char **)nss_malloc(sizeof(char *), &buffer, &buflen);

    if (!grp->gr_passwd || !grp->gr_name || !grp->gr_mem) {
        return -1;
    }

    grp->gr_mem[0] = NULL;
    return 0;
}

static enum nss_status nss_return_group(struct group_t *group,
                                        struct group *grp,
                                        char *buffer,
                                        size_t buflen,
                                        int *errnop)
{
    if (!group) {
        return NSS_STATUS_NOTFOUND;
    }

    if (nss_fill_group(group, grp, buffer, buflen)) {
        group_free(group);
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    group_free(group);
    return NSS_STATUS_SUCCESS;
}

NSS_METHOD(setgrent)(int stayopen)
{
    if (group_open_group()) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

NSS_METHOD(endgrent)(void)
{
    if (group_close_group()) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

NSS_METHOD(getgrnam_r)(const char *name,
                       struct group *grp,
                       char *buffer,
                       size_t buflen,
                       int *errnop)
{
    struct group_t *group;
    group = group_get_group_by_groupname(name);
    return nss_return_group(group, grp, buffer, buflen, errnop);
}

NSS_METHOD(getgrgid_r)(gid_t gid,
                       struct group *grp,
                       char *buffer,
                       size_t buflen,
                       int *errnop)
{
    struct group_t *group;
    group = group_get_group_by_gid(gid);
    return nss_return_group(group, grp, buffer, buflen, errnop);
}

NSS_METHOD(getgrent_r)(struct group *grp,
                       char *buffer,
                       size_t buflen,
                       int *errnop)
{
    struct group_t *group;
    group = group_get_next_group();
    return nss_return_group(group, grp, buffer, buflen, errnop);
}
