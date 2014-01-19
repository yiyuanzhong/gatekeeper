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

#include "group.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#define GATEKEEPER_GROUPNAME    PACKAGE_NAME
#define GATEKEEPER_GID          81000

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_db_group_ptr = -1;

static void group_set_db_ptr(int i)
{
    pthread_mutex_lock(&g_mutex);
    g_db_group_ptr = i;
    pthread_mutex_unlock(&g_mutex);
}

static struct group_t *group_new(void)
{
    struct group_t *g;

    g = (struct group_t *)malloc(sizeof(*g));
    if (!g) {
        return NULL;
    }

    memset(g, 0, sizeof(*g));
    g->gid = GATEKEEPER_GID;
    g->groupname = GATEKEEPER_GROUPNAME;
    return g;
}

int group_open_group(void)
{
    group_set_db_ptr(0);
    return 0;
}

int group_close_group(void)
{
    group_set_db_ptr(-1);
    return 0;
}

struct group_t *group_get_next_group(void)
{
    pthread_mutex_lock(&g_mutex);
    if (g_db_group_ptr) {
        pthread_mutex_unlock(&g_mutex);
        return NULL;
    }

    ++g_db_group_ptr;
    pthread_mutex_unlock(&g_mutex);

    return group_new();
}

void group_free(struct group_t *group)
{
    free(group);
}

struct group_t *group_get_group_by_groupname(const char *groupname)
{
    if (strcmp(groupname, GATEKEEPER_GROUPNAME)) {
        return NULL;
    }

    return group_new();
}

struct group_t *group_get_group_by_gid(gid_t gid)
{
    if (gid != GATEKEEPER_GID) {
        return NULL;
    }

    return group_new();
}
