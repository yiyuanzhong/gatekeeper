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

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stddef.h>

#include "pam-common.h"
#include "user.h"

PAM_METHOD(pam_sm_chauthtok)
{
    const char *user;
    int ret;

    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    if (user_is_valid_username(user)) {
        return PAM_AUTHTOK_ERR;
    }

    return PAM_SUCCESS;
}
