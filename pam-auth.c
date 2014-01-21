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
#include <sys/types.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "login.h"
#include "pam-common.h"
#include "user.h"

PAM_METHOD(pam_sm_authenticate)
{
    const struct pam_message *msgp;
    struct pam_response *resp;
    struct pam_message msg;
    struct pam_conv *conv;

    const char *username;
    const char *hostname;
    const char *password;
    char *pam_password;
    user_t *user;
    int ret;

    ret = pam_get_item(pamh, PAM_RHOST, (const void **)&hostname);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    ret = pam_get_user(pamh, &username, NULL);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    pam_password = NULL;
    ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    if (ret != PAM_SUCCESS || !password) {
        ret = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
        if (ret != PAM_SUCCESS) {
            return PAM_SYSTEM_ERR;
        }

        memset(&msg, 0, sizeof(msg));
        msg.msg_style = PAM_PROMPT_ECHO_OFF;
        msg.msg = "Password:";
        msgp = &msg;

        resp = NULL;
        password = NULL;
        ret = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
        if (resp) {
            if (ret == PAM_SUCCESS) {
                pam_password = resp->resp;

                /* Failure? That's OK. */
                pam_set_item(pamh, PAM_AUTHTOK, pam_password);

            } else {
                free(resp->resp);
            }
            free(resp);
        }

        password = pam_password;
    }

    if (!password) {
        return ret == PAM_CONV_ERR ? PAM_CONV_ERR : PAM_AUTH_ERR;
    }

    if (!hostname || !*hostname) { /* Can't work without remote hostname. */
        return PAM_USER_UNKNOWN;

    } else if (user_is_valid_username(username) || /* No way. */
               !login_is_valid_loginpass(password)) {

        return PAM_AUTH_ERR;

    } else if (!login_is_valid_loginname(username)) {
        return PAM_USER_UNKNOWN;
    }

    user = login_with_credentials(username, password, hostname);
    if (!user) {
        free(pam_password);
        return PAM_AUTH_ERR;
    }

    free(pam_password);

    ret = pam_set_item(pamh, PAM_USER, user->username);
    if (ret != PAM_SUCCESS) {
        user_free(user);
        return PAM_SYSTEM_ERR;
    }

    user_free(user);
    return PAM_SUCCESS;
}

PAM_METHOD(pam_sm_setcred)
{
    return PAM_SUCCESS;
}
