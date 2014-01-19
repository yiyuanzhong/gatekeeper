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

#include <stdio.h>
#include <stdlib.h>

#include "login.h"

int main(int argc, char *argv[])
{
    char loginname[100];
    char loginpass[100];
    const char *host;
    int ret;
    int id;

    if (argc >= 2) {
        host = argv[1];
    } else {
        host = "127.0.0.1";
    }

    if (argc >= 3) {
        id = atoi(argv[2]);
    } else {
        id = 0;
    }

    ret = login_demo_generate_credentials(
            0, 0, host,
            0xb922a62746eac276, id, "::1",
            0,
            loginname, sizeof(loginname),
            loginpass, sizeof(loginpass));

    if (ret) {
        fprintf(stderr, "Failed to generate credentials.\n");
        return EXIT_FAILURE;
    }

    printf("%s@%s\n", loginname, host);
    printf("%s\n", loginpass);
    return EXIT_SUCCESS;
}
