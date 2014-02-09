# Copyright 2014 yiyuanzhong@gmail.com (Yiyuan Zhong)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


AC_PREREQ([2.59])
AC_INIT([gatekeeper], [1.0.0], [yiyuanzhong@gmail.com])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([login.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([so.map])

AM_INIT_AUTOMAKE

AC_ARG_WITH([sqlite],
            [AC_HELP_STRING([--with-sqlite],
                            [use bundled sqlite (default=yes)])])

AM_CONDITIONAL([SQLITE], [test x"${with_sqlite}" != x"no"])
AS_IF([test x"${with_sqlite}" = x"no"], [PKG_CHECK_MODULES([sqlite], [sqlite3])])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
PKG_CHECK_MODULES([openssl], [libcrypto])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_SEARCH_LIBS([pthread_mutex_lock], [pthread])

AC_CHECK_LIB([gmp], [main], [], [AC_MSG_ERROR([libgmp is not found, download at https://gmplib.org/])])
AC_CHECK_LIB([pbc], [pairing_init_set_buf], [], [AC_MSG_ERROR([libpbc is not found, download at http://crypto.stanford.edu/pbc/])])
AC_CHECK_LIB([pam], [pam_get_user], [], [AC_MSG_ERROR([libpam is not found])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h shadow.h stddef.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT64_T
AC_C_BIGENDIAN

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup strtoul])

AC_CONFIG_FILES([Makefile sqlite/Makefile])
AC_OUTPUT
