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


AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

noinst_PROGRAMS = test_@PACKAGE_NAME@
lib_LTLIBRARIES = lib@PACKAGE_NAME@.la

lib@PACKAGE_NAME@_la_LIBADD = ${openssl_LIBS} ${sqlite_LIBS}
lib@PACKAGE_NAME@_la_LDFLAGS = -version-info 2:0:0
lib@PACKAGE_NAME@_la_LDFLAGS += -Wl,--version-script -Wl,$(builddir)/so.map

lib@PACKAGE_NAME@_la_SOURCES = config.h pam-common.h \
                               crypto.c crypto.h \
                               login.c login.h \
                               group.c group.h \
                               host.c host.h \
                               user.c user.h \
                               nss-common.c nss-common.h \
                               nss-grp.c nss-initgroups.c nss-pwd.c nss-spwd.c \
                               pam-account.c pam-auth.c pam-password.c pam-session.c

test_@PACKAGE_NAME@_SOURCES = main.c
test_@PACKAGE_NAME@_LDADD = lib@PACKAGE_NAME@.la

AM_CPPFLAGS = -DCONFIG_PACKAGE_NAME=@PACKAGE_NAME@ -DNDEBUG
AM_CFLAGS = -g -Wall -Werror ${openssl_CFLAGS} ${sqlite_CFLAGS}

EXTRA_DISTCLEAN = so.map
EXTRA_DIST = so.map.in sqlite/empty.sql sqlite/demo.sql

if SQLITE
SUBDIRS = sqlite
AM_CPPFLAGS += -I${srcdir}/sqlite
lib@PACKAGE_NAME@_la_LIBADD += sqlite/libsqlite3.la
endif
