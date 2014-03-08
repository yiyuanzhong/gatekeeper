Gatekeeper
====
## What is Gatekeeper?
Gatekeeper is an automated authentication and authorization solution, client
part. It provides a programming library to integrate into existing systems
that support traditional username/password authenticating schema, and a Linux
PAM+NSS module to integrate into systems that are PAM aware, like SSH.

## What happened?
The service provider, the entity being accessed, must make sure 1. who is this
guy? (authentication) 2. can I open my gate for this guy? (authorization). The
traditional way is to set a user on the provider, grant (thus restrict) the
user some access permissions, which is about authorization. And then set a
password on the user so only someone (something) knows the password can use the
user, which is about authentication.

This is a quite old schema, is well known and accepted, and very effective.
However managing users and passwords is painful so central management solutions
are implemented. And then cryptography comes and (a)symmetric keys replaced a
lot of username/passwords. Also there's tons of solutions trying to wrap plain
username/password inside something secure, like HTTPS or TLS-EAP.

So what's the problem then?

1. Managing users centrally is effective, but we still need to distribute keys
or passwords, which are hard to remember and easy to lose.
2. Advanced schemas require complicated protocols, some of them are difficult
to implement. Handing over two strings is just simple, but to do a DH exchange
then sign a ticket with EC curves, oops...
3. Central servers are bottlenecks and single point of failures.

## So how do you do it?
Ever used a RSA SecurID? The pin code and the dynamic digits are practically
"password", however it's changing automatically and difficult to guess. Try to
expand the idea, I generate a "password" for the requester, so it can access
the provider with familiar schema, without any programming or protocols.

Gatekeeper is a PKI based solution:

1. There is a CA signing certificates for agents, but the CA doesn't involve
in actual communications, preventing single point of failure.
2. An trusted agent is doing the PKI instead of actual participates. The root
account of each box is trusted, that means a service or person cannot gain
root access to that box. It's like the old days when we RSH to other hosts.
3. The ticket is in a form that is suitable for password schema: just two
strings short enough to fit in almost all the systems.
4. Eavesdroping the ticket in plaintext doesn't really compromise the schema,
because the private key is never transmitted over the wire. MITM can be
prevented with some efforts.

## How to run it?
Gatekeeper requires libgmp, libpbc, OpenSSL and sqlite3 to build.
* https://gmplib.org/
* http://crypto.stanford.edu/pbc/
* http://www.openssl.org/
* http://www.sqlite.org/

By default sqlite3 amalgamation is used, so place sqlite3.h and sqlite3.c
into sqlite/ before you configure. Alternatively you can use --without-sqlite
configure switch to use the system installed sqlite3.

The build result is installed into /usr/local/lib/libgatekeeper.so.2

In order to enable PAM+NSS, two symlinks must be properly made. Depending on
your Linux distro, it might be like:
```shell
/lib64/libnss_gatekeeper.so.2
/lib64/security/pam_gatekeeper.so
- or maybe -
/lib/x86_64-linux-gnu/libnss_gatekeeper.so.2
/lib/x86_64-linux-gnu/security/pam_gatekeeper.so
```

Check for existing PAM and NSS modules, just do what they do.

You should generate the demonstrating user database now:
```shell
# sqlite3 /var/run/gatekeeper_user.db <sqlite/empty.sql
# sqlite3 /var/run/gatekeeper_user.db <sqlite/demo.sql
```

Modify /etc/nsswitch.conf and append "gatekeeper" to 3 databases: passwd, group
and shadow, like this:
```shell
- original -
passwd: files
group:  files
shadow: files
- into -
passwd: files gatekeeper
group:  files gatekeeper
shadow: files gatekeeper
```

If you're doing it right, now try to type "getent passwd":
```shell
$ getent passwd
root:x:0:0:root:/root:/bin/bash
...
app_81001:x:81001:81000:Demo 81001:/home/services/81001:/bin/sh
app_81002:x:81002:81000:Demo 81002:/home/services/81002:/bin/sh
app_81010:x:81010:81000:Demo 81010:/home/services/81010:/bin/sh
app_81016:x:81016:81000:Demo 81016:/home/services/81016:/bin/sh
app_81019:x:81019:81000:Demo 81019:/home/services/81019:/bin/sh
app_81022:x:81022:81000:Demo 81022:/home/services/81022:/bin/sh
app_81037:x:81037:81000:Demo 81037:/home/services/81037:/bin/sh
app_81086:x:81086:81000:Demo 81086:/home/services/81086:/bin/sh
app_81113:x:81113:81000:Demo 81113:/home/services/81113:/bin/sh
app_81151:x:81151:81000:Demo 81151:/home/services/81151:/bin/sh
$
```

If you see these "app_xxxxx" accounts, they're demo accounts in this build,
then you've configured NSS module correctly.

The PAM module is not standardized and there's no certain way to configure.
A generic way is to modify (after you backup of course) /etc/pam.d/sshd, or
on many distros /etc/pam.d/common-xxx, or maybe /etc/pam.d/system-auth.

The following lines or equivalent ones should be set:
```shell
auth        sufficient  pam_gatekeeper.so # Before pam_unix.so
password    requisite   pam_gatekeeper.so # Top of password secton
```

If you've done it correctly, now you can proceed with SSH. Before that, you
need a valid set of login credentials. A demonstrate program is built but not
installed. The demo can generate valid username and password:
```shell
$ ./test_gatekeeper 127.0.0.1 0
Valid ticket for 127.0.0.1 to the no.0 account on remote box:
g_aaak8u1jdi03zflnf9059tqibdsi
X/n{UwXfZBARmVnpIRVE~Iu5zro|#@[=4lEXCOJEqd{n%Q0}_>oxJ^7.N/xege;)yvs-&R}w
$
```
Then try to login:
```shell
$ ssh g_aaak8u1jdi03zflnf9059tqibdsi@127.0.0.1
g_aaak8u1jdi03zflnf9059tqibdsi@127.0.0.1's password: (the latter string)
Last login: Mon Jan 20 01:52:06 2014 from 127.0.0.1
$ id
uid=81001(app_81001) gid=81000(gatekeeper) groups=81000(gatekeeper)
$ passwd
passwd: Authentication token manipulation error
passwd: password unchanged
$
```

You should 1. successfully login into app_81001. 2. fail to change password.

Another account?
```shell
$ ./test_gatekeeper 127.0.0.1 3
Valid ticket for 127.0.0.1 to the no.3 account on remote box:
g_aaak8u1jdi03zflnf9059tqibdsl
YUHS/.)g0=&YecJR6L~<lV,hQS^s0)2UMzscpgK^4m:H8.)14l_W?PyFEdsF9o05s2kzqJK[
$ ssh g_aaak8u1jdi03zflnf9059tqibdsl@127.0.0.1
g_aaak8u1jdi03zflnf9059tqibdsl@127.0.0.1's password:
Last login: Mon Jan 20 01:22:22 2014 from ::1
$ id
uid=81016(app_81016) gid=81000(gatekeeper) groups=81000(gatekeeper)
$
```

The username/password can be used unlimited times until 120 seconds later.

Note that the source IP address is checked against the ticket, so provide
correct IP address for __local IP__ is essential. SSH into 127.0.0.1 will
make your local IP as 127.0.0.1, ::1 for ::1, and your external IP if you
SSH into a remote box. For example, 192.168.1.1 to login into 192.168.3.7,
the remote box will see your IP as 192.168.1.1, so you use:
```shell
$ ./test_gatekeeper 192.168.1.1 0
```

## That's it?
Well, this project is currently only a demo.

In order to get the full power out of Gatekeeper, read the code and find all
the TODOs. There're quite some now. This is the list of what is missing:

1. The local service list, you must manually operate the sqlite database now.
2. The host keypair distributing system, a hardcoded keypair is used for
anything now, meaning that all the hosts share the same public key, and the
demo program holds the private key.
3. The authorization system, which can authorize a service to access another
one, including a person logging into a service. Now all the authorization
requests are granted unconditionally.
4. The naming system, so that Gatekeeper can get the remote access address of
local or remote box.
5. Replay and abuse firewall. Now only a time window is checked.
6. The local root agent to hold the private key of localhost, and sign tickets
(generating username/password) for the client, as is done by the demo program.
7. Proper side channel attack prevention.
8. A lot more...
