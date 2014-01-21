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
Gatekeeper requires libgmp, libpbc and OpenSSL to build.
* https://gmplib.org/
* http://crypto.stanford.edu/pbc/
* http://www.openssl.org/

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
app_81001:x:81001:81000:GATEKEEPER:/home:/bin/sh
app_81002:x:81002:81000:GATEKEEPER:/home:/bin/sh
app_81003:x:81003:81000:GATEKEEPER:/home:/bin/sh
app_81004:x:81004:81000:GATEKEEPER:/home:/bin/sh
app_81005:x:81005:81000:GATEKEEPER:/home:/bin/sh
app_81006:x:81006:81000:GATEKEEPER:/home:/bin/sh
app_81007:x:81007:81000:GATEKEEPER:/home:/bin/sh
app_81008:x:81008:81000:GATEKEEPER:/home:/bin/sh
app_81009:x:81009:81000:GATEKEEPER:/home:/bin/sh
app_81010:x:81010:81000:GATEKEEPER:/home:/bin/sh
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
g_aaak8u1jdi03zflnf9059tqibdsi@127.0.0.1
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
g_aaak8u1jdi03zflnf9059tqibdsl@127.0.0.1
YUHS/.)g0=&YecJR6L~<lV,hQS^s0)2UMzscpgK^4m:H8.)14l_W?PyFEdsF9o05s2kzqJK[
$ ssh g_aaak8u1jdi03zflnf9059tqibdsl@127.0.0.1
g_aaak8u1jdi03zflnf9059tqibdsl@127.0.0.1's password:
Last login: Mon Jan 20 01:22:22 2014 from ::1
$ id
uid=81004(app_81004) gid=81000(gatekeeper) groups=81000(gatekeeper)
$
```

The username/password can be used unlimited times until 120 seconds later.

## That's it?
Well, this project is currently only a demo.

In order to get the full power out of Gatekeeper, read the code and find all
the TODOs. There're quite some now. This is the list of what is missing:

1. The local service list, you see hardcoded app_81001 ~ app_81010 now.
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
