libnss-rightscale
================

ABOUT
-----

This repo contains all the pieces needed to get managed login working with
RightScale-managed Linux cloud instances.

Managed login is built on the top of nss/pam and driven by the contents of
a policy file that RightLink keeps up to date. The policy (about who can
login and who has sudo privileges) is ultimately defined in the RightScale
Cloud Management dashboard. RightLink receives updates whenever someone
changes the policy in the dashboard.

INSTALLATION
------------

```bash
sudo apt-get install -y build-essential autotools-dev autoconf libtool
./bootstrap
./configure
make
sudo make install
```

CONFIGURATION
-------------

Several Linux subsystems must be configured in order for RightScale-
managed login to function correctly.

### 1: Install RightLink

An instance running RightLink 10.5 or newer boots up. This instance
will write a policy file to `/var/lib/rightlink/login_policy` which
contains a list of users, public keys and other metadata.

### 2: Configure NSS

A RightScript (see contrib) will install this nss module to
`/usr/lib/nss_rightscale.so.2`. `/etc/nsswitch.conf` will be modified to
add the "rightscale" module as so:

```
# ...
passwd:         compat rightscale
group:          compat rightscale
shadow:         compat rightscale
# ...
```

### 3: Configure PAM

User home directories will not exist by default. PAM should be instructed to
create them if they don't exist. Add the following
line to `/etc/pam.d/ssh`:

```
# ...
session    required    pam_mkhomedir.so skel=/etc/skel/ umask=0022
# ...
```

### 4: Configure OpenSSH

NSS doesn't know about public keys. OpenSSH defers to NSS for username
validation but has its own system for handling public keys. A helper script
should be added to the system to read and return public keys embedded in
`/var/lib/rightlink/login_policy`. Install `scripts/rs-ssh-keys` to
`/usr/local/bin/rs-ssh-keys` then add the following to `/etc/ssh/sshd_config`:

```
# ...
AuthorizedKeysCommand /usr/local/bin/rs-ssh-keys
AuthorizedKeysCommandUser nobody
# ...
```

### 5: Configure Sudo

All users belong to the "rightscale" group. Users marked with the
server_superuser privilege also belong to the "rightscale_sudo group". Add
this group to `/etc/sudoers/90-rightscale-users`

```
# ...
%rightscale_sudo ALL=NOPASSWD: ALL
Defaults:%rightscale_sudo !requiretty
# ...
```

TEST
----
Run `make test` to run unit tests.

AUTHORS
-------
Peter Schroeter <peter.schroeter@rightscale.com>
Maintained by the RightScale Ivory Team.
