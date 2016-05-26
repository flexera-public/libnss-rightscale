#ifndef NSS_RIGHTSCALE_H
#define NSS_RIGHTSCALE_H

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
/* #error You must use autotools to build this! */
#endif

#include <nss.h>
#include <stdio.h>
#include <pwd.h>

/* Print debug messages. Only to stdout for now */
#ifdef DEBUG
#define NSS_DEBUG(msg, ...) printf((msg), ## __VA_ARGS__)
#else
#define NSS_DEBUG(msg, ...)
#endif

#define FALSE 0
#define TRUE !FALSE

/* Struct defining an entry in the /var/lib/rightlink/login_policy file */
struct rs_user {
    char *preferred_name; /* Preferred login name. May not be stable over time */
    char *unique_name;    /* Unique login name */
    uid_t rs_uid;         /* RightScale UID (mysql primary key) */
    uid_t local_uid;      /* Local UID, typically Rightscale UID + offset (10000) */
    char *gecos;          /* gecos, which is email address currently */
    int superuser;        /* Whether the username is a superuser or not */
};

#endif
