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
#include <grp.h>
#include <pwd.h>
#include <shadow.h>

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

enum nss_status _nss_rightscale_setpwent();
enum nss_status _nss_rightscale_endpwent();
enum nss_status _nss_rightscale_getpwent_r(struct passwd *, char *, size_t, int *);
enum nss_status _nss_rightscale_getpwnam_r(const char *, struct passwd *, char *, size_t, int *);
enum nss_status _nss_rightscale_getpwuid_r(uid_t, struct passwd *, char *, size_t, int *);

enum nss_status _nss_rightscale_setspent();
enum nss_status _nss_rightscale_endspent();
enum nss_status _nss_rightscale_getspent_r(struct spwd *, char *, size_t, int *);
enum nss_status _nss_rightscale_getspnam_r(const char *, struct spwd *, char *, size_t, int *);

enum nss_status _nss_rightscale_setgrent();
enum nss_status _nss_rightscale_endgrent();
enum nss_status _nss_rightscale_getgrent_r(struct group *, char *, size_t, int *);
enum nss_status _nss_rightscale_getgrnam_r(const char *, struct group *, char *, size_t, int *);
enum nss_status _nss_rightscale_getgruid_r(uid_t, struct group *, char *, size_t, int *);

#endif
