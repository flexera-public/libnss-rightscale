/*
 * Copyright (C) 2007, Sébastien Le Ray
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * passwd.c : Functions handling passwd entries retrieval.
 */

#include "nss-socket.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

/**
 * Setup everything needed to retrieve passwd entries.
 */
enum nss_status _nss_socket_setpwent(void) {
    NSS_DEBUG("Initializing pw functions\n");
    return NSS_STATUS_SUCCESS;
}

/*
 * Free getpwent resources.
 */
enum nss_status _nss_socket_endpwent(void) {
    NSS_DEBUG("Finishing pw functions\n");
    return NSS_STATUS_SUCCESS;
}

/*
 * Return next passwd entry.
 * Not implemeted yet.
 */

enum nss_status
_nss_socket_getpwent_r(struct passwd *pwbuf, char *buf,
                      size_t buflen, int *errnop) {
    NSS_DEBUG("Getting next pw entry\n");
    return NSS_STATUS_UNAVAIL;
}

/**
 * Get user info by username.
 */

enum nss_status _nss_socket_getpwnam_r(const char* name, struct passwd *pwbuf,
               char *buf, size_t buflen, int *errnop)
{
    enum nss_status res;
    int fd;

    NSS_DEBUG("getpwnam_r: Looking for user %s\n", name);

    res = open_passwd(&fd, errnop);
    if(res != NSS_STATUS_SUCCESS) return res;
    res = write_getpwnam(fd, name, errnop);
    if(res != NSS_STATUS_SUCCESS) return res;
    res = read_getpwnam(fd, pwbuf, buf, buflen, errnop);
    close_passwd(fd);

    return res;
}

/*
 * Get user by UID.
 */

enum nss_status _nss_socket_getpwuid_r(uid_t uid, struct passwd *pwbuf,
               char *buf, size_t buflen, int *errnop) {
    int res;
    int fd;

    NSS_DEBUG("getpwuid_r: looking for user #%d\n", uid);

    res = open_passwd(&fd, errnop);
    if(res != NSS_STATUS_SUCCESS) return res;
    res = write_getpwuid(fd, uid, errnop);
    if(res != NSS_STATUS_SUCCESS) return res;
    res = read_getpwuid(fd, pwbuf, buf, buflen, errnop);
    close_passwd(fd);

    return res;
}

