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

#ifndef NSS_SOCKET_UTILS_H
#define NSS_SOCKET_UTILS_H

#include <grp.h>
#include <pwd.h>

int check_security_passwd(const char*);

enum nss_status open_passwd(int*, int*);
enum nss_status write_getpwnam(int, const char*, int*);
enum nss_status read_getpwnam(int, struct passwd*, char*, size_t, int*);
enum nss_status write_getpwuid(int, uid_t, int*);
enum nss_status read_getpwuid(int, struct passwd*, char*, size_t, int*);
void close_passwd(int);

enum nss_status fill_passwd(struct passwd*, char*, size_t, const char*,
    const char*, uid_t, gid_t, const char*, const char*, const char*, int*);

#endif
