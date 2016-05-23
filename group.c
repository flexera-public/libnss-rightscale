/*
 * group.c : Functions handling group entries retrieval.
 */

#include "nss-rightscale.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

/*
 * struct used to store data used by getgrent.
 */
static group_count = -1;

static struct group rightscale = {
    gr_name: "rightscale",
    gr_passwd: "x",
    gr_gid: 10000,
    gr_mem: (char **)NULL
};

static struct group rightscale_sudo = {
    gr_name: "rightscale_sudo",
    gr_passwd: "x",
    gr_gid: 10001,
    gr_mem: (char **)NULL
};

enum nss_status populate_groups(struct group* rs, struct group* rs_sudo) {
    FILE *fp = open_policy_file();
    if (fp == NULL) {
        return NSS_STATUS_UNAVAIL;
    }
    int superuser_index = 0;
    int user_index = 0;
    int line_no = 1;
    struct passwd* entry;

    group_count = 0;
    rs->gr_mem = malloc(sizeof(char*)*100);
    rs_sudo->gr_mem = malloc(sizeof(char*)*100);

    // All users are part of the rightscale group.
    // Only superusers are also part of the rightscale_sudo group.
    while (entry = read_next_policy_entry(fp, &line_no)) {
        if (entry->pw_gid == rs_sudo->gr_gid) {
            rs_sudo->gr_mem[superuser_index] = malloc(sizeof(char)*(strlen(entry->pw_name) + 1));
            strcpy(rs_sudo->gr_mem[superuser_index], entry->pw_name);
            superuser_index++;
        }
        rs->gr_mem[user_index] = malloc(sizeof(char)*(strlen(entry->pw_name) + 1));
        strcpy(rs->gr_mem[user_index], entry->pw_name);
        user_index++;

        free_passwd(entry);
    }
    rs_sudo->gr_mem[superuser_index] = NULL;
    rs->gr_mem[user_index] = NULL;

    close_policy_file(fp);

    return NSS_STATUS_SUCCESS;
}

void free_groups(struct group* rs, struct group* rs_sudo) {
    int i;
    if (rs_sudo->gr_mem != NULL) {
        for(i = 0; rs_sudo->gr_mem[i] != NULL; i++) {
            free(rs_sudo->gr_mem[i]);
        }
        free(rs_sudo->gr_mem);
        rs_sudo->gr_mem = NULL;

    }
    if (rs->gr_mem != NULL) {
        for(i = 0; rs->gr_mem[i] != NULL; i++) {
            free(rs->gr_mem[i]);
        }
        free(rs->gr_mem);
        rs->gr_mem = NULL;
    }
}

/**
 * Setup everything needed to retrieve group entries.
 */
enum nss_status _nss_rightscale_setgrent() {
    NSS_DEBUG("rightscale setgrent\n");

    int res = populate_groups(&rightscale, &rightscale_sudo);
    if (res != NSS_STATUS_SUCCESS) {
        return res;
    }
    group_count = 0;

    return NSS_STATUS_SUCCESS;
}

/*
 * Free getgrent resources.
 */
enum nss_status _nss_rightscale_endgrent() {
    NSS_DEBUG("rightscale endgrent\n");
    group_count = -1;
    free_groups(&rightscale, &rightscale_sudo);
    return NSS_STATUS_SUCCESS;
}

/*
 * Return next group entry.
 */
enum nss_status _nss_rightscale_getgrent_r(struct group *grbuf, char *buf,
            size_t buflen, int *errnop) {

    int res;
    enum nss_status set_status;
    NSS_DEBUG("rightscale getgrent_r\n");
    if (group_count == -1) {
        set_status = _nss_rightscale_setgrent();
        if (set_status != NSS_STATUS_SUCCESS) {
            *errnop = ENOENT;
            return set_status;
        }
    }

    struct group* target_group;
    if (group_count == 0) {
        target_group = &rightscale;
    } else if (group_count == 1) {
        target_group = &rightscale_sudo;
    } else {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    res = fill_group(grbuf, buf, buflen, target_group, errnop);
    /* buffer was long enough this time */
    if(!(res == NSS_STATUS_TRYAGAIN && (*errnop) == ERANGE)) {
        group_count += 1;
    }
    return res;
}

/**
 * Get group by name
 */
enum nss_status _nss_rightscale_getgrnam_r(const char* name, struct group *grbuf,
            char *buf, size_t buflen, int *errnop) {
    int res;
    populate_groups(&rightscale, &rightscale_sudo);

    NSS_DEBUG("rightscale getgrnam_r: Looking for group %s\n", name);
    if (strcmp(name, rightscale.gr_name) == 0) {
        res = fill_group(grbuf, buf, buflen, &rightscale, errnop);
    } else if (strcmp(name, rightscale_sudo.gr_name) == 0) {
        res = fill_group(grbuf, buf, buflen, &rightscale_sudo, errnop);
    } else {
        res = NSS_STATUS_NOTFOUND;
        *errnop = ENOENT;
    }
    free_groups(&rightscale, &rightscale_sudo);

    return res;
}

/*
 * Get group by GID.
 */
enum nss_status _nss_rightscale_getgrgid_r(gid_t gid, struct group *grbuf,
               char *buf, size_t buflen, int *errnop) {
    int res;
    populate_groups(&rightscale, &rightscale_sudo);

    NSS_DEBUG("rightscale getgrgid_r: Looking for group #%d\n", gid);
    if (gid == rightscale.gr_gid) {
        res = fill_group(grbuf, buf, buflen, &rightscale, errnop);
    } else if (gid == rightscale_sudo.gr_gid) {
        res = fill_group(grbuf, buf, buflen, &rightscale_sudo, errnop);
    } else {
        res = NSS_STATUS_NOTFOUND;
        *errnop = ENOENT;
    }
    free_groups(&rightscale, &rightscale_sudo);

    return res;
}
