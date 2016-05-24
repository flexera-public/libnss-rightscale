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
static int group_count = -1;
static int num_users = 0;

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

static struct group** users = NULL;

enum nss_status populate_groups(struct group* rs, struct group* rs_sudo) {
    FILE *fp = open_policy_file();
    if (fp == NULL) {
        return NSS_STATUS_UNAVAIL;
    }
    group_count = 0;

    if (users != NULL) {
        return;
    }
    int num_superusers = 0;
    num_users = 0;
    int line_no = 1;
    struct rs_user* entry;
    int rs_size = 16; /* initialize size. we'll dynamically reallocate as needed */
    int rs_sudo_size = 16; /* initialize size. we'll dynamically reallocate as needed */

    users = malloc(sizeof(struct group*)*rs_size);
    rs->gr_mem = malloc(sizeof(char*)*rs_size);
    rs_sudo->gr_mem = malloc(sizeof(char*)*rs_sudo_size);

    // All users are part of the rightscale group.
    // Only superusers are also part of the rightscale_sudo group.
    while (entry = read_next_policy_entry(fp, &line_no)) {
        if (entry->superuser == TRUE) {
            rs_sudo->gr_mem[num_superusers] = malloc(sizeof(char)*(strlen(entry->preferred_name) + 1));
            rs_sudo->gr_mem[num_superusers+1] = malloc(sizeof(char)*(strlen(entry->unique_name) + 1));
            strcpy(rs_sudo->gr_mem[num_superusers], entry->preferred_name);
            strcpy(rs_sudo->gr_mem[num_superusers+1], entry->unique_name);
            num_superusers += 2;
            if (num_superusers > (rs_sudo_size - 2)) {
                rs_sudo_size *= 2;
                rs_sudo->gr_mem = realloc(rs_sudo->gr_mem, rs_sudo_size * sizeof(char*));
            }
        }
        rs->gr_mem[num_users] = malloc(sizeof(char)*(strlen(entry->preferred_name) + 1));
        rs->gr_mem[num_users+1] = malloc(sizeof(char)*(strlen(entry->unique_name) + 1));
        strcpy(rs->gr_mem[num_users], entry->preferred_name);
        strcpy(rs->gr_mem[num_users+1], entry->unique_name);

        users[num_users] = malloc(sizeof(struct group));
        users[num_users]->gr_name = rs->gr_mem[num_users];
        users[num_users]->gr_passwd = "x";
        users[num_users]->gr_gid = entry->local_uid;
        users[num_users]->gr_mem = malloc(sizeof(char *));
        users[num_users]->gr_mem[0] = NULL;
        users[num_users+1] = malloc(sizeof(struct group));
        users[num_users+1]->gr_name = rs->gr_mem[num_users+1];
        users[num_users+1]->gr_passwd = "x";
        users[num_users+1]->gr_gid = entry->local_uid;
        users[num_users+1]->gr_mem = malloc(sizeof(char *));
        users[num_users+1]->gr_mem[0] = NULL;

// print_group(users[num_users]);
// print_group(users[num_users+1]);

        num_users += 2;
        if (num_users > (rs_size - 2)) {
            rs_size *= 2;
            rs->gr_mem = realloc(rs->gr_mem, rs_size * sizeof(char*));
            users = realloc(users, rs_size * sizeof(struct group*));
        }

        free_rs_user(entry);
    }
    rs_sudo->gr_mem[num_superusers] = NULL;
    rs->gr_mem[num_users] = NULL;

//    NSS_DEBUG("Num users: %d superusers %d\n", num_users, num_superusers);

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
    if (num_users != 0 && users != NULL) {
        for(i = 0; i < num_users; i++) {
            free(users[i]->gr_mem);
            free(users[i]);
        }
        free(users);
        num_users = 0;
        users = NULL;
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
    if (group_count < num_users) {
        target_group = users[group_count];
    } else if (group_count == num_users) {
        target_group = &rightscale;
    } else if (group_count == (num_users + 1)) {
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

void print_group(struct group* entry) {
    NSS_DEBUG("group (%p) gr_name %s gr_mem (%p) gr_gid %d\n",
        entry, entry->gr_name, entry->gr_mem, entry->gr_gid);
}

