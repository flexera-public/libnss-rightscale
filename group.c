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

/* struct used to store data used by getgrent. */
 static struct {
    int group_count;
    struct group** users;
    int num_users;
} grent_data = { -1, NULL, 0 };

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


/* Reads through the entire policy file and compiles a list of groups. Currently
 * each user gets their own group and also belongs to the rightscale group.
 * Superusers additionally belong to the rightscale_sudo group */
enum nss_status populate_groups(struct group* rs, struct group* rs_sudo) {
    FILE *fp = open_policy_file();
    if (fp == NULL) {
        return NSS_STATUS_UNAVAIL;
    }
    grent_data.group_count = 0;

    if (grent_data.users != NULL) {
        return;
    }
    int num_superusers = 0;
    grent_data.num_users = 0;
    int line_no = 1;
    struct rs_user* entry;
    int rs_size = 16; /* initial size. we'll dynamically reallocate as needed */
    int rs_sudo_size = 16; /* initial size. we'll dynamically reallocate as needed */

    grent_data.users = malloc(sizeof(struct group*)*rs_size);
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
        rs->gr_mem[grent_data.num_users] = malloc(sizeof(char)*(strlen(entry->preferred_name) + 1));
        rs->gr_mem[grent_data.num_users+1] = malloc(sizeof(char)*(strlen(entry->unique_name) + 1));
        strcpy(rs->gr_mem[grent_data.num_users], entry->preferred_name);
        strcpy(rs->gr_mem[grent_data.num_users+1], entry->unique_name);

        grent_data.users[grent_data.num_users] = malloc(sizeof(struct group));
        grent_data.users[grent_data.num_users]->gr_name = rs->gr_mem[grent_data.num_users];
        grent_data.users[grent_data.num_users]->gr_passwd = "x";
        grent_data.users[grent_data.num_users]->gr_gid = entry->local_uid;
        grent_data.users[grent_data.num_users]->gr_mem = malloc(sizeof(char *));
        grent_data.users[grent_data.num_users]->gr_mem[0] = NULL;
        grent_data.users[grent_data.num_users+1] = malloc(sizeof(struct group));
        grent_data.users[grent_data.num_users+1]->gr_name = rs->gr_mem[grent_data.num_users+1];
        grent_data.users[grent_data.num_users+1]->gr_passwd = "x";
        grent_data.users[grent_data.num_users+1]->gr_gid = entry->local_uid;
        grent_data.users[grent_data.num_users+1]->gr_mem = malloc(sizeof(char *));
        grent_data.users[grent_data.num_users+1]->gr_mem[0] = NULL;

        grent_data.num_users += 2;
        if (grent_data.num_users > (rs_size - 2)) {
            rs_size *= 2;
            rs->gr_mem = realloc(rs->gr_mem, rs_size * sizeof(char*));
            grent_data.users = realloc(grent_data.users, rs_size * sizeof(struct group*));
        }

        free_rs_user(entry);
    }
    rs_sudo->gr_mem[num_superusers] = NULL;
    rs->gr_mem[grent_data.num_users] = NULL;

    close_policy_file(fp);

    return NSS_STATUS_SUCCESS;
}

/* Undoes everything done by populate_groups and free's all resources */
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
    if (grent_data.num_users != 0 && grent_data.users != NULL) {
        for(i = 0; i < grent_data.num_users; i++) {
            free(grent_data.users[i]->gr_mem);
            free(grent_data.users[i]);
        }
        free(grent_data.users);
        grent_data.num_users = 0;
        grent_data.users = NULL;
    }

}

/* Setup everything needed to retrieve group entries. */
enum nss_status _nss_rightscale_setgrent() {
    NSS_DEBUG("rightscale setgrent\n");

    enum nss_status res = populate_groups(&rightscale, &rightscale_sudo);
    if (res != NSS_STATUS_SUCCESS) {
        return res;
    }
    grent_data.group_count = 0;

    return NSS_STATUS_SUCCESS;
}

/* Free getgrent resources. */
enum nss_status _nss_rightscale_endgrent() {
    NSS_DEBUG("rightscale endgrent\n");
    grent_data.group_count = -1;
    free_groups(&rightscale, &rightscale_sudo);
    return NSS_STATUS_SUCCESS;
}

/* Return next group entry. */
enum nss_status _nss_rightscale_getgrent_r(struct group *grbuf, char *buf,
            size_t buflen, int *errnop) {

    enum nss_status res;
    NSS_DEBUG("rightscale getgrent_r\n");
    if (grent_data.group_count == -1) {
        res = _nss_rightscale_setgrent();
        if (res != NSS_STATUS_SUCCESS) {
            *errnop = ENOENT;
            return res;
        }
    }

    struct group* target_group;
    if (grent_data.group_count < grent_data.num_users) {
        target_group = grent_data.users[grent_data.group_count];
    } else if (grent_data.group_count == grent_data.num_users) {
        target_group = &rightscale;
    } else if (grent_data.group_count == (grent_data.num_users + 1)) {
        target_group = &rightscale_sudo;
    } else {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    res = fill_group(grbuf, buf, buflen, target_group, errnop);
    /* buffer was long enough this time */
    if(!(res == NSS_STATUS_TRYAGAIN && (*errnop) == ERANGE)) {
        grent_data.group_count += 1;
    }
    return res;
}

/* Get group by name */
enum nss_status _nss_rightscale_getgrnam_r(const char* name, struct group *grbuf,
            char *buf, size_t buflen, int *errnop) {
    enum nss_status res = populate_groups(&rightscale, &rightscale_sudo);
    if (res != NSS_STATUS_SUCCESS) {
        return res;
    }

    NSS_DEBUG("rightscale getgrnam_r: Looking for group %s\n", name);
    if (strcmp(name, rightscale.gr_name) == 0) {
        res = fill_group(grbuf, buf, buflen, &rightscale, errnop);
    } else if (strcmp(name, rightscale_sudo.gr_name) == 0) {
        res = fill_group(grbuf, buf, buflen, &rightscale_sudo, errnop);
    } else {
        int i;
        int found=FALSE;
        for (i = 0; i < grent_data.num_users && !found; i++) {
            if (strcmp(name, grent_data.users[i]->gr_name) == 0) {
                found = TRUE;
                res = fill_group(grbuf, buf, buflen, grent_data.users[i], errnop);
            }
        }
        if (!found) {
            res = NSS_STATUS_NOTFOUND;
            *errnop = ENOENT;
        }
    }
    free_groups(&rightscale, &rightscale_sudo);

    return res;
}

/* Get group by GID. */
enum nss_status _nss_rightscale_getgrgid_r(gid_t gid, struct group *grbuf,
               char *buf, size_t buflen, int *errnop) {
    enum nss_status res = populate_groups(&rightscale, &rightscale_sudo);
    if (res != NSS_STATUS_SUCCESS) {
        return res;
    }

    NSS_DEBUG("rightscale getgrgid_r: Looking for group #%d\n", gid);
    if (gid == rightscale.gr_gid) {
        res = fill_group(grbuf, buf, buflen, &rightscale, errnop);
    } else if (gid == rightscale_sudo.gr_gid) {
        res = fill_group(grbuf, buf, buflen, &rightscale_sudo, errnop);
    } else {
        int i;
        int found=FALSE;
        for (i = 0; i < grent_data.num_users && !found; i++) {
            if (gid == grent_data.users[i]->gr_gid) {
                found = TRUE;
                res = fill_group(grbuf, buf, buflen, grent_data.users[i], errnop);
            }
        }
        if (!found) {
            res = NSS_STATUS_NOTFOUND;
            *errnop = ENOENT;
        }
    }
    free_groups(&rightscale, &rightscale_sudo);

    return res;
}

/* Debugging helper */
void print_group(struct group* entry) {
    NSS_DEBUG("group (%p) gr_name %s gr_mem (%p) gr_gid %d\n",
        entry, entry->gr_name, entry->gr_mem, entry->gr_gid);
}

