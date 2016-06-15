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
struct group_data {
    int group_counter;
    struct group **users;
    int num_users;
    struct group *rightscale;
    struct group *rightscale_sudo;
};

static struct group_data grent_data = { -1, NULL, 0, NULL, NULL };

/* Reads through the entire policy file and compiles a list of groups. Currently
 * each user gets their own group and also belongs to the rightscale group.
 * Superusers additionally belong to the rightscale_sudo group */
enum nss_status populate_groups(struct group_data *rs_groups) {
    /* Rewind in case setgrent was called again */
    rs_groups->group_counter = 0;

    if (rs_groups->users != NULL) {
        return NSS_STATUS_SUCCESS;
    }
    
    FILE *fp = open_policy_file();
    if (fp == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    int num_superusers = 0;
    rs_groups->num_users = 0;
    int line_no = 1;
    struct rs_user *entry;
    int rs_size = 16; /* initial size. we'll dynamically reallocate as needed */
    int rs_sudo_size = 16; /* initial size. we'll dynamically reallocate as needed */

    rs_groups->users = malloc(sizeof(struct group *)*rs_size);
    rs_groups->rightscale = malloc(sizeof(struct group));
    rs_groups->rightscale->gr_name = "rightscale";
    rs_groups->rightscale->gr_passwd = "x";
    rs_groups->rightscale->gr_gid = 10000;
    rs_groups->rightscale->gr_mem = malloc(sizeof(char *)*rs_size);
    rs_groups->rightscale_sudo = malloc(sizeof(struct group));
    rs_groups->rightscale_sudo->gr_name = "rightscale_sudo";
    rs_groups->rightscale_sudo->gr_passwd = "x";
    rs_groups->rightscale_sudo->gr_gid = 10001;
    rs_groups->rightscale_sudo->gr_mem = malloc(sizeof(char *)*rs_sudo_size);

    // All users are part of the rightscale group.
    // Only superusers are also part of the rightscale_sudo group.
    while (entry = read_next_policy_entry(fp, &line_no)) {
        if (entry->superuser == TRUE) {
            if (strlen(entry->preferred_name) != 0 && strcmp(entry->preferred_name, entry->unique_name) != 0) {
                rs_groups->rightscale_sudo->gr_mem[num_superusers] =
                    malloc(sizeof(char)*(strlen(entry->preferred_name) + 1));
                strcpy(rs_groups->rightscale_sudo->gr_mem[num_superusers], entry->preferred_name);
                num_superusers += 1;
            }
            rs_groups->rightscale_sudo->gr_mem[num_superusers] =
                malloc(sizeof(char)*(strlen(entry->unique_name) + 1));
            strcpy(rs_groups->rightscale_sudo->gr_mem[num_superusers], entry->unique_name);
            num_superusers += 1;
            if (num_superusers > (rs_sudo_size - 2)) {
                rs_sudo_size *= 2;
                rs_groups->rightscale_sudo->gr_mem = realloc(rs_groups->rightscale_sudo->gr_mem, rs_sudo_size * sizeof(char *));
            }
        }
        if (strlen(entry->preferred_name) != 0 && strcmp(entry->preferred_name, entry->unique_name) != 0) {
            rs_groups->rightscale->gr_mem[rs_groups->num_users] = malloc(sizeof(char)*(strlen(entry->preferred_name) + 1));
            strcpy(rs_groups->rightscale->gr_mem[rs_groups->num_users], entry->preferred_name);
            rs_groups->users[rs_groups->num_users] = malloc(sizeof(struct group));
            rs_groups->users[rs_groups->num_users]->gr_name = rs_groups->rightscale->gr_mem[rs_groups->num_users];
            rs_groups->users[rs_groups->num_users]->gr_passwd = "x";
            rs_groups->users[rs_groups->num_users]->gr_gid = entry->local_uid;
            rs_groups->users[rs_groups->num_users]->gr_mem = malloc(sizeof(char *));
            rs_groups->users[rs_groups->num_users]->gr_mem[0] = NULL;
            rs_groups->num_users += 1;
        }
        rs_groups->rightscale->gr_mem[rs_groups->num_users] = malloc(sizeof(char)*(strlen(entry->unique_name) + 1));
        strcpy(rs_groups->rightscale->gr_mem[rs_groups->num_users], entry->unique_name);
        rs_groups->users[rs_groups->num_users] = malloc(sizeof(struct group));
        rs_groups->users[rs_groups->num_users]->gr_name = rs_groups->rightscale->gr_mem[rs_groups->num_users];
        rs_groups->users[rs_groups->num_users]->gr_passwd = "x";
        rs_groups->users[rs_groups->num_users]->gr_gid = entry->local_uid;
        rs_groups->users[rs_groups->num_users]->gr_mem = malloc(sizeof(char *));
        rs_groups->users[rs_groups->num_users]->gr_mem[0] = NULL;
        rs_groups->num_users += 1;

        if (rs_groups->num_users > (rs_size - 2)) {
            rs_size *= 2;
            rs_groups->rightscale->gr_mem = realloc(rs_groups->rightscale->gr_mem, rs_size * sizeof(char *));
            rs_groups->users = realloc(rs_groups->users, rs_size * sizeof(struct group *));
        }

        free_rs_user(entry);
    }
    rs_groups->rightscale_sudo->gr_mem[num_superusers] = NULL;
    rs_groups->rightscale->gr_mem[rs_groups->num_users] = NULL;

    close_policy_file(fp);

    return NSS_STATUS_SUCCESS;
}

/* Undoes everything done by populate_groups and free's all resources */
void free_groups(struct group_data *rs_groups) {
    int i;
    rs_groups->group_counter = -1;
    if (rs_groups->rightscale_sudo != NULL) {
        for(i = 0; rs_groups->rightscale_sudo->gr_mem[i] != NULL; i++) {
            free(rs_groups->rightscale_sudo->gr_mem[i]);
        }
        free(rs_groups->rightscale_sudo->gr_mem);
        free(rs_groups->rightscale_sudo);
        rs_groups->rightscale_sudo = NULL;

    }
    if (rs_groups->rightscale != NULL) {
        for(i = 0; rs_groups->rightscale->gr_mem[i] != NULL; i++) {
            free(rs_groups->rightscale->gr_mem[i]);
        }
        free(rs_groups->rightscale->gr_mem);
        free(rs_groups->rightscale);
        rs_groups->rightscale = NULL;
    }
    if (rs_groups->users != NULL) {
        for(i = 0; i < rs_groups->num_users; i++) {
            free(rs_groups->users[i]->gr_mem);
            free(rs_groups->users[i]);
        }
        free(rs_groups->users);
        rs_groups->num_users = 0;
        rs_groups->users = NULL;
    }

}

/* Setup everything needed to retrieve group entries. */
enum nss_status _nss_rightscale_setgrent() {
    NSS_DEBUG("rightscale setgrent\n");

    enum nss_status res = populate_groups(&grent_data);
    if (res != NSS_STATUS_SUCCESS) {
        return res;
    }

    return NSS_STATUS_SUCCESS;
}

/* Free getgrent resources. */
enum nss_status _nss_rightscale_endgrent() {
    NSS_DEBUG("rightscale endgrent\n");
    free_groups(&grent_data);
    return NSS_STATUS_SUCCESS;
}

/* Return next group entry. */
enum nss_status _nss_rightscale_getgrent_r(struct group *grbuf, char *buf,
            size_t buflen, int *errnop) {

    enum nss_status res;
    NSS_DEBUG("rightscale getgrent_r\n");
    if (grent_data.group_counter == -1) {
        res = _nss_rightscale_setgrent();
        if (res != NSS_STATUS_SUCCESS) {
            *errnop = ENOENT;
            return res;
        }
    }

    struct group *target_group;
    if (grent_data.group_counter < grent_data.num_users) {
        target_group = grent_data.users[grent_data.group_counter];
    } else if (grent_data.group_counter == grent_data.num_users) {
        target_group = grent_data.rightscale;
    } else if (grent_data.group_counter == (grent_data.num_users + 1)) {
        target_group = grent_data.rightscale_sudo;
    } else {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    res = fill_group(grbuf, buf, buflen, target_group, errnop);
    /* buffer was long enough this time */
    if(!(res == NSS_STATUS_TRYAGAIN && (*errnop) == ERANGE)) {
        grent_data.group_counter += 1;
    }
    return res;
}

/* Get group by name */
enum nss_status _nss_rightscale_getgrnam_r(const char *name, struct group *grbuf,
            char *buf, size_t buflen, int *errnop) {

    struct group_data rs_groups = { -1, NULL, 0, NULL, NULL };
    enum nss_status res = populate_groups(&rs_groups);
    if (res != NSS_STATUS_SUCCESS) {
        return res;
    }

    NSS_DEBUG("rightscale getgrnam_r: Looking for group %s\n", name);
    if (strcmp(name, rs_groups.rightscale->gr_name) == 0) {
        res = fill_group(grbuf, buf, buflen, rs_groups.rightscale, errnop);
    } else if (strcmp(name, rs_groups.rightscale_sudo->gr_name) == 0) {
        res = fill_group(grbuf, buf, buflen, rs_groups.rightscale_sudo, errnop);
    } else {
        int i;
        int found=FALSE;
        for (i = 0; i < rs_groups.num_users && !found; i++) {
            if (strcmp(name, rs_groups.users[i]->gr_name) == 0) {
                found = TRUE;
                res = fill_group(grbuf, buf, buflen, rs_groups.users[i], errnop);
            }
        }
        if (!found) {
            res = NSS_STATUS_NOTFOUND;
            *errnop = ENOENT;
        }
    }
    free_groups(&rs_groups);

    return res;
}

/* Get group by GID. */
enum nss_status _nss_rightscale_getgrgid_r(gid_t gid, struct group *grbuf,
               char *buf, size_t buflen, int *errnop) {

    struct group_data rs_groups = { -1, NULL, 0, NULL, NULL };
    enum nss_status res = populate_groups(&rs_groups);
    if (res != NSS_STATUS_SUCCESS) {
        return res;
    }

    NSS_DEBUG("rightscale getgrgid_r: Looking for group #%d\n", gid);
    if (gid == rs_groups.rightscale->gr_gid) {
        res = fill_group(grbuf, buf, buflen, rs_groups.rightscale, errnop);
    } else if (gid == rs_groups.rightscale_sudo->gr_gid) {
        res = fill_group(grbuf, buf, buflen, rs_groups.rightscale_sudo, errnop);
    } else {
        int i;
        int found=FALSE;
        for (i = 0; i < rs_groups.num_users && !found; i++) {
            if (gid == rs_groups.users[i]->gr_gid) {
                found = TRUE;
                res = fill_group(grbuf, buf, buflen, rs_groups.users[i], errnop);
            }
        }
        if (!found) {
            res = NSS_STATUS_NOTFOUND;
            *errnop = ENOENT;
        }
    }
    free_groups(&rs_groups);

    return res;
}

/* Debugging helper */
void print_group(struct group *entry) {
    NSS_DEBUG("group (%p) gr_name %s gr_mem (%p) gr_gid %d\n",
        entry, entry->gr_name, entry->gr_mem, entry->gr_gid);
}
