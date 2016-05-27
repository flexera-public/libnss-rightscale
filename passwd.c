/*
 * passwd.c : Functions handling passwd entries retrieval.
 */

#include "nss-rightscale.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>


/* struct used to store data used by getpwent. */
static struct {
    FILE* fp;
    int line_no;
    int entry_seen_count;
} pwent_data = { NULL, 1, 0 };

/* Setup everything needed to retrieve passwd entries. */
enum nss_status _nss_rightscale_setpwent() {
    NSS_DEBUG("rightscale setpwent\n");
    if (pwent_data.fp == NULL) {
        pwent_data.fp = open_policy_file();
        if (pwent_data.fp == NULL) {
            return NSS_STATUS_UNAVAIL;
        }
    } else {
      rewind(pwent_data.fp);
    }
    pwent_data.line_no = 1;
    pwent_data.entry_seen_count = 0;
    return NSS_STATUS_SUCCESS;
}

/* Free getpwent resources. */
enum nss_status _nss_rightscale_endpwent() {
    NSS_DEBUG("rightscale endpwent\n");
    if (pwent_data.fp != NULL) {
        close_policy_file(pwent_data.fp);
        pwent_data.fp = NULL;
    }
    return NSS_STATUS_SUCCESS;
}

/* Reentrant return next passwd entry. */
enum nss_status _nss_rightscale_getpwent_r(struct passwd *pwbuf, char *buf, size_t buflen, int *errnop) {

    enum nss_status res;
    NSS_DEBUG("rightscale getpwent_r\n");
    if (pwent_data.fp == NULL) {
        res = _nss_rightscale_setpwent();
        if (res != NSS_STATUS_SUCCESS) {
            *errnop = ENOENT;
            return res;
        }
    }

    int previous_line_no = pwent_data.line_no;
    fpos_t previous_pos;
    fgetpos(pwent_data.fp, &previous_pos);
    struct rs_user* entry;

    entry = read_next_policy_entry(pwent_data.fp, &pwent_data.line_no);

    if (entry == NULL) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    int use_preferred = TRUE;
    if (pwent_data.entry_seen_count == 1) {
        use_preferred = FALSE;
    }
    res = fill_passwd(pwbuf, buf, buflen, entry, use_preferred, errnop);
    free_rs_user(entry);
    // Rewind and re-read the current entry
    if(res == NSS_STATUS_TRYAGAIN && (*errnop) == ERANGE) {
        pwent_data.line_no = previous_line_no;
        fsetpos(pwent_data.fp, &previous_pos);
    } else {
        if (pwent_data.entry_seen_count == 0) {
            pwent_data.line_no = previous_line_no;
            fsetpos(pwent_data.fp, &previous_pos);
            pwent_data.entry_seen_count += 1;
        } else {
            pwent_data.entry_seen_count = 0;
        }
    }
    return res;

}

/* Get user info by username. */
enum nss_status _nss_rightscale_getpwnam_r(const char* name, struct passwd *pwbuf,
            char *buf, size_t buflen, int *errnop) {
    enum nss_status res;
    struct rs_user* entry;

    NSS_DEBUG("rightscale getpwnam_r: Looking for user %s\n", name);

    FILE *fp = open_policy_file();
    if (fp == NULL) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    int found = FALSE;
    int line_no = 1;
    while ((entry = read_next_policy_entry(fp, &line_no)) && !found) {
        if (strcmp(entry->preferred_name, name) == 0) {
            found = TRUE;
            res = fill_passwd(pwbuf, buf, buflen, entry, TRUE, errnop);
        } else if (strcmp(entry->unique_name, name) == 0) {
            found = TRUE;
            res = fill_passwd(pwbuf, buf, buflen, entry, FALSE, errnop);
        }
        free_rs_user(entry);
    }

    /* We've gotten to the end of file without finding anything */
    if (!found) {
        res = NSS_STATUS_NOTFOUND;
        *errnop = ENOENT;
    }

    close_policy_file(fp);
    return res;
}

/* Get user by UID. */
enum nss_status _nss_rightscale_getpwuid_r(uid_t uid, struct passwd *pwbuf,
               char *buf, size_t buflen, int *errnop) {
    enum nss_status res;
    struct rs_user* entry;

    NSS_DEBUG("rightscale getpwuid_r: Looking for uid %d\n", uid);

    FILE *fp = open_policy_file();
    if (fp == NULL) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    int found = FALSE;
    int line_no = 1;
    while ((entry = read_next_policy_entry(fp, &line_no)) && !found) {
        if (entry->local_uid == uid) {
            found = TRUE;
            res = fill_passwd(pwbuf, buf, buflen, entry, TRUE, errnop);
        }

        free_rs_user(entry);
    }

    /* We've gotten to the end of file without finding anything */
    if (!found) {
        res = NSS_STATUS_NOTFOUND;
        *errnop = ENOENT;
    }

    close_policy_file(fp);
    return res;
}
