/*
 * shadow.c : Functions handling shadow entries retrieval.
 */

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "nss-rightscale.h"
#include "utils.h"

/*
 * Get shadow information using username.
 */

/*
 * struct used to store data used by getpwent.
 */
static struct {
    FILE* fp;
    int line_no;
    int entry_seen_count;
} spent_data = { NULL, 1, 0 };


/**
 * Setup everything needed to retrieve shadow entries.
 */
enum nss_status _nss_rightscale_setspent() {
    NSS_DEBUG("rightscale setspent\n");
    if (spent_data.fp == NULL) {
        spent_data.fp = open_policy_file();
        if (spent_data.fp == NULL) {
            return NSS_STATUS_UNAVAIL;
        }
    } else {
      rewind(spent_data.fp);
    }
    spent_data.line_no = 1;
    spent_data.entry_seen_count = 0;
    return NSS_STATUS_SUCCESS;
}

/*
 * Free getspent resources.
 */
enum nss_status _nss_rightscale_endspent() {
    NSS_DEBUG("rightscale endspent\n");
    if (spent_data.fp != NULL) {
        close_policy_file(spent_data.fp);
        spent_data.fp = NULL;
    }
    return NSS_STATUS_SUCCESS;
}


/*
 * Return next shadow entry.
 */
enum nss_status _nss_rightscale_getspent_r(struct spwd *spbuf, char *buf,
            size_t buflen, int *errnop) {

    int res;
    enum nss_status set_status;
    NSS_DEBUG("rightscale getspent_r\n");
    if (spent_data.fp == NULL) {
        set_status = _nss_rightscale_setspent();
        if (set_status != NSS_STATUS_SUCCESS) {
            *errnop = ENOENT;
            return set_status;
        }
    }

    int previous_line_no = spent_data.line_no;
    fpos_t previous_pos;
    fgetpos(spent_data.fp, &previous_pos);
    struct rs_user* entry;

    entry = read_next_policy_entry(spent_data.fp, &spent_data.line_no);

    if (entry == NULL) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    int use_preferred = TRUE;
    if (strlen(entry->preferred_name) == 0 || strcmp(entry->preferred_name, entry->unique_name) == 0) {
        spent_data.entry_seen_count = 1;
    }
    if (spent_data.entry_seen_count == 1) {
        use_preferred = FALSE;
    }

    res = fill_spwd(spbuf, buf, buflen, entry, use_preferred, errnop);
    free_rs_user(entry);
    // Rewind and re-read the current entry
    if(res == NSS_STATUS_TRYAGAIN && (*errnop) == ERANGE) {
        spent_data.line_no = previous_line_no;
        fsetpos(spent_data.fp, &previous_pos);
    } else {
        if (spent_data.entry_seen_count == 0) {
            spent_data.line_no = previous_line_no;
            fsetpos(spent_data.fp, &previous_pos);
            spent_data.entry_seen_count += 1;
        } else {
            spent_data.entry_seen_count = 0;
        }
    }
    return res;

}

/**
 * Get shadow info by username.
 */
enum nss_status _nss_rightscale_getspnam_r(const char* name, struct spwd *spbuf,
            char *buf, size_t buflen, int *errnop) {
    int res;
    struct rs_user* entry;

    NSS_DEBUG("rightscale getspnam_r: Looking for user %s\n", name);

    FILE *fp = open_policy_file();
    if (fp == NULL) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    int found = FALSE;
    int line_no = 1;
    while (entry = read_next_policy_entry(fp, &line_no)) {
        if (strcmp(entry->preferred_name, name) == 0 &&
          strlen(entry->preferred_name) != 0 &&
          strcmp(entry->preferred_name, entry->unique_name) != 0) {
            found = TRUE;
            res = fill_spwd(spbuf, buf, buflen, entry, TRUE, errnop);
            break;
        } else if (strcmp(entry->unique_name, name) == 0) {
            found = TRUE;
            res = fill_spwd(spbuf, buf, buflen, entry, FALSE, errnop);
            break;
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
