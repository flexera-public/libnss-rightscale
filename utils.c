/*
 * utils.c : Some utility functions.
 */

#include "nss-rightscale.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <string.h>
#include <shadow.h>
#include <sys/un.h>

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

/* This must be longer than any single line in the policy file */
#define BUF_SIZE 4096


FILE* open_policy_file()
{
    /* Create input file descriptor */
    FILE* fp = fopen(POLICY_FILE, "r");
    if (fp == NULL) {
        NSS_DEBUG("Cannot open policy file %s\n", POLICY_FILE);
    }
    return fp;
}

/* Reads the next policy entry into the passed in struct.
 * Its up to the caller to free everything in the passwd struct.
 * Valid policy entry line is:
 * preferred_name:unique_name:rs_uid:local_uid:superuser:gecos:public_key1:public_key2:..."
 */ 
struct rs_user* read_next_policy_entry(FILE* fp, int* line_no) {
    char rawentry[BUF_SIZE];
    char *name, *gecos, *unique_name, *preferred_name;
    uid_t rs_uid = 0;
    uid_t local_uid = 0;
    int superuser = -1;
    const char *delimiters = ":";

    int entry_valid = FALSE;
    while (!entry_valid) {
        if( fgets (rawentry, BUF_SIZE, fp) == NULL ) {
            return NULL;
        }
        *line_no += 1;

        if (strlen(rawentry) < 2) {
            continue;
        }
        char *rawentryp = rawentry;

        preferred_name  = strsep(&rawentryp, delimiters);
        unique_name  = strsep(&rawentryp, delimiters);
        char *rs_uid_s = strsep(&rawentryp, delimiters);
        char *local_uid_s = strsep(&rawentryp, delimiters);
        if (local_uid_s != NULL) { sscanf(local_uid_s, "%d", &local_uid); }
        if (rs_uid_s != NULL) { sscanf(rs_uid_s, "%d", &rs_uid); }
        char *superuser_s = strsep(&rawentryp, delimiters);
        if (superuser_s != NULL) {
            if (strcmp(superuser_s, "1") == 0 || strcmp(superuser_s, "Y") == 0) {
                superuser = TRUE;
            } else if (strcmp(superuser_s, "0") == 0 || strcmp(superuser_s, "N") == 0) {
                superuser = FALSE;
            }
        }

        gecos = strsep(&rawentryp, delimiters);

        if (preferred_name != NULL && unique_name != NULL && gecos != NULL &&
            superuser != -1 && rs_uid > 500 && local_uid > 500) {
            entry_valid = TRUE;
        } else {
            NSS_DEBUG("%s:%d: Invalid format\n", POLICY_FILE, *line_no - 1);
        }
    }

    struct rs_user* entry = malloc(sizeof(struct rs_user));

    entry->preferred_name = malloc(sizeof(char)*(strlen(preferred_name) + 1));
    strcpy(entry->preferred_name, preferred_name);

    entry->unique_name = malloc(sizeof(char)*(strlen(unique_name) + 1));
    strcpy(entry->unique_name, unique_name);

    entry->gecos = malloc(sizeof(char)*(strlen(gecos) + 1));
    strcpy(entry->gecos, gecos);

    entry->rs_uid = rs_uid;
    entry->local_uid = local_uid;
    entry->superuser = superuser;

    return entry;
}


void close_policy_file(FILE* fp) {
    fclose(fp);
}

/*
 * Fill an user struct using given information.
 * @param pwbuf Struct which will be filled with various info.
 * @param buf Buffer which will contain all strings pointed to by pwbuf.
 * @param buflen Buffer length.
 * @param entry Source struct populated from policy file.
 * @param use_preferred Boolean -- whether to fill the name with preferred or unique name.
 * @param errnop Pointer to errno, will be filled if something goes wrong.
 */
enum nss_status fill_passwd(struct passwd* pwbuf, char* buf, size_t buflen,
    struct rs_user* entry, int use_preferred, int* errnop) {
    char *passwd = "x";
    char *shell = "/bin/bash";
    char *name;

    int total_length = 0;

    if (use_preferred == TRUE) {
        name = entry->preferred_name;
    } else {
        name = entry->unique_name;
    }
    int name_length = strlen(name);
    total_length += name_length + 1;
    int preferred_name_length = strlen(entry->preferred_name);
    total_length += preferred_name_length + 7; // For pw_dir aka homedir
    int passwd_length = strlen(passwd);
    total_length += passwd_length + 1;
    int gecos_length = strlen(entry->gecos);
    total_length += gecos_length + 1;
    int shell_length = strlen(shell);
    total_length += shell_length + 1;

    if(buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    pwbuf->pw_uid = entry->local_uid;
    pwbuf->pw_gid = entry->local_uid;

    strcpy(buf, name);
    pwbuf->pw_name = buf;
    buf += name_length + 1;

    sprintf(buf, "/home/%s", entry->preferred_name);
    pwbuf->pw_dir = buf;
    buf += preferred_name_length + 7;

    strcpy(buf, passwd);
    pwbuf->pw_passwd = buf;
    buf += passwd_length + 1;

    strcpy(buf, shell);
    pwbuf->pw_shell = buf;
    buf += shell_length + 1;

    strcpy(buf, entry->gecos);
    pwbuf->pw_gecos = buf;
    buf += gecos_length + 1;

    return NSS_STATUS_SUCCESS;
}

/*
 * Fill an user struct using given information.
 * @param spbuf Struct which will be filled with various info.
 * @param buf Buffer which will contain all strings pointed to by pwbuf.
 * @param buflen Buffer length.
 * @param entry Source struct populated from policy file.
 * @param use_preferred Boolean -- whether to fill the name with preferred or unique name.
 * @param errnop Pointer to errno, will be filled if something goes wrong.
 */
enum nss_status fill_spwd(struct spwd* spbuf, char* buf, size_t buflen,
    struct rs_user* entry, int use_preferred, int* errnop) {
    char *name;
    char *passwd = "*";
    int total_length = 0;

    if (use_preferred == TRUE) {
        name = entry->preferred_name;
    } else {
        name = entry->unique_name;
    }

    int name_length = strlen(name);
    total_length += name_length + 1;

    int passwd_length = strlen(passwd);
    total_length += passwd_length + 1;

    if(buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    spbuf->sp_warn = 7;
    /* Follow fields should not be populated and will be set as follows:
    spbuf->sp_lstchg = nil; Days since password last changed. nil if feature isn't used.
    spbuf->sp_inact = nil; Days after password expiration acct is valid. nil = forever.
    spbuf->sp_min = 0; Min days to password change
    spbuf->sp_max = 99999; Max days to password change
    spbuf->sp_expire = nil; Password never expires
    spbuf->sp_flag = nil; Reserved for future use
    */

    strcpy(buf, name);
    spbuf->sp_namp = buf;
    buf += name_length + 1;

    strcpy(buf, passwd);
    spbuf->sp_pwdp = buf;
    buf += passwd_length + 1;

    return NSS_STATUS_SUCCESS;
}

void free_rs_user(struct rs_user* entry) {
    free(entry->preferred_name);
    free(entry->unique_name);
    free(entry->gecos);
    free(entry);
}

void print_rs_user(struct rs_user* entry) {
    NSS_DEBUG("rs_user (%p) preferred_name %s unique_name %s gecos %s rs_uid %d local_uid %d\n",
        entry, entry->preferred_name, entry->unique_name, entry->gecos, entry->rs_uid, entry->local_uid);
}


/*
 * Fill an group struct using given information.
 * @param grbuf Struct which will be filled with various info.
 * @param buf Buffer which will contain all strings pointed to by grbuf.
 * @param buflen Buffer length.
 * @param entry Source struct populated from policy file.
 * @param errnop Pointer to errno, will be filled if something goes wrong.
 */
enum nss_status fill_group(struct group* grbuf, char* buf, size_t buflen,
    struct group* entry, int* errnop) {

    int total_length = 0;

    char **gr_memp = entry->gr_mem;

    int i;
    for (i = 0; gr_memp[i] != NULL; i++) {
        total_length += strlen(gr_memp[i]) + 1;
    }

    int name_length = strlen(entry->gr_name);
    total_length += name_length + 1;

    int passwd_length = strlen(entry->gr_passwd);
    total_length += passwd_length + 1;

    /* Calculate number of extra bytes needed to align on pointer size boundry */
    /* Should always be 0 */
    int offset = 0;
    if ((offset = (unsigned long)(buf) % sizeof(char*)) != 0)
        offset = sizeof(char*) - offset;
    total_length += offset;

    // The pointers to group members are in buf also!. The array is null terminated, hence the + 1
    total_length += sizeof(char *) * (i + 1);

    if(buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    grbuf->gr_gid = entry->gr_gid;

    buf += offset;
    grbuf->gr_mem = (char **)(buf);

    buf +=  sizeof(char *) * (i + 1);

    gr_memp = entry->gr_mem;
    for (i = 0; gr_memp[i] != NULL; i++) {
        strcpy(buf, gr_memp[i]);
        grbuf->gr_mem[i] = buf;
        buf += strlen(gr_memp[i]) + 1;
    }
    grbuf->gr_mem[i] = NULL; /* Null terminated list */


    strcpy(buf, entry->gr_name);
    grbuf->gr_name = buf;
    buf += name_length + 1;

    strcpy(buf, entry->gr_passwd);
    grbuf->gr_passwd = buf;
    buf += passwd_length + 1;

    return NSS_STATUS_SUCCESS;
}

