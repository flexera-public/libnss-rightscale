/*
 * utils.c : Some utility functions.
 */

#include "nss-rightscale.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <string.h>
#include <sys/un.h>

#include <stdio.h>
// #include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

/* This must be longer than any single line in the policy file */
#define BUF_SIZE 4096
static const char *POLICY_FILE = "/var/lib/rightlink/login_policy";

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
 * Valid policy entry line is "username:uid:gid:gecos:public_key1:public_key2:..."
 */ 
struct passwd* read_next_policy_entry(FILE* fp, int* line_no) {
    char rawentry[BUF_SIZE];
    char *name;
    char *gecos;
    char *passwd = "x";
    char *shell = "/bin/bash";
    int uid = 0;
    int gid = 0;
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

        name  = strsep(&rawentryp, delimiters);
        char *uid_s = strsep(&rawentryp, delimiters);
        char *gid_s = strsep(&rawentryp, delimiters);
        if (uid_s != NULL) { sscanf(uid_s, "%d", &uid); }
        if (gid_s != NULL) { sscanf(gid_s, "%d", &gid); }
        gecos = strsep(&rawentryp, delimiters);

        if (name != NULL && gecos != NULL && uid > 0 && gid > 0) {
            entry_valid = TRUE;
        } else {
            NSS_DEBUG("%s:%d: Invalid format\n", POLICY_FILE, *line_no - 1);
        }
    }

    struct passwd* entry = malloc(sizeof(struct passwd));
    entry->pw_name = malloc(sizeof(char)*(strlen(name) + 1));
    strcpy(entry->pw_name, name);
    entry->pw_dir = malloc(sizeof(char)*(strlen(name) + 7));
    sprintf(entry->pw_dir, "/home/%s", name);

    entry->pw_gecos = malloc(sizeof(char)*(strlen(gecos) + 1));
    strcpy(entry->pw_gecos, gecos);
    
    entry->pw_shell = malloc(sizeof(char)*(strlen(shell) + 1));
    strcpy(entry->pw_shell, shell);

    entry->pw_passwd = malloc(sizeof(char)*(strlen(passwd) + 1));
    strcpy(entry->pw_passwd, passwd);

    entry->pw_uid = uid;
    entry->pw_gid = gid;

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
 * @param errnop Pointer to errno, will be filled if something goes wrong.
 */
enum nss_status fill_passwd(struct passwd* pwbuf, char* buf, size_t buflen,
    struct passwd* entry, int* errnop) {
    int total_length = 0;
    int name_length     = strlen(entry->pw_name);
    total_length += name_length + 1;
    int passwd_length   = strlen(entry->pw_passwd); 
    total_length += passwd_length + 1;
    int dir_length      = strlen(entry->pw_dir);
    total_length += dir_length + 1;
    int gecos_length    = strlen(entry->pw_gecos);
    total_length += gecos_length + 1;
    int shell_length    = strlen(entry->pw_shell);
    total_length += shell_length + 1;

    if(buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    pwbuf->pw_uid = entry->pw_uid;
    pwbuf->pw_gid = entry->pw_gid;

    strcpy(buf, entry->pw_name);
    pwbuf->pw_name = buf;
    buf += name_length + 1;

    strcpy(buf, entry->pw_passwd);
    pwbuf->pw_passwd = buf;
    buf += passwd_length + 1;

    strcpy(buf, entry->pw_shell);
    pwbuf->pw_shell = buf;
    buf += shell_length + 1;

    strcpy(buf, entry->pw_dir);
    pwbuf->pw_dir = buf;
    buf += dir_length + 1;

    strcpy(buf, entry->pw_gecos);
    pwbuf->pw_gecos = buf;
    buf += gecos_length + 1;

    return NSS_STATUS_SUCCESS;
}

void free_passwd(struct passwd* entry) {
    free(entry->pw_name);
    free(entry->pw_gecos);
    free(entry->pw_passwd);
    free(entry->pw_shell);
    free(entry->pw_dir);
    free(entry);
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

