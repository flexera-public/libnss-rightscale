/*
 * passwd.c : Functions handling passwd entries retrieval.
 */

#include "nss-rightscale.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Get shadow information using username.
 */

enum nss_status _nss_rightscale_getspnam_r(const char* name, struct spwd *spbuf,
               char *buf, size_t buflen, int *errnop) {
    int res;
    int name_length;
    int pw_length;
    const unsigned char* pw;

    NSS_DEBUG("_nss_rightscale_getspnam_r: looking for user %s (shadow)\n", name);

    res = NSS_STATUS_UNAVAIL;

    return res;
}
