#ifndef NSS_RIGHTSCALE_UTILS_H
#define NSS_RIGHTSCALE_UTILS_H

#include <grp.h>
#include <pwd.h>

/* Read and parse entries from the RightScale policy file */
FILE* open_policy_file();
void close_policy_file(FILE *fp);
struct passwd* read_next_policy_entry(FILE*, int*);
enum nss_status fill_passwd(struct passwd*, char*, size_t, struct passwd*, int*);
enum nss_status fill_group(struct group*, char*, size_t, struct group*, int*);
void free_passwd(struct passwd*);

#endif
