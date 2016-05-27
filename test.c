/* Test script.
 * Compile with: gcc -g test.c -o test shadow.o utils.o passwd.o group.o
 * Run with: ./test scripts/sample_policy 
*/


#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include "nss-rightscale.h"
#undef POLICY_FILE
#define POLICY_FILE "./scripts/sample_policy"

static int nss_errno;
static enum nss_status last_error;
static int total_errors;

static void report_nss_error(const char *who, enum nss_status status) {
  last_error = status;
  total_errors++;
  printf("ERROR %s: NSS_STATUS=%d (nss_errno=%d)\n",
         who, status, nss_errno);
}

static struct passwd *nss_getpwent(void) {
  static struct passwd pwd;
  static char buf[1000];
  enum nss_status status;

  status = _nss_rightscale_getpwent_r(&pwd, buf, sizeof(buf), &nss_errno);
  if (status == NSS_STATUS_NOTFOUND) {
    return NULL;
  }
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("getpwent", status);
    return NULL;
  }
  return &pwd;
}

static struct passwd *nss_getpwnam(const char *name) {
  static struct passwd pwd;
  static char buf[1000];
  enum nss_status status;

  status = _nss_rightscale_getpwnam_r(name, &pwd, buf, sizeof(buf), &nss_errno);
  if (status == NSS_STATUS_NOTFOUND) {
    return NULL;
  }
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("getpwnam", status);
    return NULL;
  }
  return &pwd;
}

static struct passwd *nss_getpwuid(uid_t uid) {
  static struct passwd pwd;
  static char buf[1000];
  enum nss_status status;

  status = _nss_rightscale_getpwuid_r(uid, &pwd, buf, sizeof(buf), &nss_errno);
  if (status == NSS_STATUS_NOTFOUND) {
    return NULL;
  }
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("getpwuid", status);
    return NULL;
  }
  return &pwd;
}

static void nss_setpwent(void) {
  enum nss_status status;

  status = _nss_rightscale_setpwent();
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("setpwent", status);
  }
}

static void nss_endpwent(void) {
  enum nss_status status;

  status = _nss_rightscale_endpwent();
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("endpwent", status);
  }
}

static struct spwd *nss_getspent(void) {
  static struct spwd sp;
  static char buf[1000];
  enum nss_status status;

  status = _nss_rightscale_getspent_r(&sp, buf, sizeof(buf), &nss_errno);
  if (status == NSS_STATUS_NOTFOUND) {
    return NULL;
  }
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("getspent", status);
    return NULL;
  }
  return &sp;
}

static struct spwd *nss_getspnam(const char *name) {
  static struct spwd sp;
  static char buf[1000];
  enum nss_status status;

  status = _nss_rightscale_getspnam_r(name, &sp, buf, sizeof(buf), &nss_errno);
  if (status == NSS_STATUS_NOTFOUND) {
    return NULL;
  }
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("getspnam", status);
    return NULL;
  }
  return &sp;
}

static void nss_setspent(void) {
  enum nss_status status;

  status = _nss_rightscale_setspent();
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("setspent", status);
  }
}

static void nss_endspent(void) {
  enum nss_status status;

  status = _nss_rightscale_endspent();
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("endspent", status);
  }
}


static struct group *nss_getgrent(void) {
  static struct group grp;
  static char *buf;
  static int buflen = 1024;
  enum nss_status status;

  if (!buf)
    buf = (char *)malloc(buflen);

again:
  status = _nss_rightscale_getgrent_r(&grp, buf, buflen, &nss_errno);
  if (status == NSS_STATUS_TRYAGAIN) {
    buflen *= 2;
    buf = (char *)realloc(buf, buflen);
    if (!buf) {
      return NULL;
    }
    goto again;
  }
  if (status == NSS_STATUS_NOTFOUND) {
    free(buf);
    return NULL;
  }
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("getgrent", status);
    free(buf);
    return NULL;
  }
  return &grp;
}

static struct group *nss_getgrnam(const char *name) {
  static struct group grp;
  static char *buf;
  static int buflen = 1000;
  enum nss_status status;

  if (!buf)
    buf = (char *)malloc(buflen);
again:
  status = _nss_rightscale_getgrnam_r(name, &grp, buf, buflen, &nss_errno);
  if (status == NSS_STATUS_TRYAGAIN) {
    buflen *= 2;
    buf = (char *)realloc(buf, buflen);
    if (!buf) {
      return NULL;
    }
    goto again;
  }
  if (status == NSS_STATUS_NOTFOUND) {
    free(buf);
    return NULL;
  }
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("getgrnam", status);
    free(buf);
    return NULL;
  }
  return &grp;
}

static struct group *nss_getgrgid(gid_t gid) {
  static struct group grp;
  static char *buf;
  static int buflen = 1000;
  enum nss_status status;

  if (!buf)
    buf = (char *)malloc(buflen);

again:
  status = _nss_rightscale_getgrgid_r(gid, &grp, buf, buflen, &nss_errno);
  if (status == NSS_STATUS_TRYAGAIN) {
    buflen *= 2;
    buf = (char *)realloc(buf, buflen);
    if (!buf) {
      return NULL;
    }
    goto again;
  }
  if (status == NSS_STATUS_NOTFOUND) {
    free(buf);
    return NULL;
  }
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("getgrgid", status);
    free(buf);
    return NULL;
  }
  return &grp;
}

static void nss_setgrent(void) {
  enum nss_status status;

  status = _nss_rightscale_setgrent();
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("setgrent", status);
  }
}

static void nss_endgrent(void) {
  enum nss_status status;

  status = _nss_rightscale_endgrent();
  if (status != NSS_STATUS_SUCCESS) {
    report_nss_error("endgrent", status);
  }
}

static void print_passwd(struct passwd *pwd) {
  printf("%s:%s:%lu:%lu:%s:%s:%s\n",
         pwd->pw_name,
         pwd->pw_passwd,
         (unsigned long)pwd->pw_uid,
         (unsigned long)pwd->pw_gid,
         pwd->pw_gecos,
         pwd->pw_dir,
         pwd->pw_shell);
}

static void print_spwd(struct spwd *sp) {
  printf("%s:%s:%ld:%ld:%ld:%ld:::\n",
         sp->sp_namp,
         sp->sp_pwdp,
         sp->sp_lstchg,
         sp->sp_min,
         sp->sp_max,
         sp->sp_warn);
}

static void print_group(struct group *grp) {
  int i;
  printf("%s:%s:%lu:",
         grp->gr_name,
         grp->gr_passwd,
         (unsigned long)grp->gr_gid);

  if (!grp->gr_mem[0]) {
    printf("\n");
    return;
  }

  for (i=0; grp->gr_mem[i+1]; i++) {
    printf("%s,", grp->gr_mem[i]);
  }
  printf("%s\n", grp->gr_mem[i]);
}

static void nss_test_users(void) {
  struct passwd *pwd;

  nss_setpwent();
  /* loop over all users */
  while ((pwd = nss_getpwent())) {
    printf("Testing user %s\n", pwd->pw_name);
    printf("  getpwent:   "); print_passwd(pwd);
    pwd = nss_getpwuid(pwd->pw_uid);
    if (!pwd) {
      total_errors++;
      printf("ERROR: can't getpwuid\n");
      continue;
    }
    printf("  getpwuid:   "); print_passwd(pwd);
    pwd = nss_getpwnam(pwd->pw_name);
    if (!pwd) {
      total_errors++;
      printf("ERROR: can't getpwnam\n");
      continue;
    }
    printf("  getpwnam:   "); print_passwd(pwd);
    printf("\n");
  }
  nss_endpwent();
}

static void nss_test_shadow(void) {
  struct spwd *pwd;

  nss_setspent();
  /* loop over all users */
  while ((pwd = nss_getspent())) {
    printf("Testing shadow %s\n", pwd->sp_namp);
    printf("  getspent:   "); print_spwd(pwd);
    pwd = nss_getspnam(pwd->sp_namp);
    if (!pwd) {
      total_errors++;
      printf("ERROR: can't getspnam\n");
      continue;
    }
    printf("  getspnam:   "); print_spwd(pwd);
    printf("\n");
  }
  nss_endspent();
}

static void nss_test_idempotency(void) {
  char first_name[1024];

  // See setgrent/endgrent/getgrent docs for ref.
  printf("Testing group idempotency\n");
  nss_endgrent();
  printf("  getgrent calls setgrent\n");
  struct group *grp = nss_getgrent(); // Should auto-call setgrent for you.
  strcpy(first_name, grp->gr_name);
  printf("  setgrent rewinds to beginning\n");
  nss_setgrent();
  grp = nss_getgrent();
  if (strcmp(grp->gr_name, first_name) != 0) {
    total_errors++;
    printf("  ERROR: setgrent didn't appear to rewind getgrent, %s != %s\n", grp->gr_name, first_name);
  }
  nss_endgrent();
  printf("  endgrent can be called multiple times\n");
  nss_endgrent();
  printf("\n");

  printf("Testing passwd idempotency\n");
  nss_endpwent();
  printf("  getpwent calls setpwent\n");
  struct passwd *pw = nss_getpwent();
  strcpy(first_name, pw->pw_name);
  printf("  setpwent rewinds to beginning\n");
  nss_setpwent();
  pw = nss_getpwent();
  if (strcmp(pw->pw_name, first_name) != 0) {
    total_errors++;
    printf("  ERROR: setpwent didn't appear to rewind getpwent, %s != %s\n", pw->pw_name, first_name);
  }
  nss_endpwent();
  printf("  endpwent can be called multiple times\n");
  nss_endpwent();
  printf("\n");

  printf("Testing shadow idempotency\n");
  nss_endspent();
  printf("  getspent calls setspent\n");
  struct spwd *sp = nss_getspent();
  strcpy(first_name, sp->sp_namp);
  printf("  setspent rewinds to beginning\n");
  nss_setspent();
  sp = nss_getspent();
  if (strcmp(sp->sp_namp, first_name) != 0) {
    total_errors++;
    printf("  ERROR: setspent didn't appear to rewind getspent, %s != %s\n", sp->sp_namp, first_name);
  }
  nss_endspent();
  printf("  endspent can be called multiple times\n");
  nss_endspent();
  printf("\n");
}

static void nss_test_groups(void) {
  struct group *grp;

  nss_setgrent();
  /* loop over all groups */
  while ((grp = nss_getgrent())) {
    printf("Testing group %s\n", grp->gr_name);
    printf("  getgrent: "); print_group(grp);
    grp = nss_getgrnam(grp->gr_name);
    if (!grp) {
      total_errors++;
      printf("ERROR: can't getgrnam\n");
      continue;
    }
    printf("  getgrnam: "); print_group(grp);
    grp = nss_getgrgid(grp->gr_gid);
    if (!grp) {
      total_errors++;
      printf("ERROR: can't getgrgid\n");
      continue;
    }
    printf("  getgrgid: "); print_group(grp);
    printf("\n");
  }
  nss_endgrent();
}

static void nss_test_errors(void) {
  struct passwd *pwd;
  struct group *grp;

  pwd = getpwnam("nosuchname");
  if (pwd || last_error != NSS_STATUS_NOTFOUND) {
    total_errors++;
    printf("ERROR Non existent user gave error %d\n", last_error);
  }

  pwd = getpwuid(909090);
  if (pwd || last_error != NSS_STATUS_NOTFOUND) {
    total_errors++;
    printf("ERROR Non existent uid gave error %d\n", last_error);
  }

  grp = getgrnam("nosuchgroup");
  if (grp || last_error != NSS_STATUS_NOTFOUND) {
    total_errors++;
    printf("ERROR Non existent group gave error %d\n", last_error);
  }

  grp = getgrgid(909090);
  if (grp || last_error != NSS_STATUS_NOTFOUND) {
    total_errors++;
    printf("ERROR Non existent gid gave error %d\n", last_error);
  }
}

 int main(int argc, char *argv[]) {
  printf("Using policy file %s\n", POLICY_FILE);

  nss_test_users();
  nss_test_groups();
  nss_test_shadow();
  nss_test_errors();
  nss_test_idempotency();

  printf("total_errors=%d\n", total_errors);

  return total_errors;
}
