/*-
 * Copyright (c) 2008 Chris Reinhardt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $MidnightBSD: src/libexec/mport.delete/mport.delete.c,v 1.2 2008/01/05 22:29:14 ctriv Exp $
 */



#include <sys/cdefs.h>
__MBSDID("$MidnightBSD: src/libexec/mport.delete/mport.delete.c,v 1.2 2008/01/05 22:29:14 ctriv Exp $");


#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <mport.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>

static void usage(void);
static int check_fake(mportPlist *, const char *, const char *, const char *);
static int grep_file(const char *, const char *);


int main(int argc, char *argv[]) 
{
  int ch, ret;
  const char *skip = NULL;
  mportPlist *plist;
  FILE *fp;
  
  while ((ch = getopt(argc, argv, "s:")) != -1) {
    switch (ch) {
      case 's':
        skip = optarg;
        break;
      case '?':
      default:
        usage();
        break; 
    }
  } 

  argc -= optind;
  argv += optind;

  warnx("argc: %i", argc);

  warnx("argv[0] = %s; argv[1] = %s; argv[2] = %s; argv[3] = %s", argv[0], argv[1], argv[2], argv[3]);

  if (argc != 3) 
    usage();
  
  if ((fp = fopen(argv[0], "r")) == NULL)
    err(EX_NOINPUT, "Could not open plist file %s", argv[1]);
      
  if ((plist = mport_plist_new()) == NULL) 
    err(EX_OSERR, "Could not not allocate plist");
  
  if (mport_plist_parsefile(fp, plist) != MPORT_OK)
    err(EX_DATAERR, "Invalid plist");

  warnx("running check_fake");  
  
  printf("Checking %s\n", argv[1]);
  ret = check_fake(plist, argv[1], argv[2], skip);
  
  if (ret == 0) {
    printf("Fake succeeded.\n");
  } else {
    printf("Fake failed.\n");
  }
  
  mport_plist_free(plist);
  
  return ret;
}

static int check_fake(mportPlist *plist, const char *destdir, const char *prefix, const char *skip)
{
  mportPlistEntry *e;
  char cwd[FILENAME_MAX], file[FILENAME_MAX];
  char *anchored_skip;
  struct stat st;
  regex_t *skipre;
  int ret = 0;

  warnx("checking skip: %s", skip);
    
  if (skip != NULL) {
    warnx("Compiling skip: %s", skip);
    if (asprintf(&anchored_skip, "^%s$", skip) == -1)
      err(EX_OSERR, "Could not build skip regex");
  
    if (regcomp(skipre, skip, REG_EXTENDED|REG_NOSUB) != 0)
      errx(EX_DATAERR, "Could not compile skip regex");
  }
  
  warnx("Coping prefix (%s) to cwd", prefix);
  
  (void)strlcpy(cwd, prefix, FILENAME_MAX);

  warnx("Starting loop, cwd: %s", cwd);
  
  STAILQ_FOREACH(e, plist, next) {
    if (e->type == PLIST_CWD) {
        if (e->data == NULL) {
          warnx("Setting cwd to '%s'", prefix);
          (void)strlcpy(cwd, prefix, FILENAME_MAX);
        } else {
          warnx("Setting cwd to '%s'", e->data);
          (void)strlcpy(cwd, e->data, FILENAME_MAX);
        }
        
        break;
    }
    
    if (e->type != PLIST_FILE)
      continue;
    
    (void)snprintf(file, FILENAME_MAX, "%s%s/%s", destdir, cwd, e->data);

    warnx("checking %s", file);
      
    if (lstat(file, &st) != 0) {
      (void)snprintf(file, FILENAME_MAX, "%s/%s", cwd, e->data);
      
      if (lstat(file, &st) == 0) {
        (void)printf("    %s installed in %s\n", e->data, cwd);
      } else {
        (void)printf("    %s not installed.\n", e->data);
      }
      
      ret = 1;
      continue;
    }
    
    if (S_ISLNK(st.st_mode))
      continue;  /* skip symlinks */


    /* if file matches skip continue */
    if (skip != NULL && (regexec(skipre, e->data, 0, NULL, 0) == 0))
      continue;      
    
    /* grep file for fake destdir */
    if (grep_file(file, destdir)) {
      (void)printf("    %s contains the fake destdir", e->data);
      ret = 1;
    }
  }
  
  if (skip != NULL)
    regfree(skipre);
  
  return ret;
} 
      

static int grep_file(const char *file, const char *destdir)
{
  if (file || destdir)
    return 0;
}
      
static void usage() 
{
  errx(EX_USAGE, "Usage: mport.delete [-s skip] plist destdir prefix");
  exit(EX_USAGE);
}


