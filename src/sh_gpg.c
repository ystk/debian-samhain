/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000 Rainer Wichmann                                */
/*                                                                         */
/*  This program is free software; you can redistribute it                 */
/*  and/or modify                                                          */
/*  it under the terms of the GNU General Public License as                */
/*  published by                                                           */
/*  the Free Software Foundation; either version 2 of the License, or      */
/*  (at your option) any later version.                                    */
/*                                                                         */
/*  This program is distributed in the hope that it will be useful,        */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of         */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          */
/*  GNU General Public License for more details.                           */
/*                                                                         */
/*  You should have received a copy of the GNU General Public License      */
/*  along with this program; if not, write to the Free Software            */
/*  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.              */

#include "config_xor.h"

#include <stdio.h>
#include <stdlib.h>


#if defined(WITH_GPG) || defined(WITH_PGP)

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#if defined(SH_WITH_SERVER)
#include <pwd.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/wait.h>

#include <string.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif


#if !defined(O_NONBLOCK)
#if defined(O_NDELAY)
#define O_NONBLOCK  O_NDELAY
#else
#define O_NONBLOCK  0
#endif
#endif


#include "samhain.h"
#include "sh_utils.h"
#include "sh_error.h"
#include "sh_tiger.h"
#if defined(SH_WITH_SERVER)
#define SH_NEED_PWD_GRP 1
#include "sh_static.h"
#endif

static struct {
  char     conf_id[SH_MINIBUF+1];
  char     conf_fp[SH_MINIBUF+1];
  char     data_id[SH_MINIBUF+1];
  char     data_fp[SH_MINIBUF+1];
} gp;

typedef struct {
  pid_t    pid;
  FILE   * pipe;
} sh_gpg_popen_t;

#define SH_GPG_OK      0
#define SH_GPG_BAD     1
#define SH_GPG_BADSIGN 2

/* replace #if 0 by #if 1 and set an appropriate path in front of '/pdbg.'
 * for debugging
 */
#if 0
#define PDGBFILE "/pdbg."
#endif

#if defined(PDGBFILE)
FILE * pdbg;
FILE * pdbgc;
#define PDBG_OPEN    pdbg = fopen(PDGBFILE"main",  "a")  
#define PDBG_CLOSE   sl_fclose (FIL__, __LINE__, pdbg)
#define PDBG(arg)    fprintf(pdbg,  "PDBG: step %d\n", arg); fflush(pdbg)
#define PDBG_D(arg)  fprintf(pdbg,  "PDBG: %d\n", arg); fflush(pdbg)
#define PDBG_S(arg)  fprintf(pdbg,  "PDBG: %s\n", arg); fflush(pdbg)

#define PDBGC_OPEN   pdbgc = fopen(PDGBFILE"child", "a")  
#define PDBGC_CLOSE  sl_fclose (FIL__, __LINE__, pdbgc)
#define PDBGC(arg)   fprintf(pdbgc, "PDBG: step %d\n", arg); fflush(pdbgc)
#define PDBGC_D(arg) fprintf(pdbgc, "PDBG: %d\n", arg); fflush(pdbgc)
#define PDBGC_S(arg) fprintf(pdbgc, "PDBG: %s\n", arg); fflush(pdbgc)
#else
#define PDBG_OPEN    
#define PDBG_CLOSE   
#define PDBG(arg)    
#define PDBG_D(arg)  
#define PDBG_S(arg)  
#define PDBGC_OPEN    
#define PDBGC_CLOSE   
#define PDBGC(arg)    
#define PDBGC_D(arg)  
#define PDBGC_S(arg)  
#endif

#undef  FIL__
#define FIL__  _("sh_gpg.c")

#ifdef GPG_HASH

static int sh_gpg_checksum (SL_TICKET checkfd, int flag)
{
  char * test_gpg;
  char * test_ptr1 = NULL;
  char * test_ptr2 = NULL;
  char   wstrip1[128];
  char   wstrip2[128];
  int    i, k;
#include "sh_gpg_chksum.h"

  SL_ENTER(_("sh_gpg_checksum"));

#if defined(WITH_PGP)
  test_gpg = sh_tiger_hash_gpg (DEFAULT_PGP_PATH, checkfd, TIGER_NOLIM);
#else
  test_gpg = sh_tiger_hash_gpg (DEFAULT_GPG_PATH, checkfd, TIGER_NOLIM);
#endif
  
  test_ptr1 = strchr(GPG_HASH, ':');
  if (test_gpg != NULL)
    test_ptr2 = strchr(test_gpg, ':');
  
  if (test_ptr2 != NULL)
    test_ptr2 += 2;
  else
    test_ptr2 = test_gpg;
  if (test_ptr1 != NULL)
    test_ptr1 += 2;
  else
    test_ptr1 = GPG_HASH;

  /* Tue Jun 24 23:11:54 CEST 2003 (1.7.9) -- strip whitespace
   */
  k = 0;
  for (i = 0; i < 127; ++i)
    {
      if (test_ptr1[i] == '\0')
	break;
      if (test_ptr1[i] != ' ')
	{
	  wstrip1[k] = test_ptr1[i];
	  ++k;
	}
    }
  wstrip1[k] = '\0';

  for(i = 0; i < KEY_LEN; ++i)
    {
      if (gpgchk[i] != wstrip1[i]) 
	{
	  sh_error_handle(SH_ERR_SEVERE, FIL__, __LINE__, 0, MSG_E_GPG_CHK, 
			  gpgchk, wstrip1);
	  break;
	}
    }

  k = 0;
  if (test_ptr2)
    {
      for (i = 0; i < 127; ++i)
	{
	  if (test_ptr2[i] == '\0')
	    break;
	  if (test_ptr2[i] != ' ')
	    {
	      wstrip2[k] = test_ptr2[i];
	      ++k;
	    }
	}
    }
  wstrip2[k] = '\0';

  if (0 != sl_strncmp(wstrip1, wstrip2, 127))
    {
      TPT(((0), FIL__, __LINE__, _("msg=<pgp checksum: %s>\n"), test_gpg));
      TPT(((0), FIL__, __LINE__, _("msg=<Compiled-in : %s>\n"), GPG_HASH));
      TPT(((0), FIL__, __LINE__, _("msg=<wstrip1     : %s>\n"), wstrip1));
      TPT(((0), FIL__, __LINE__, _("msg=<wstrip2     : %s>\n"), wstrip2));
      if (flag == 1)
	sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_GPG, 
			GPG_HASH, test_gpg);
      dlog(1, FIL__, __LINE__, _("The compiled-in checksum of the gpg binary\n(%s)\ndoes not match the actual checksum\n(%s).\nYou need to recompile with the correct checksum."), wstrip1, wstrip2);
      SH_FREE(test_gpg);
      SL_RETURN((-1), _("sh_gpg_checksum"));
    }
  SH_FREE(test_gpg);
  SL_RETURN( (0), _("sh_gpg_checksum"));
}
#endif

struct startup_info {
  long   line;
  char * program;
  long   uid;
  char * path;
  char * key_uid;
  char * key_id;
};

static struct startup_info startInfo = { 0, NULL, 0, NULL, NULL, NULL };

void sh_gpg_log_startup (void)
{
  if (startInfo.program != NULL)
    {
      sh_error_handle ((-1), FIL__, startInfo.line, 0, MSG_START_GH,
		       startInfo.program, startInfo.uid,
		       startInfo.path,
		       startInfo.key_uid, startInfo.key_id);
    }
  return;
}

static void sh_gpg_fill_startup (long line, char * program, long uid, char * path, 
				 char * key_uid, char * key_id)
{
  startInfo.line    = line;
  startInfo.program = sh_util_strdup(program);
  startInfo.uid     = uid;
  startInfo.path    = sh_util_strdup(path);
  startInfo.key_uid = sh_util_strdup(key_uid);
  startInfo.key_id  = sh_util_strdup(key_id);
  return;
}

static FILE * sh_gpg_popen (sh_gpg_popen_t  *source, int fd, 
			    int mode, char * id, char * homedir)
{
  extern int flag_err_debug;
  int pipedes[2];
  FILE * outf = NULL;
  char * envp[2];
  size_t len;
  char   path[256];
  char   cc1[32];
  char   cc2[32];
#if defined(WITH_PGP)
  char   cc3[32];
  char   cc0[3] = "-f";
#endif
#if defined(WITH_GPG)
  char   cc0[2] = "-";
  char   cc3[32];
  char   cc4[SH_PATHBUF+32];
  char   cc5[32];
#endif

  char * arg[9];

#if defined(HAVE_GPG_CHECKSUM)
  SL_TICKET   checkfd = -1;
  int         myrand;
  int         i;
#if defined(__linux__)
  int         get_the_fd(SL_TICKET);
  char        pname[128];
  int         pfd;
  int         val_return;
#endif
#endif

  SL_ENTER(_("sh_gpg_popen"));

#if defined(WITH_GPG)
  /* -- GnuPG -- */
  sl_strlcpy (path,  DEFAULT_GPG_PATH,  256);
  sl_strlcpy (cc1,   _("--status-fd"),  32);
  sl_strlcpy (cc2,   _("--verify"),     32);
  sl_strlcpy (cc3,   _("--homedir"),    32);
  /* sl_strlcpy (cc4,   sh.effective.home, SH_PATHBUF+32); */
  sl_strlcpy (cc4,   homedir,           SH_PATHBUF+32);
  sl_strlcat (cc4,   _("/.gnupg"),      SH_PATHBUF+32);
  sl_strlcpy (cc5,   _("--no-tty"),     32);

  /* fprintf(stderr, "YULE: homedir=%s\n", homedir); */

#if defined(SH_WITH_SERVER)
  if (0 == sl_ret_euid())   /* privileges not dropped yet */
    {
      struct stat lbuf;
      int         status_stat = 0;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      struct passwd    pwd;
      char          *  buffer = SH_ALLOC(SH_PWBUF_SIZE);
      struct passwd *  tempres;
      sh_getpwnam_r(DEFAULT_IDENT, &pwd, buffer, SH_PWBUF_SIZE, &tempres);
#else
      struct passwd * tempres = sh_getpwnam(DEFAULT_IDENT);
#endif

      if (!tempres)
	{
	  dlog(1, FIL__, __LINE__, 
	       _("User %s does not exist. Please add the user to your system.\n"), 
	       DEFAULT_IDENT);
	  status_stat = -1;
	}
      if (!tempres->pw_dir || tempres->pw_dir[0] == '\0')
	{
	  dlog(1, FIL__, __LINE__, 
	       _("User %s does not have a home directory.\nPlease add the home directory for this user to your system.\n"), 
	       DEFAULT_IDENT);
	  status_stat = -2;
	}
      if (status_stat == 0)
	{
	  sl_strlcpy (cc4, tempres->pw_dir, SH_PATHBUF+32); 
	  sl_strlcat (cc4,   _("/.gnupg"),      SH_PATHBUF+32); 
	  status_stat =  retry_lstat(FIL__, __LINE__, cc4, &lbuf);
	  if (status_stat == -1)
	    {
	      dlog(1, FIL__, __LINE__, 
		   _("Gnupg directory %s for user %s\ndoes not exist or is not accessible.\nPlease add the directory and put the keyring (pubring.gpg) there\nto verify the configuration file.\n"),
		   cc4, DEFAULT_IDENT);
	      status_stat = -3;
	    }
	}
      if (status_stat == 0 && lbuf.st_uid != tempres->pw_uid)
	{
	  dlog(1, FIL__, __LINE__, 
	       _("Gnupg directory %s\nis not owned by user %s.\n"), 
	       cc4, DEFAULT_IDENT);
	  status_stat = -4;
	}
      if (status_stat == 0)
	{
	  sl_strlcat (cc4,   _("/pubring.gpg"),      SH_PATHBUF+32); 
	  status_stat =  retry_lstat(FIL__, __LINE__, cc4, &lbuf);
	  if (status_stat == -1)
	    {
	      dlog(1, FIL__, __LINE__, 
		   _("Gnupg public keyring %s for user %s\ndoes not exist or is not accessible.\nPlease add the directory and put the keyring (pubring.gpg) there\nto verify the configuration file.\n"),
		   cc4, DEFAULT_IDENT);
	      status_stat = -5;
	    }
	}
      if (status_stat == 0 && lbuf.st_uid != tempres->pw_uid)
	{
	  dlog(1, FIL__, __LINE__, 
	       _("Gnupg public keyring %s\nis not owned by user %s.\n"), 
	       cc4, DEFAULT_IDENT);
	  status_stat = -6;
	}
      if (status_stat != 0)
	{
	  sh_error_handle((-1), FIL__, __LINE__, status_stat, MSG_EXIT_ABORT1, 
			  sh.prg_name);
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}
      sl_strlcpy (cc4, tempres->pw_dir, SH_PATHBUF+32); 
      sl_strlcat (cc4,   _("/.gnupg"),      SH_PATHBUF+32); 
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      SH_FREE(buffer);
#endif
    }
#endif

  arg[0] = path; 
  arg[1] = cc1;
  arg[2] = "1";
  arg[3] = cc2;
  arg[4] = cc3;
  arg[5] = cc4;
  arg[6] = cc5;
  arg[7] = cc0;
  arg[8] = NULL;

  /* catch 'unused parameter' compiler warning
   */
  (void) mode;
  (void) id;
#elif defined(WITH_PGP)
  /* -- PGP -- */
  sl_strlcpy (path,  DEFAULT_PGP_PATH, 256);
  if (mode == 0)
    {
      sl_strlcpy (cc1,   _("+language=en"),  32);
      sl_strlcpy (cc2,   _("-o"),     32);
      sl_strlcpy (cc3,   _("/dev/null"),     32);
      
      arg[0] = path; 
      arg[1] = cc1;
      arg[2] = cc2; 
      arg[3] = cc3; 
      arg[4] = cc0;
      arg[5] = NULL;
    }
  else
    {
      sl_strlcpy (cc1,   _("+language=en"),  32);
      sl_strlcpy (cc2,   _("-kvc"),     32);       
      
      arg[0] = path; 
      arg[1] = cc1;
      arg[2] = cc2;
      arg[3] = id;
      arg[4] = NULL;
      arg[5] = NULL;
    }
#endif

  /* use homedir of effective user
   */
  if (sh.effective.home != NULL)
    {
      len = sl_strlen(sh.effective.home) + 6;
      envp[0] = malloc (len); /* free() ok   */
      if (envp[0] != NULL)
	sl_snprintf (envp[0], len, _("HOME=%s"), sh.effective.home); 
      envp[1] = NULL;
    }
  else
    {
      envp[0] = NULL;
    }

  /* Create the pipe 
   */
  if (aud_pipe(FIL__, __LINE__, pipedes) < 0) 
    {
      if (envp[0] != NULL) 
	free(envp[0]);
      SL_RETURN( (NULL), _("sh_gpg_popen"));
    }

  fflush (NULL);
  
  source->pid = aud_fork(FIL__, __LINE__);
  
  /* Failure
   */
  if (source->pid == (pid_t) - 1) 
    {
      sl_close_fd(FIL__, __LINE__, pipedes[0]);
      sl_close_fd(FIL__, __LINE__, pipedes[1]);
      if (envp[0] != NULL) 
	free(envp[0]);
      SL_RETURN( (NULL), _("sh_gpg_popen"));
    }

  if (source->pid == (pid_t) 0) 
    {

      /* child - make read side of the pipe stdout 
       */
      if (retry_aud_dup2(FIL__, __LINE__,
			pipedes[STDOUT_FILENO], STDOUT_FILENO) < 0)
	{
	  TPT(((0), FIL__, __LINE__, _("msg=<dup2 on pipe failed>\n")));
	  dlog(1, FIL__, __LINE__, _("Internal error: dup2 failed\n"));
	  aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	}
      
      /* close the pipe descriptors 
       */
      sl_close_fd (FIL__, __LINE__, pipedes[STDIN_FILENO]);
      sl_close_fd (FIL__, __LINE__, pipedes[STDOUT_FILENO]);
      

#if defined(WITH_PGP)
      if (mode == 0) 
	{
	  if (retry_aud_dup2(FIL__, __LINE__, fd, STDIN_FILENO) < 0)
	    {
	      TPT(((0), FIL__, __LINE__, _("msg=<dup2 on fd failed>\n")));
	      dlog(1, FIL__, __LINE__, _("Internal error: dup2 failed\n"));
	      aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	    }
	}
#else
      if (retry_aud_dup2(FIL__, __LINE__, fd, STDIN_FILENO) < 0)
	{
	  TPT(((0), FIL__, __LINE__, _("msg=<dup2 on fd failed>\n")));
	  dlog(1, FIL__, __LINE__, _("Internal error: dup2 failed\n"));
	  aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	}
#endif
 
      /* don't leak file descriptors
       */
      sh_unix_closeall (3, -1, SL_TRUE); /* in child process */

      if (flag_err_debug != SL_TRUE)
	{
	  if (NULL == freopen(_("/dev/null"), "r+", stderr))
	    {
	      dlog(1, FIL__, __LINE__, _("Internal error: freopen failed\n"));
	      aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	    }
	}


      /* We should become privileged if SUID,
       * to be able to read the keyring.
       * We have checked that gpg is OK,
       * AND that only a trusted user could overwrite
       * gpg.
       */
      memset (skey, '\0', sizeof(sh_key_t));
      aud_setuid(FIL__, __LINE__, geteuid());
      
      PDBGC_OPEN;
      PDBGC_D((int)getuid());
      PDBGC_D((int)geteuid());

      {
	int i = 0;
	while (arg[i] != NULL)
	  {
	    PDBGC_S(arg[i]);
	    ++i;
	  }
      }
      PDBGC_CLOSE;

      /* exec the program */

#if defined(__linux__) && defined(HAVE_GPG_CHECKSUM)
      /* 
       * --  emulate an fexecve with checksum testing
       */
#if defined(WITH_PGP)
      checkfd = sl_open_read(FIL__, __LINE__, DEFAULT_PGP_PATH, SL_NOPRIV);
#else
      checkfd = sl_open_read(FIL__, __LINE__, DEFAULT_GPG_PATH, SL_NOPRIV);
#endif

      if (0 != sh_gpg_checksum(checkfd, 0))
	{
	  sl_close(checkfd);
	  aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	}

      pfd = get_the_fd(checkfd);
      do {
	val_return = dup (pfd);
      } while (val_return < 0 && errno == EINTR);
      pfd = val_return;
      sl_close(checkfd);
      /* checkfd = -1; *//* never read */

      sl_snprintf(pname, sizeof(pname), _("/proc/self/fd/%d"), pfd);
      if (0 == access(pname, R_OK|X_OK))               /* flawfinder: ignore */

	{
	  fcntl  (pfd, F_SETFD, FD_CLOEXEC);
	  retry_aud_execve (FIL__, __LINE__,  pname, arg, envp);
	      
	  dlog(1, FIL__, __LINE__, _("Unexpected error: execve %s failed\n"),
	       pname);
	  /* failed 
	   */
	  aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	}
	  
      /* procfs not working, go ahead 
       */
#endif

#if defined(HAVE_GPG_CHECKSUM)
      /* This is an incredibly ugly kludge to prevent an attacker
       * from knowing when it is safe to slip in a fake executable
       * between the integrity check and the execve
       */
      myrand = (int) taus_get ();

      myrand = (myrand < 0) ? (-myrand) : myrand;
      myrand = (myrand % 32) + 2;

      for (i = 0; i < myrand; ++i)
	{
#if defined(WITH_PGP)
	  checkfd = sl_open_fastread(FIL__, __LINE__, DEFAULT_PGP_PATH, SL_NOPRIV);
#else
	  checkfd = sl_open_fastread(FIL__, __LINE__, DEFAULT_GPG_PATH, SL_NOPRIV);
#endif
	  if (0 != sh_gpg_checksum(checkfd, 0)) {
	    aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	  }
	  sl_close(checkfd);
	}
#endif
			       

#if defined(WITH_GPG)
      retry_aud_execve (FIL__, __LINE__, DEFAULT_GPG_PATH, arg, envp);
      dlog(1, FIL__, __LINE__, _("Unexpected error: execve %s failed\n"),
	   DEFAULT_GPG_PATH);
#elif defined(WITH_PGP)
      retry_aud_execve (FIL__, __LINE__, DEFAULT_PGP_PATH, arg, envp);
#endif
      
      /* failed 
       */
      TPT(((0), FIL__, __LINE__, _("msg=<execve failed>\n")));
      dlog(1, FIL__, __LINE__, _("Unexpected error: execve failed\n"));
      aud__exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  /* parent
   */

  if (envp[0] != NULL) 
    free(envp[0]);

  sl_close_fd (FIL__, __LINE__, pipedes[STDOUT_FILENO]);
  retry_fcntl (FIL__, __LINE__, pipedes[STDIN_FILENO], F_SETFD, FD_CLOEXEC);
  retry_fcntl (FIL__, __LINE__, pipedes[STDIN_FILENO], F_SETFL,  O_NONBLOCK);

  outf = fdopen (pipedes[STDIN_FILENO], "r");
  
  if (outf == NULL) 
    {
      aud_kill (FIL__, __LINE__, source->pid, SIGKILL);
      sl_close_fd (FIL__, __LINE__, pipedes[STDOUT_FILENO]);
      waitpid (source->pid, NULL, 0);
      source->pid = 0;
      SL_RETURN( (NULL), _("sh_gpg_popen"));
    }
  
  SL_RETURN( (outf), _("sh_gpg_popen"));
}


static int sh_gpg_pclose (sh_gpg_popen_t *source)
{
  int status = 0;
  
  SL_ENTER(_("sh_gpg_pclose"));

  status = sl_fclose(FIL__, __LINE__, source->pipe);
  if (status)
    SL_RETURN( (-1), _("sh_gpg_pclose"));
  
  if (waitpid(source->pid, NULL, 0) != source->pid)
    status = -1;
  
  source->pipe = NULL;
  source->pid = 0;
  SL_RETURN( (status), _("sh_gpg_pclose"));
}
 
static
int sh_gpg_check_file_sign(int fd, char * sign_id, char * sign_fp, 
			   char * homedir, int whichfile)
{
  struct stat buf;
  char line[256];
  sh_gpg_popen_t  source;
  int have_id = BAD, have_fp = BAD, status = 0;
#ifdef WITH_PGP
  char *ptr;
#endif

#ifdef HAVE_GPG_CHECKSUM
  SL_TICKET checkfd;
#endif

  SL_ENTER(_("sh_gpg_check_file_sign"));

  /* check whether GnuPG exists and has the correct checksum
   */
#if defined(WITH_GPG)

  TPT(((0), FIL__, __LINE__, _("msg=<Check signature>\n")));
  TPT(((0), FIL__, __LINE__, _("msg=<gpg is %s>\n"), DEFAULT_GPG_PATH));

  if (0 != retry_lstat(FIL__, __LINE__, DEFAULT_GPG_PATH, &buf))
    {
      char errbuf[SH_ERRBUF_SIZE];

      status = errno;
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, status, MSG_ERR_LSTAT,
		      sh_error_message(status, errbuf, sizeof(errbuf)), DEFAULT_GPG_PATH);
      SL_RETURN( SH_GPG_BAD, _("sh_gpg_check_file_sign"));
    }

  if (0 != tf_trust_check (DEFAULT_GPG_PATH, SL_YESPRIV))
    SL_RETURN( SH_GPG_BAD, _("sh_gpg_check_file_sign"));

#ifdef HAVE_GPG_CHECKSUM
  checkfd = sl_open_read(FIL__, __LINE__, DEFAULT_GPG_PATH, SL_YESPRIV);

  if (0 != sh_gpg_checksum(checkfd, 1))
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      _("Checksum mismatch"), 
		      _("gpg_check_file_sign"));
      sl_close(checkfd);
      SL_RETURN( SH_GPG_BAD, _("sh_gpg_check_file_sign"));
    }
  sl_close(checkfd);
#endif

#elif defined(WITH_PGP)

  TPT(((0), FIL__, __LINE__, _("msg=<Check signature>\n")));
  TPT(((0), FIL__, __LINE__, _("msg=<pgp is %s>\n"), DEFAULT_PGP_PATH));

  if (0 != retry_lstat(FIL__, __LINE__, DEFAULT_PGP_PATH, &buf))
    {
      char errbuf[SH_ERRBUF_SIZE];

      status = errno;
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, status, MSG_ERR_LSTAT,
		      sh_error_message(status, errbuf, sizeof(errbuf)), DEFAULT_PGP_PATH);
      SL_RETURN( SH_GPG_BAD, _("sh_gpg_check_file_sign"));
    }
  if (0 != tf_trust_check (DEFAULT_PGP_PATH, SL_YESPRIV))
    SL_RETURN( SH_GPG_BAD, _("sh_gpg_check_file_sign"));

#ifdef HAVE_GPG_CHECKSUM
  checkfd = sl_open_read(FIL__, __LINE__, DEFAULT_PGP_PATH, SL_YESPRIV);

  if (0 != sh_gpg_checksum(checkfd, 1))
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      _("Checksum mismatch"), 
		      _("gpg_check_file_sign"));
      sl_close(checkfd);
      SL_RETURN( SH_GPG_BAD, _("sh_gpg_check_file_sign"));
    }
  sl_close(checkfd);
#endif

#endif

  TPT(((0), FIL__, __LINE__, _("msg=<Open pipe to check signature>\n")));

  fflush(NULL);
 
  source.pipe   = sh_gpg_popen  ( &source, fd, 0, NULL, homedir );

  if (NULL == source.pipe)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      _("Could not open pipe"), 
		      _("gpg_check_file_sign"));
      SL_RETURN( SH_GPG_BAD, _("sh_gpg_check_file_sign"));
    }

  TPT(((0), FIL__, __LINE__, _("msg=<Open pipe success>\n")));

 xagain:

  errno = 0;

  while (NULL != fgets(line, sizeof(line), source.pipe))
    {

      TPT(((0), FIL__, __LINE__, _("msg=<gpg out: %s>\n"), line));
      if (line[strlen(line)-1] == '\n')
	line[strlen(line)-1] = ' ';
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      line, 
		      _("gpg_check_file_sign"));

      if (sl_strlen(line) < 18) 
	continue;
#if defined(WITH_GPG)
      /* Sun May 27 18:40:05 CEST 2001
       */
      if (0 == sl_strncmp(_("BADSIG"), &line[9], 6) ||
	  0 == sl_strncmp(_("ERRSIG"), &line[9], 6) ||
	  0 == sl_strncmp(_("NO_PUBKEY"), &line[9], 6) ||
	  0 == sl_strncmp(_("NODATA"), &line[9], 6) ||
	  0 == sl_strncmp(_("SIGEXPIRED"), &line[9], 6))
	{
	  if      (0 == sl_strncmp(_("BADSIG"), &line[9], 6)) {
	    dlog(1, FIL__, __LINE__, 
		 _("%s file is signed, but the signature is invalid."),
		 ((whichfile == 1) ? _("Configuration") : _("Database")));
	  } 
	  else if (0 == sl_strncmp(_("NO_PUBKEY"), &line[9], 6)) {
	    dlog(1, FIL__, __LINE__, 
		 _("%s file is signed, but the public key to verify the signature is not in my keyring %s/.gnupg/pubring.asc."), 
		 ((whichfile == 1) ? _("Configuration") : _("Database")),
		 homedir);
	  }
	  else if (0 == sl_strncmp(_("ERRSIG"), &line[9], 6)) {
	    dlog(1, FIL__, __LINE__, 
		 _("%s file is signed, but the public key to verify the signature is not in my keyring %s/.gnupg/pubring.asc."), 
		 ((whichfile == 1) ? _("Configuration") : _("Database")),
		 homedir);
	  }
	  else if (0 == sl_strncmp(_("SIGEXPIRED"), &line[9], 6)) {
	    dlog(1, FIL__, __LINE__, 
		 _("%s file is signed, but the public key to verify the signature has expired."), 
		 ((whichfile == 1) ? _("Configuration") : _("Database")));
	  }
	  else if (0 == sl_strncmp(_("NODATA"), &line[9], 6)) {
	    dlog(1, FIL__, __LINE__, 
		 _("%s file is not signed."), 
		 ((whichfile == 1) ? _("Configuration") : _("Database")));
	  }

	  have_fp = BAD; have_id = BAD;
	  break;
	}
      if (0 == sl_strncmp(_("GOODSIG"), &line[9], 7))
	{
	  sl_strlcpy (sign_id, &line[25], SH_MINIBUF+1);
	  if (sign_id)
	    sign_id[sl_strlen(sign_id)-1] = '\0';  /* remove trailing '"' */
	  have_id = GOOD;
	} 
      if (0 == sl_strncmp(_("VALIDSIG"), &line[9], 8))
	{
	  strncpy (sign_fp, &line[18], 40);
	  sign_fp[40] = '\0';
	  have_fp = GOOD;
	}
#elif defined(WITH_PGP)
      if (0 == sl_strncmp(_("Bad signature"), line, 13) ||
	  0 == sl_strncmp(_("Error"), line, 5) ||
	  0 == sl_strncmp(_("Malformed"), line, 9) ||
	  0 == sl_strncmp(_("WARNING"), line, 7) ||
	  0 == sl_strncmp(_("ERROR"), line, 5) 
	  )
	{
	  have_fp = BAD; have_id = BAD;
	  break;
	}
      if (0 == sl_strncmp(_("Good signature"), line, 14))
	{
	  ptr = strchr ( line, '"');
	  ++ptr;
	  if (ptr)
	    {
	      sl_strlcpy (sign_id, ptr, SH_MINIBUF+1);
	      sign_id[sl_strlen(sign_id)-1] = '\0'; /* remove trailing dot */
	      sign_id[sl_strlen(sign_id)-2] = '\0'; /* remove trailing '"' */
	    }
	  else
	    {
	      sl_strlcpy (sign_id, _("(null)"), SH_MINIBUF+1);
	    }
	  have_id = GOOD;
	}
#endif
    }

  if (ferror(source.pipe) && errno == EAGAIN) 
    {
      retry_msleep(0,10); /* sleep 10 ms to avoid starving the gpg child writing to the pipe */
      clearerr(source.pipe);
      goto xagain;
    }
 
  sh_gpg_pclose (&source);

  TPT(((0), FIL__, __LINE__, _("msg=<Close pipe>\n")));

#ifdef WITH_PGP
  /* get the fingerprint */

  source.pipe   = sh_gpg_popen  ( &source, fd, 1,  sign_id, homedir);
  if (NULL == source.pipe)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      _("Could not open pipe for fp"), 
		      _("gpg_check_file_sign"));
      SL_RETURN( SH_GPG_BAD, _("sh_gpg_check_file_sign"));
    }

  TPT(((0), FIL__, __LINE__, _("msg=<Open pipe success>\n")));

 yagain:

  errno = 0;

  while (NULL != fgets(line, sizeof(line), source.pipe))
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
      char * saveptr = NULL;
#endif
      if (line[strlen(line)-1] == '\n')
	line[strlen(line)-1] = ' ';
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      line, 
		      _("gpg_check_file_sign"));

      if (sl_strlen(line) < 18) 
	continue;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
      ptr = strtok_r (line, " ", &saveptr);
#else
      ptr = strtok (line, " ");
#endif
      while (ptr)
	{
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
	  ptr = strtok_r (NULL, " ", &saveptr);
#else
	  ptr = strtok (NULL, " ");
#endif
	  if (ptr && 0 == sl_strncmp (ptr, _("fingerprint"), 11))
	    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
	      ptr = strtok_r (NULL, " ", &saveptr); /* to '=' */
#else
	      ptr = strtok (NULL, " "); /* to '=' */
#endif
	      sign_fp[0] = '\0';
	      while (ptr)
		{
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
		  ptr = strtok_r (NULL, " ", &saveptr); /* part of fingerprint */
#else
		  ptr = strtok (NULL, " "); /* part of fingerprint */
#endif
		  sl_strlcat (sign_fp, ptr, SH_MINIBUF+1);
		}
	      /* sign_fp[sl_strlen(sign_fp)-1] = '\0'; remove trailing '\n' */
	      if (sl_strlen(sign_fp) > 0) 
		have_fp = GOOD;
	      break;
	    } 
	} 
    }

  if (ferror(source.pipe) && errno == EAGAIN) 
    {
      retry_msleep(0,10); /* sleep 10 ms to avoid starving the gpg child writing to the pipe */
      clearerr(source.pipe);
      goto yagain;
    }
 
  sh_gpg_pclose (&source);
#endif

  if (have_id == GOOD)
    {
      TPT(((0), FIL__, __LINE__, _("msg=<Got signator ID>\n")));
      ;
    }
  if (have_fp == GOOD)
    {
      TPT(((0), FIL__, __LINE__, _("msg=<Got fingerprint>\n")));
      ;
    }

  if (have_id == GOOD && have_fp == GOOD)
    SL_RETURN( SH_GPG_OK, _("sh_gpg_check_file_sign"));
  else
    {
      if (have_id == BAD)
	sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
			_("No good signature"), 
			_("gpg_check_file_sign"));
      else
	sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
			_("No fingerprint for key"), 
			_("gpg_check_file_sign"));
      SL_RETURN( SH_GPG_BADSIGN, _("sh_gpg_check_file_sign"));
    }
}

int get_the_fd(SL_TICKET file_1);

int sh_gpg_check_sign (long file_1, long file_2, int what)
{
  int status = SH_GPG_BAD;
  int fd1 = 0;
  int fd2 = 0;
  static int smsg = S_FALSE;
  char  * tmp;
  char  * tmp2;

  char  * homedir = sh.effective.home;
#if defined(SH_WITH_SERVER)
  struct passwd * tempres;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  struct passwd    pwd;
  char           * buffer = SH_ALLOC(SH_PWBUF_SIZE);
#endif
#endif

#ifdef USE_FINGERPRINT
#include "sh_gpg_fp.h"
#endif

  SL_ENTER(_("sh_gpg_check_sign"));


  if (what == 0 || what == 1)
    fd1 = get_the_fd(file_1);
  if (what == 0 || what == 2)
    fd2 = get_the_fd(file_2);


  if (fd1 < 0 || fd2 < 0)
    {
      TPT(((0), FIL__, __LINE__, _("msg=<GPG_CHECK: FD1 = %d>\n"), fd1));
      TPT(((0), FIL__, __LINE__, _("msg=<GPG_CHECK: FD2 = %d>\n"), fd2));
      dlog(1, FIL__, __LINE__, 
	   _("This looks like an unexpected internal error.\n"));
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORT1, sh.prg_name);
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
#if defined(SH_WITH_SERVER)
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      SH_FREE(buffer);
#endif
#endif
      SL_RETURN( (-1), _("sh_gpg_check_sign"));
    }
  
  if (what == 0 || what == 1)
    {
      TPT(((0), FIL__, __LINE__, _("msg=<GPG_CHECK: FD1 = %d>\n"), fd1));
#if defined(SH_WITH_SERVER)
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      sh_getpwnam_r(DEFAULT_IDENT, &pwd, buffer, SH_PWBUF_SIZE, &tempres);
#else
      tempres = sh_getpwnam(DEFAULT_IDENT);
#endif

      if ((tempres != NULL) && (0 == sl_ret_euid()))
	{
	  /* privileges not dropped yet*/
	  homedir = tempres->pw_dir;
	}
#endif
      status = sh_gpg_check_file_sign(fd1, gp.conf_id, gp.conf_fp, homedir, 1);
      TPT(((0), FIL__, __LINE__, _("msg=<CONF SIGUSR: |%s|>\n"), gp.conf_id));
      TPT(((0), FIL__, __LINE__, _("msg=<CONF SIGFP:  |%s|>\n"), gp.conf_fp));
    }

  if ((what == 0 && SH_GPG_OK == status) || what == 2)
    {
      TPT(((0), FIL__, __LINE__, _("msg=<GPG_CHECK: FD2 = %d>\n"), fd2));
#if defined(SH_WITH_SERVER)
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      sh_getpwnam_r(DEFAULT_IDENT, &pwd, buffer, SH_PWBUF_SIZE, &tempres);
#else
      tempres = sh_getpwnam(DEFAULT_IDENT);
#endif

      if ((tempres != NULL) && (0 == sl_ret_euid()))
	{
	  /* privileges not dropped yet*/
	  homedir = tempres->pw_dir;
	}
#endif
      status = sh_gpg_check_file_sign(fd2, gp.data_id, gp.data_fp, homedir, 2);
      TPT(((0), FIL__, __LINE__, _("msg=<DATA SIGUSR: |%s|>\n"), gp.data_id));
      TPT(((0), FIL__, __LINE__, _("msg=<DATA SIGFP:  |%s|>\n"), gp.data_fp));
    }
  
  if (SH_GPG_OK == status && what == 1)
    {
#ifdef USE_FINGERPRINT
      if ((sl_strcmp(SH_GPG_FP, gp.conf_fp) == 0))
	{
	  int i;

	  for(i = 0; i < (int) sl_strlen(gp.conf_fp); ++i)
	    {
	      if (gpgfp[i] != gp.conf_fp[i]) 
		{
		  sh_error_handle(SH_ERR_SEVERE, FIL__, __LINE__, 0, 
				  MSG_E_GPG_FP, 
				  gpgfp, gp.conf_fp);
		  break;
		}
	    }

	  if (smsg == S_FALSE)
	    {
	      tmp  = sh_util_safe_name(gp.conf_id);
	      sh_gpg_fill_startup (__LINE__,
				   /* sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_START_GH, */
			       sh.prg_name, sh.real.uid,
			       (sh.flag.hidefile == S_TRUE) ? 
			       _("(hidden)") : file_path('C', 'R'), 
			       tmp, 
			       gp.conf_fp);
	      SH_FREE(tmp);
	    }
	  smsg = S_TRUE;
#if defined(SH_WITH_SERVER)
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
	  SH_FREE(buffer);
#endif
#endif
	  SL_RETURN(0, _("sh_gpg_check_sign"));
	}
      else
	{
	  /* fp mismatch
	   */
	  dlog(1, FIL__, __LINE__, 
	       _("The fingerprint of the signing key: %s\ndoes not match the compiled-in fingerprint: %s.\nTherefore the signature could not be verified.\n"), 
	       gp.conf_fp, SH_GPG_FP);
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      _("Fingerprint mismatch"), 
		      _("gpg_check_sign"));
	  status = SH_GPG_BADSIGN;
	}
#else
      if (smsg == S_FALSE)
	{
	  tmp = sh_util_safe_name(gp.conf_id);
	  sh_gpg_fill_startup (__LINE__,
	  /* sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_START_GH, */
			   sh.prg_name, sh.real.uid,
			   (sh.flag.hidefile == S_TRUE) ? 
			   _("(hidden)") : file_path('C', 'R'), 
			   tmp, 
			   gp.conf_fp);
	  SH_FREE(tmp);
	}
      smsg = S_TRUE;
#if defined(SH_WITH_SERVER)
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      SH_FREE(buffer);
#endif
#endif
      SL_RETURN(0, _("sh_gpg_check_sign"));
#endif
    }
  
  else if (SH_GPG_OK == status && (what == 2 || what == 0))
    {
      if ((sl_strcmp(gp.data_id, gp.conf_id) == 0) &&
	  (sl_strcmp(gp.data_fp, gp.conf_fp) == 0))
	{
#if defined(SH_WITH_SERVER)
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
	  SH_FREE(buffer);
#endif
#endif
	  SL_RETURN(0, _("sh_gpg_check_sign"));
	}
      else
	{
	  /* ID or fp not equal 
	   */
	  dlog(1, FIL__, __LINE__, 
	       _("The fingerprint or ID of the signing key is not the same for the\nconfiguration file and the file signature database.\nTherefore the signature could not be verified.\n"));
	  tmp  = sh_util_safe_name (gp.conf_id);
	  tmp2 = sh_util_safe_name (gp.data_id);
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_START_GH2,
			   sh.prg_name, sh.real.uid,
			   (sh.flag.hidefile == S_TRUE) ? _("(hidden)") : file_path('C', 'R'),
			   tmp,  gp.conf_fp,
			   (sh.flag.hidefile == S_TRUE) ? _("(hidden)") : file_path('D', 'R'),
			   tmp2, gp.data_fp);
	  SH_FREE(tmp);
	  SH_FREE(tmp2);
	}
    }

  if (status != SH_GPG_OK) 
    {
      uid_t   e_uid  = sl_ret_euid();
      char  * e_home = sh.effective.home;

#if defined(SH_WITH_SERVER)
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      struct passwd    e_pwd;
      char          *  e_buffer = SH_ALLOC(SH_PWBUF_SIZE);
      struct passwd *  e_tempres;
      sh_getpwnam_r(DEFAULT_IDENT, &e_pwd, e_buffer, SH_PWBUF_SIZE, &e_tempres);
#else
      struct passwd * e_tempres = sh_getpwnam(DEFAULT_IDENT);
#endif

      if ((e_tempres != NULL) && (0 == sl_ret_euid()))   
	{
	  /* privileges not dropped yet */
	  e_uid  = e_tempres->pw_uid;
	  e_home = e_tempres->pw_dir;
	}
#endif
      dlog(1, FIL__, __LINE__, 
	   _("The signature of the configuration file or the file signature database\ncould not be verified. Possible reasons are:\n - gpg binary (%s) not found\n - invalid signature\n - the signature key is not in the private keyring of UID %d,\n - there is no keyring in %s/.gnupg, or\n - the file is not signed - did you move /filename.asc to /filename ?\nTo create a signed file, use (remove old signatures before):\n   gpg -a --clearsign --not-dash-escaped FILE\n   mv FILE.asc FILE\n"),
#if defined(WITH_GPG) 
	   DEFAULT_GPG_PATH,
#else
	   DEFAULT_PGP_PATH,
#endif
	   (int) e_uid, e_home);

#if defined(SH_WITH_SERVER)
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      SH_FREE(e_buffer);
#endif
#endif
    }

  TPT(((0), FIL__, __LINE__, _("msg=<Status = %d>\n"), status));

  sh_error_handle((-1), FIL__, __LINE__, status, MSG_EXIT_ABORT1, sh.prg_name);
  aud_exit (FIL__, __LINE__, EXIT_FAILURE);

  return (-1); /* make compiler happy */
}  

#define FGETS_BUF 16384

SL_TICKET sh_gpg_extract_signed(SL_TICKET fd)
{
  FILE * fin_cp = NULL;
  char * buf    = NULL;
  int    bufc;
  int    flag_pgp    = S_FALSE;
  int    flag_nohead = S_FALSE;
  SL_TICKET fdTmp = (-1);
  SL_TICKET open_tmp (void);

  /* extract the data and copy to temporary file
   */
  fdTmp = open_tmp();

  fin_cp = fdopen(dup(get_the_fd(fd)), "rb");
  buf = SH_ALLOC(FGETS_BUF);

  while (NULL != fgets(buf, FGETS_BUF, fin_cp))
    {
      bufc = 0; 
      while (bufc < FGETS_BUF) { 
	if (buf[bufc] == '\n') { ++bufc; break; }
	++bufc;
      }

      if (flag_pgp == S_FALSE &&
	  (0 == sl_strcmp(buf, _("-----BEGIN PGP SIGNED MESSAGE-----\n"))||
	   0 == sl_strcmp(buf, _("-----BEGIN PGP MESSAGE-----\n")))
	  )
	{
	  flag_pgp = S_TRUE;
	  sl_write(fdTmp, buf, bufc);
	  continue;
	}
      
      if (flag_pgp == S_TRUE && flag_nohead == S_FALSE)
	{
	  if (buf[0] == '\n')
	    {
	      flag_nohead = S_TRUE;
	      sl_write(fdTmp, buf, 1);
	      continue;
	    }
	  else if (0 == sl_strncmp(buf, _("Hash:"), 5) ||
		   0 == sl_strncmp(buf, _("NotDashEscaped:"), 15))
	    {
	      sl_write(fdTmp, buf, bufc);
	      continue;
	    }
	  else
	    continue;
	}
    
      if (flag_pgp == S_TRUE && buf[0] == '\n')
	{
	  sl_write(fdTmp, buf, 1);
	}
      else if (flag_pgp == S_TRUE)
	{
	  /* sl_write_line(fdTmp, buf, bufc); */
	  sl_write(fdTmp, buf, bufc);
	}
      
      if (flag_pgp == S_TRUE && 
	  0 == sl_strcmp(buf, _("-----END PGP SIGNATURE-----\n")))
	break;
    }
  SH_FREE(buf);
  sl_fclose(FIL__, __LINE__, fin_cp); /* fin_cp = fdopen(dup(), "rb"); */
  sl_rewind (fdTmp);

  return fdTmp;
}

/* #ifdef WITH_GPG */
#endif








