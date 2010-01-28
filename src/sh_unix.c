/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999 Rainer Wichmann                                      */
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
#include <string.h>
#include <ctype.h>
#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#ifdef  HAVE_UNISTD_H
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
/* need to undef these, since the #define's may be picked up from
 * linux/wait.h, and will clash with a typedef in sys/wait.h
 */
#undef P_ALL
#undef P_PID
#undef P_PGID
#include <sys/wait.h>

/*********************
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
**********************/
#endif

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef FD_SET
#define NFDBITS         32
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#endif /* !FD_SET */
#ifndef FD_SETSIZE
#define FD_SETSIZE      32
#endif
#ifndef FD_ZERO
#define FD_ZERO(p)      memset((char *)(p), '\0', sizeof(*(p)))
#endif


#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#include <sys/mman.h>
#endif

#include "samhain.h"
#include "sh_error.h"
#include "sh_unix.h"
#include "sh_utils.h"
#include "sh_mem.h"
#include "sh_hash.h"
#include "sh_tools.h"
#include "sh_tiger.h"
#include "sh_prelink.h"
#include "sh_pthread.h"

/* moved here from far below
 */
#include <netdb.h>

#define SH_NEED_PWD_GRP
#define SH_NEED_GETHOSTBYXXX
#include "sh_static.h"

#ifndef HAVE_LSTAT
#define lstat   stat
#endif
 
#if defined(S_IFLNK) && !defined(S_ISLNK)
#define S_ISLNK(mode) (((mode) & S_IFMT) == S_IFLNK)
#else
#if !defined(S_ISLNK)
#define S_ISLNK(mode) (0)
#endif
#endif

#if defined(S_IFSOCK) && !defined(S_ISSOCK)
#define S_ISSOCK(mode) (((mode) & S_IFMT) == S_IFSOCK)
#else
#if !defined(S_ISSOCK)
#define S_ISSOCK(mode) (0)
#endif
#endif

#if defined(S_IFDOOR) && !defined(S_ISDOOR)
#define S_ISDOOR(mode) (((mode) & S_IFMT) == S_IFDOOR)
#else
#if !defined(S_ISDOOR)
#define S_ISDOOR(mode) (0)
#endif
#endif

#if defined(S_IFPORT) && !defined(S_ISPORT)
#define S_ISPORT(mode) (((mode) & S_IFMT) == S_IFPORT)
#else
#if !defined(S_ISPORT)
#define S_ISPORT(mode) (0)
#endif
#endif

#define SH_KEY_NULL _("000000000000000000000000000000000000000000000000")

#undef  FIL__
#define FIL__  _("sh_unix.c")

unsigned long mask_PRELINK      = MASK_PRELINK_;
unsigned long mask_USER0        = MASK_USER_;
unsigned long mask_USER1        = MASK_USER_;
unsigned long mask_USER2        = MASK_USER_;
unsigned long mask_USER3        = MASK_USER_;
unsigned long mask_USER4        = MASK_USER_;
unsigned long mask_ALLIGNORE    = MASK_ALLIGNORE_;
unsigned long mask_ATTRIBUTES   = MASK_ATTRIBUTES_;
unsigned long mask_LOGFILES     = MASK_LOGFILES_;
unsigned long mask_LOGGROW      = MASK_LOGGROW_;
unsigned long mask_READONLY     = MASK_READONLY_;
unsigned long mask_NOIGNORE     = MASK_NOIGNORE_;


extern char **environ;

int sh_unix_maskreset()
{
  mask_PRELINK      = MASK_PRELINK_;
  mask_USER0        = MASK_USER_;
  mask_USER1        = MASK_USER_;
  mask_USER2        = MASK_USER_;
  mask_USER3        = MASK_USER_;
  mask_USER4        = MASK_USER_;
  mask_ALLIGNORE    = MASK_ALLIGNORE_;
  mask_ATTRIBUTES   = MASK_ATTRIBUTES_;
  mask_LOGFILES     = MASK_LOGFILES_;
  mask_LOGGROW      = MASK_LOGGROW_;
  mask_READONLY     = MASK_READONLY_;
  mask_NOIGNORE     = MASK_NOIGNORE_;
  return 0;
}


#ifdef SYS_SIGLIST_DECLARED
/* extern const char * const sys_siglist[]; */
#else
char * sh_unix_siglist (int signum)
{
  switch (signum)
    {
#ifdef SIGHUP
    case SIGHUP: 
      return _("Hangup");
#endif
#ifdef SIGINT
    case SIGINT: 
      return _("Interrupt");
#endif
#ifdef SIGQUIT
    case SIGQUIT: 
      return _("Quit");
#endif
#ifdef SIGILL
    case SIGILL: 
      return _("Illegal instruction");
#endif
#ifdef SIGTRAP
    case SIGTRAP: 
      return _("Trace/breakpoint trap");
#endif
#ifdef SIGABRT
    case SIGABRT: 
      return _("IOT trap/Abort");
#endif
#ifdef SIGBUS
    case SIGBUS: 
      return _("Bus error");
#endif
#ifdef SIGFPE
    case SIGFPE: 
      return _("Floating point exception");
#endif
#ifdef SIGUSR1
    case SIGUSR1: 
      return _("User defined signal 1");
#endif
#ifdef SIGSEGV
    case SIGSEGV: 
      return _("Segmentation fault");
#endif
#ifdef SIGUSR2
    case SIGUSR2: 
      return _("User defined signal 2");
#endif
#ifdef SIGPIPE
    case SIGPIPE: 
      return _("Broken pipe");
#endif
#ifdef SIGALRM
    case SIGALRM: 
      return _("Alarm clock");
#endif
#ifdef SIGTERM
    case SIGTERM: 
      return _("Terminated");
#endif
#ifdef SIGSTKFLT
    case SIGSTKFLT: 
      return _("Stack fault");
#endif
#ifdef SIGCHLD
    case SIGCHLD: 
      return _("Child exited");
#endif
#ifdef SIGCONT
    case SIGCONT: 
      return _("Continued");
#endif
#ifdef SIGSTOP
    case SIGSTOP: 
      return _("Stopped");
#endif
#ifdef SIGTSTP
    case SIGTSTP: 
      return _("Stop typed at tty");
#endif
#ifdef SIGTTIN
    case SIGTTIN: 
      return _("Stopped (tty input)");
#endif
#ifdef SIGTTOU
    case SIGTTOU: 
      return _("Stopped (tty output)");
#endif
#ifdef SIGURG
    case SIGURG: 
      return _("Urgent condition");
#endif
#ifdef SIGXCPU
    case SIGXCPU: 
      return _("CPU time limit exceeded");
#endif
#ifdef SIGXFSZ
    case SIGXFSZ: 
      return _("File size limit exceeded");
#endif
#ifdef SIGVTALRM
    case SIGVTALRM: 
      return _("Virtual time alarm");
#endif
#ifdef SIGPROF
    case SIGPROF: 
      return _("Profile signal");
#endif
#ifdef SIGWINCH
    case SIGWINCH: 
      return _("Window size changed");
#endif
#ifdef SIGIO
    case SIGIO: 
      return _("Possible I/O");
#endif
#ifdef SIGPWR
    case SIGPWR: 
      return _("Power failure");
#endif
#ifdef SIGUNUSED
    case SIGUNUSED: 
      return _("Unused signal");
#endif
    }
  return _("Unknown");
}
#endif


/* Log from within a signal handler without using any
 * functions that are not async signal safe.
 *
 * This is the safe_itoa helper function.
 */
char * safe_itoa(int i, char * str, int size)
{
  unsigned int u;
  int iisneg = 0;
  char *p = &str[size-1];
  
  *p = '\0';
  if (i < 0) {
    iisneg = 1;
    u = ((unsigned int)(-(1+i))) + 1;
  } else {
    u = i;
  }
  do {
    --p;
    *p = '0' + (u % 10);
    u /= 10;
  } while (u && (p != str));
  if ((iisneg == 1) && (p != str)) {
    --p;
    *p = '-';
  }
  return p;
}

/* Log from within a signal handler without using any
 * functions that are not async signal safe.
 *
 * This is the safe_logger function.
 * Arguments: signal (signal number), method (0=logger, 1=stderr), thepid (pid)
 */
extern int OnlyStderr; 

int safe_logger (int thesignal, int method, char * details)
{
  unsigned int i = 0;
  int status = -1;
  struct stat buf;
  pid_t  newpid;
  char  str[128];
  char  * p;
  
  char l0[64], l1[64], l2[64], l3[64];
  char a0[32], a1[32], a2[32];
  char e0[128];
  char msg[128];
  
  char * locations[] = { NULL, NULL, NULL, NULL, NULL };
  char * envp[]      = { NULL, NULL };
  char * argp[]      = { NULL, NULL, NULL, NULL, NULL };
  
  pid_t  thepid = getpid();
  
  if ((sh.flag.isdaemon == S_FALSE) || (OnlyStderr == S_TRUE))
    method = 1;
  
  /* seems that solaris cc needs this way of initializing ...
   */
  locations[0] = l0;
  locations[1] = l1;
  locations[2] = l2;
  locations[3] = l3;
  
  envp[0] = e0;
  
  argp[0] = a0;
  argp[1] = a1;
  argp[2] = a2;
  
  sl_strlcpy(msg, _("samhain["), 128);
  p = safe_itoa((int) thepid, str, 128);
  if (p && *p)
    sl_strlcat(msg, p, 128);
  if (thesignal == 0)
    {
      if (details == NULL) {
	sl_strlcat(msg, _("]: out of memory"), 128);
      } else {
	sl_strlcat(msg, _("]: "), 128);
	sl_strlcat(msg, details, 128);
      }
    }
  else 
    {
      sl_strlcat(msg, _("]: exit on signal "), 128);
      p = safe_itoa(thesignal, str, 128);
      if (p && *p)
	sl_strlcat(msg, p, 128);
    }

  if (method == 1) {
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif
    int retval = 0;
    do {
      retval = write(STDERR_FILENO,  msg, strlen(msg));
    } while (retval < 0 && errno == EINTR);
    do {
      retval = write(STDERR_FILENO, "\n", 1);
    } while (retval < 0 && errno == EINTR);
    return 0;
  }

  sl_strlcpy (l0, _("/usr/bin/logger"), 64);
  sl_strlcpy (l1, _("/usr/sbin/logger"), 64);
  sl_strlcpy (l2, _("/usr/ucb/logger"), 64);
  sl_strlcpy (l3, _("/bin/logger"), 64);

  sl_strlcpy (a0, _("logger"), 32);
  sl_strlcpy (a1, _("-p"), 32);
  sl_strlcpy (a2, _("daemon.alert"), 32);

  sl_strlcpy (e0,
	      _("PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/ucb:/usr/local/bin"),
	      128);

  while (locations[i] != NULL) {
    status = stat(locations[i], &buf);
    if (status == 0)
      break;
    ++i;
  }

  if (locations[i] != NULL) {
    argp[3] = msg;
    newpid = fork();
    if (newpid == 0) {
      execve(locations[i], argp, envp);
      _exit(1);
    }
    else if (newpid > 0) {
      waitpid(newpid, &status, WUNTRACED);
    }
  }
  return 0;
}

void safe_fatal (const char * details, 
		 const char * file, int line)
{
  char msg[128];
  char str[128];
  char * p;
  int  thesignal = 0;
  int  method = 0;

  p = safe_itoa((int) line, str, 128);
  sl_strlcpy(msg, _("FATAL: "), 128);
  sl_strlcat(msg, file, 128);
  sl_strlcat(msg, ": ", 128);
  if (p && (*p)) {
    sl_strlcat(msg, p   , 128);
    sl_strlcat(msg, ": ", 128);
  }
  sl_strlcat(msg, details, 128);
  (void) safe_logger (thesignal, method, msg);
  raise(SIGKILL);
}

extern char sh_sig_msg[64];

volatile int immediate_exit_normal = 0;

#if defined(SA_SIGACTION_WORKS)
static
void sh_unix_sigexit (int mysignal, siginfo_t * signal_info, void * signal_add)
#else
static
void sh_unix_sigexit (int mysignal)
#endif
{

#if defined(SA_SIGACTION_WORKS)
  if (signal_info != NULL && signal_info->si_code == SI_USER && 
      mysignal != SIGTERM && mysignal != SIGINT) 
    {
      return;
    }

  /* avoid compiler warning (unused var)
   */
  (void) signal_add;
#endif

  /* 
   * Block re-entry
   */
  if (immediate_exit_normal > 0)
    {
      ++immediate_exit_normal;
      if ((skey != NULL) && (immediate_exit_normal == 2))
	memset (skey, '\0', sizeof(sh_key_t));
      if (immediate_exit_normal == 2)
	{
	  int val_return;

	  do {
	    val_return = chdir ("/");
	  } while (val_return < 0 && errno == EINTR);

	  safe_logger (mysignal, 0, NULL);
	}
      raise(SIGKILL);
    }
  else
    {
      immediate_exit_normal = 1;
    }

#ifdef SYS_SIGLIST_DECLARED
  strncpy (sh_sig_msg, sys_siglist[mysignal],     40);
#else
  strncpy (sh_sig_msg, sh_unix_siglist(mysignal), 40);
#endif
  sh_sig_msg[63] = '\0';

  ++sig_raised;
  ++sig_urgent;
  sig_termfast   = 1;
  return;
}

volatile int immediate_exit_fast = 0;

#if defined(SA_SIGACTION_WORKS)
static
void sh_unix_sigexit_fast (int mysignal, siginfo_t * signal_info, 
			   void * signal_add)
#else
static
void sh_unix_sigexit_fast (int mysignal)
#endif
{
#if defined(SL_DEBUG) && (defined(USE_SYSTEM_MALLOC) || !defined(USE_MALLOC_LOCK))
  int retval;
#endif

#if defined(SA_SIGACTION_WORKS)
  if (signal_info != NULL && signal_info->si_code == SI_USER)
    {
      return;
    }
#endif

  /* avoid compiler warning (unused var)
   */
#if defined(SA_SIGACTION_WORKS)
  (void) signal_add;
#endif

  /* Check whether the heap is ok; otherwise _exit 
   */
#if !defined(SL_DEBUG) || (!defined(USE_SYSTEM_MALLOC) && defined(USE_MALLOC_LOCK))
  ++immediate_exit_fast;
  if (skey != NULL && immediate_exit_fast < 2)
    memset (skey, '\0', sizeof(sh_key_t));
  if (immediate_exit_fast < 2)
    safe_logger (mysignal, 0, NULL);
  raise(SIGKILL);
#else

  /* debug code
   */
  if (immediate_exit_fast == 1)
    {
      ++immediate_exit_fast;
      if (skey != NULL)
	memset (skey, '\0', sizeof(sh_key_t));
#ifdef WITH_MESSAGE_QUEUE
      close_ipc ();
#endif
      safe_logger (mysignal, 0, NULL);
      do {
	retval = chdir ("/");
      } while (retval < 0 && errno == EINTR);
      raise(SIGFPE);
    }
  else if (immediate_exit_fast == 2)
    {
      do {
	retval = chdir ("/");
      } while (retval < 0 && errno == EINTR);
      raise(SIGFPE);
    }
  else if (immediate_exit_fast != 0)
    {
      raise(SIGKILL);
    }

  ++immediate_exit_fast;
  
  /* The FPE|BUS|SEGV|ILL signals leave the system in an undefined
   * state, thus it is best to exit immediately.
   */
#ifdef SYS_SIGLIST_DECLARED
  strncpy (sh_sig_msg, sys_siglist[mysignal],     40);
#else
  strncpy (sh_sig_msg, sh_unix_siglist(mysignal), 40);
#endif
  sh_sig_msg[63] = '\0';

  sl_stack_print();

  /* Try to push out an error message. 
   */
  sh_error_handle ((-1), FIL__, __LINE__, mysignal, MSG_EXIT_NORMAL, 
		   sh.prg_name, sh_sig_msg);

  if (skey != NULL)
    memset (skey, '\0', sizeof(sh_key_t));
#ifdef WITH_MESSAGE_QUEUE
  close_ipc ();
#endif

  do {
    retval = chdir ("/");
  } while (retval < 0 && errno == EINTR);

  raise(SIGFPE);
#endif
}


static
void sh_unix_sigaction (int mysignal)
{
  ++sig_raised;
#ifdef SIGUSR1
  if (mysignal == SIGUSR1)
    sig_debug_switch       = 1;
#endif
#ifdef SIGUSR2
  if (mysignal == SIGUSR2)
    {
      ++sig_suspend_switch;
      ++sig_urgent;
    }
#endif
#ifdef SIGHUP
  if (mysignal == SIGHUP)
    sig_config_read_again = 1;
#endif
#ifdef SIGTTOU
  if (mysignal == SIGTTOU)
    sig_force_check = 1;
#endif
#ifdef SIGABRT
  if (mysignal == SIGABRT)
    sig_fresh_trail       = 1;
#endif
#ifdef SIGQUIT
  if (mysignal == SIGQUIT)
    {
      sig_terminate       = 1;
      ++sig_urgent;
    }
#endif
#ifdef SIGTERM
  if (mysignal == SIGTERM)
    {
      strncpy (sh_sig_msg, _("Terminated"), 40);
      sig_termfast          = 1;
      ++sig_urgent;
    }
#endif

  return;
}

static
void sh_unix_siginstall (int goDaemon)
{
  struct sigaction act, act_fast, act2, oldact, ignact;
#if defined (SH_WITH_SERVER)
  (void) goDaemon;
#endif

  SL_ENTER(_("sh_unix_siginstall"));

  ignact.sa_handler = SIG_IGN;            /* signal action           */
  sigemptyset( &ignact.sa_mask );         /* set an empty mask       */
  ignact.sa_flags = 0;                    /* init sa_flags           */

#if defined(SA_SIGACTION_WORKS)
  act.sa_sigaction = &sh_unix_sigexit;    /* signal action           */
#else
  act.sa_handler   = &sh_unix_sigexit;    /* signal action           */
#endif

  sigfillset ( &act.sa_mask );            /* set a  full mask        */


  /* Block all but deadly signals.
   */
#ifdef SIGILL
  sigdelset  ( &act.sa_mask, SIGILL  );
#endif
#ifndef SL_DEBUG
#ifdef SIGFPE
  sigdelset  ( &act.sa_mask, SIGFPE  );
#endif
#endif
#ifdef SIGSEGV
  sigdelset  ( &act.sa_mask, SIGSEGV );
#endif
#ifdef SIGBUS
  sigdelset  ( &act.sa_mask, SIGBUS  );
#endif

#if defined(SA_SIGACTION_WORKS)
  act_fast.sa_sigaction = &sh_unix_sigexit_fast;  /* signal action           */
#else
  act_fast.sa_handler   = &sh_unix_sigexit_fast;  /* signal action           */
#endif

  sigfillset ( &act_fast.sa_mask );               /* set a full mask         */

#ifdef SIGILL
  sigdelset  ( &act_fast.sa_mask, SIGILL  );
#endif
#ifndef SL_DEBUG
#ifdef SIGFPE
  sigdelset  ( &act_fast.sa_mask, SIGFPE  );
#endif
#endif
#ifdef SIGSEGV
  sigdelset  ( &act_fast.sa_mask, SIGSEGV );
#endif
#ifdef SIGBUS
  sigdelset  ( &act_fast.sa_mask, SIGBUS  );
#endif


  /* Use siginfo to verify origin of signal, if possible.
   */
#if defined(SA_SIGACTION_WORKS)
  act.sa_flags      = SA_SIGINFO;
  act_fast.sa_flags = SA_SIGINFO;
#else
  act.sa_flags      = 0;
  act_fast.sa_flags = 0;
#endif 

  /* Do not block the signal from being received in its handler ...
   * (is this a good or a bad idea ??).
   */
#if   defined(SA_NOMASK)
  act_fast.sa_flags |= SA_NOMASK;
#elif defined(SA_NODEFER)
  act_fast.sa_flags |= SA_NODEFER;
#endif


  act2.sa_handler = &sh_unix_sigaction;  /* signal action           */
  sigemptyset( &act2.sa_mask );          /* set an empty mask       */
  act2.sa_flags = 0;                     /* init sa_flags           */

  /* signals to control the daemon */

#ifdef SIGHUP
  retry_sigaction(FIL__, __LINE__, SIGHUP,     &act2, &oldact);
#endif
#ifdef SIGABRT
  retry_sigaction(FIL__, __LINE__, SIGABRT,    &act2, &oldact);
#endif
#ifdef SIGUSR1
  retry_sigaction(FIL__, __LINE__, SIGUSR1,    &act2, &oldact);
#endif
#ifdef SIGUSR2
  retry_sigaction(FIL__, __LINE__, SIGUSR2,    &act2, &oldact);
#endif
#ifdef SIGQUIT
  retry_sigaction(FIL__, __LINE__, SIGQUIT,    &act2, &oldact);
#endif
#ifdef SIGTERM
  retry_sigaction(FIL__, __LINE__, SIGTERM,    &act,  &oldact);
#endif

  /* fatal signals that may cause termination */

#ifdef SIGILL
  retry_sigaction(FIL__, __LINE__, SIGILL,  &act_fast, &oldact);
#endif
#ifndef SL_DEBUG
#ifdef SIGFPE
  retry_sigaction(FIL__, __LINE__, SIGFPE,  &act_fast, &oldact);
#endif
#endif
#ifdef SIGSEGV
  retry_sigaction(FIL__, __LINE__, SIGSEGV, &act_fast, &oldact);
#endif
#ifdef SIGBUS
  retry_sigaction(FIL__, __LINE__, SIGBUS,  &act_fast, &oldact);
#endif

  /* other signals  */

#ifdef SIGINT
  retry_sigaction(FIL__, __LINE__, SIGINT,       &act, &oldact);
#endif
#ifdef SIGPIPE
#ifdef HAVE_PTHREAD
  retry_sigaction(FIL__, __LINE__, SIGPIPE,   &ignact, &oldact);
#else
  retry_sigaction(FIL__, __LINE__, SIGPIPE,      &act, &oldact);
#endif
#endif
#ifdef SIGALRM
  retry_sigaction(FIL__, __LINE__, SIGALRM,   &ignact, &oldact);
#endif
#ifdef SIGTSTP
  retry_sigaction(FIL__, __LINE__, SIGTSTP,   &ignact, &oldact);
#endif
#ifdef SIGTTIN
  retry_sigaction(FIL__, __LINE__, SIGTTIN,   &ignact, &oldact);
#endif
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
#ifdef SIGTTOU
  if (goDaemon == 1)
    retry_sigaction(FIL__, __LINE__, SIGTTOU,     &act2, &oldact);
  else
    retry_sigaction(FIL__, __LINE__, SIGTTOU,   &ignact, &oldact);
#endif
#else
#ifdef SIGTTOU
  retry_sigaction(FIL__, __LINE__, SIGTTOU,   &ignact, &oldact);
#endif
#endif

#ifdef SIGTRAP
#if !defined(SCREW_IT_UP)
  retry_sigaction(FIL__, __LINE__, SIGTRAP,      &act, &oldact);
#endif
#endif

#ifdef SIGPOLL
  retry_sigaction(FIL__, __LINE__, SIGPOLL,   &ignact, &oldact);
#endif
#if defined(SIGPROF) && !defined(SH_PROFILE)
  retry_sigaction(FIL__, __LINE__, SIGPROF,   &ignact, &oldact);
#endif
#ifdef SIGSYS
  retry_sigaction(FIL__, __LINE__, SIGSYS,       &act, &oldact);
#endif
#ifdef SIGURG
  retry_sigaction(FIL__, __LINE__, SIGURG,    &ignact, &oldact);
#endif
#if defined(SIGVTALRM) && !defined(SH_PROFILE)
  retry_sigaction(FIL__, __LINE__, SIGVTALRM, &ignact, &oldact);
#endif
#ifdef SIGXCPU
  retry_sigaction(FIL__, __LINE__, SIGXCPU,      &act, &oldact);
#endif
#ifdef SIGXFSZ
  retry_sigaction(FIL__, __LINE__, SIGXFSZ,      &act, &oldact);
#endif

#ifdef SIGEMT
  retry_sigaction(FIL__, __LINE__, SIGEMT,    &ignact, &oldact);
#endif
#ifdef SIGSTKFLT
  retry_sigaction(FIL__, __LINE__, SIGSTKFLT,    &act, &oldact);
#endif
#ifdef SIGIO
  retry_sigaction(FIL__, __LINE__, SIGIO,     &ignact, &oldact);
#endif
#ifdef SIGPWR
  retry_sigaction(FIL__, __LINE__, SIGPWR,       &act, &oldact);
#endif

#ifdef SIGLOST
  retry_sigaction(FIL__, __LINE__, SIGLOST,   &ignact, &oldact);
#endif
#ifdef SIGUNUSED
  retry_sigaction(FIL__, __LINE__, SIGUNUSED, &ignact, &oldact);
#endif

  SL_RET0(_("sh_unix_siginstall"));
}

/* ---------------------------------------------------------------- */

/* checksum the own binary
 */
int sh_unix_self_hash (const char * c)
{
  char message[512];
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_unix_self_hash"));

  if (c == NULL)
    {
      sh.exec.path[0] = '\0';
      SL_RETURN((0), _("sh_unix_self_hash"));
    }
  sl_strlcpy(sh.exec.path, c, SH_PATHBUF);

  sl_strlcpy(sh.exec.hash,
	     sh_tiger_hash (c, TIGER_FILE, TIGER_NOLIM, hashbuf, sizeof(hashbuf)), 
	     KEY_LEN+1);
  sl_snprintf(message, 512, _("%s has checksum: %s"),
	      sh.exec.path, sh.exec.hash);
  message[511] = '\0';
  sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		  message, _("sh_unix_self_hash"));
  if (0 == sl_strcmp(sh.exec.hash, SH_KEY_NULL ))
    {
      dlog(1, FIL__, __LINE__, 
	   _("Could not checksum my own executable because of the\nfollowing error: %s: %s\n\nPossible reasons include:\n  Wrong path in configure file option SamhainPath=/path/to/executable\n  No read permission for the effective UID: %d\n"), 
	   sh.exec.path, sl_get_errmsg(), (int) sl_ret_euid());
      sh_error_handle ((-1), FIL__, __LINE__, EACCES, MSG_NOACCESS,
		       (long) sh.real.uid, c);
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
    }
  SL_RETURN((0), _("sh_unix_self_hash"));
}

int sh_unix_self_check ()
{
  char newhash[KEY_LEN+1];
  char message[512];
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_unix_self_check"));
  if (sh.exec.path == NULL || sh.exec.path[0] == '\0')
    SL_RETURN((0), _("sh_unix_self_check"));

  sl_strlcpy(newhash, 
	     sh_tiger_hash (sh.exec.path, TIGER_FILE, TIGER_NOLIM, hashbuf, sizeof(hashbuf)), 
	     KEY_LEN+1);
  if (0 == sl_strncmp(sh.exec.hash, 
		      newhash,
		      KEY_LEN))
    SL_RETURN((0), _("sh_unix_self_check"));

 
  dlog(1, FIL__, __LINE__, 
       _("The checksum of the executable: %s has changed since startup (%s -> %s).\n"),
       sh.exec.path, sh.exec.hash, newhash);

  sl_snprintf(message, 512, 
	      _("The checksum of %s has changed since startup (%s -> %s)"),
	      sh.exec.path, sh.exec.hash, newhash);
  message[511] = '\0';

  sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		  message, _("sh_unix_self_check"));
  sh_error_handle ((-1), FIL__, __LINE__, EACCES, MSG_E_AUTH,
		   sh.exec.path);
  SL_RETURN((-1), _("sh_unix_self_check"));
}


/* ---------------------------------------------------------------- */


/* added    Tue Feb 22 10:36:44 NFT 2000 Rainer Wichmann            */
static int tf_add_trusted_user_int(const char * c)
{
  struct passwd *          w;
  int                           count;
  uid_t                     pwid  = (uid_t)-1;

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  struct passwd    pwd;
  char           * buffer;
#endif
  
  SL_ENTER(_("tf_add_trusted_user_int"));

  /* First check for a user name.
   */
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  buffer = SH_ALLOC(SH_PWBUF_SIZE);
  sh_getpwnam_r(c, &pwd, buffer, SH_PWBUF_SIZE, &w);
#else
  w = sh_getpwnam(c);
#endif

  if ((w != NULL) && ((pwid = w->pw_uid) > 0))
    goto succe;
	
  /* Failed, so check for a numerical value.
   */
  pwid = strtol(c, (char **)NULL, 10);
  if (pwid > 0 && pwid < 65535)
    goto succe;
      
  sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS, 
		   _("add trusted user"), c);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  SH_FREE(buffer);
#endif
  SL_RETURN((-1), _("tf_add_trusted_user_int"));

 succe:
  count = sl_trust_add_user(pwid);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  SH_FREE(buffer);
#endif
  SL_RETURN((count), _("tf_add_trusted_user_int"));
}

int tf_add_trusted_user(const char * c)
{
  int    i;
  char * q;
  char * p = sh_util_strdup (c);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
  char * saveptr;
#endif

  SL_ENTER(_("tf_add_trusted_user"));

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
  q = strtok_r(p, ", \t", &saveptr);
#else
  q = strtok(p, ", \t");
#endif
  if (!q)
    {
      SH_FREE(p);
      SL_RETURN((-1), _("tf_add_trusted_user"));
    }
  while (q)
    {
      i = tf_add_trusted_user_int(q);
      if (SL_ISERROR(i))
	{
	  SH_FREE(p);
	  SL_RETURN((i), _("tf_add_trusted_user"));
	}
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
      q = strtok_r(NULL, ", \t", &saveptr);
#else
      q = strtok(NULL, ", \t");
#endif
    }
  SH_FREE(p);
  SL_RETURN((0), _("tf_add_trusted_user"));
}

extern uid_t   sl_trust_baduid(void);
extern gid_t   sl_trust_badgid(void);

#if defined(HOST_IS_CYGWIN) || defined(__cygwin__) || defined(__CYGWIN32__) || defined(__CYGWIN__)
int tf_trust_check (const char * file, int mode)
{
  (void) file;
  (void) mode;
  return 0;
}
#else
int tf_trust_check (const char * file, int mode)
{
  char * tmp;
  char * tmp2;
  char * p;
  int    status;
  int    level;
  uid_t  ff_euid;

  SL_ENTER(_("tf_trust_check"));

  if (mode == SL_YESPRIV)
    sl_get_euid(&ff_euid);
  else
    sl_get_ruid(&ff_euid);

#if defined(SH_WITH_SERVER)
  if (0 == sl_ret_euid())   /* privileges not dropped yet */
    {
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
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}
      ff_euid = tempres->pw_uid;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      SH_FREE(buffer);
#endif
    }
#endif

  status = sl_trustfile_euid(file, ff_euid);

  if ( SL_ENONE != status) 
    {
      if (status == SL_ESTAT) 
	level = SH_ERR_ALL;
      else
	level = SH_ERR_ERR;

      tmp  = sh_util_safe_name (file);
      p    = sl_trust_errfile();
      if (p && *p != '\0')
	{
	  tmp2  = sh_util_safe_name (sl_trust_errfile());
	  sh_error_handle(level, FIL__, __LINE__, status, MSG_E_TRUST2,
			  sl_error_string(status), tmp, tmp2);
	  SH_FREE(tmp2);  
	}
      else
	{
	  sh_error_handle(level, FIL__, __LINE__, status, MSG_E_TRUST1,
			  sl_error_string(status), tmp);
	}
      SH_FREE(tmp);

      if (status == SL_EBADUID   || status == SL_EBADGID || 
	  status == SL_EBADOTH   || status == SL_ETRUNC  || 
	  status == SL_EINTERNAL )
	{
	  switch (status) {
	  case SL_EINTERNAL:
	    dlog(1, FIL__, __LINE__, 
		 _("An internal error occured in the trustfile function.\n"));
	    break;
	  case SL_ETRUNC:
	    tmp  = sh_util_safe_name (file);
	    dlog(1, FIL__, __LINE__, 
		 _("A filename truncation occured in the trustfile function.\nProbably the normalized filename for %s\nis too long. This may be due e.g. to deep or circular softlinks.\n"), 
		 tmp);
	    SH_FREE(tmp);
	    break;
	  case SL_EBADOTH:
	    tmp  = sh_util_safe_name (file);
	    p    = sl_trust_errfile();
	    dlog(1, FIL__, __LINE__, 
		 _("The path element: %s\nin the filename: %s is world writeable.\n"),
		 p, tmp);
	    SH_FREE(tmp);
	    break;
	  case SL_EBADUID:
	    tmp  = sh_util_safe_name (file);
	    p    = sl_trust_errfile();
	    dlog(1, FIL__, __LINE__, 
		 _("The owner (UID = %ld) of the path element: %s\nin the filename: %s\nis not in the list of trusted users.\nTo fix the problem, you can:\n - run ./configure again with the option --with-trusted=0,...,UID\n   where UID is the UID of the untrusted user, or\n - use the option TrustedUser=UID in the configuration file.\n"),
		 (UID_CAST)sl_trust_baduid(), p, tmp);
	    SH_FREE(tmp);
	    break;
	  case SL_EBADGID:
	    tmp  = sh_util_safe_name (file);
	    p    = sl_trust_errfile();
	    dlog(1, FIL__, __LINE__, 
		 _("The path element: %s\nin the filename: %s\nis group writeable (GID = %ld), and at least one of the group\nmembers (UID = %ld) is not in the list of trusted users.\nTo fix the problem, you can:\n - run ./configure again with the option --with-trusted=0,...,UID\n   where UID is the UID of the untrusted user, or\n - use the option TrustedUser=UID in the configuration file.\n"),
		 p, tmp, (UID_CAST)sl_trust_badgid(), 
		 (UID_CAST)sl_trust_baduid());
	    SH_FREE(tmp);
	    break;
	  default:
	    break;
	  }
	    
	  SL_RETURN((-1), _("tf_trust_check"));
	}
    }

  SL_RETURN((0), _("tf_trust_check"));
}
#endif

#ifdef HAVE_INITGROUPS
#ifdef HOST_IS_OSF
int  sh_unix_initgroups (      char * in_user, gid_t in_gid)
#else
int  sh_unix_initgroups (const char * in_user, gid_t in_gid)
#endif
{
  int status  = -1;
  status = sh_initgroups (in_user, in_gid);
  if (status < 0)
    {
      if (errno == EPERM)
	return 0;
      if (errno == EINVAL)
	return 0;
      return -1;
    }
  return 0;
}
#else
int  sh_unix_initgroups (const char * in_user, gid_t in_gid)
{
  (void) in_user;
  (void) in_gid;
  return 0;
}
#endif

#ifdef HAVE_INITGROUPS
char *  sh_unix_getUIDname (int level, uid_t uid, char * out, size_t len);
int  sh_unix_initgroups2 (uid_t in_pid, gid_t in_gid)
{
  int status  = -1;
  char user[SH_MINIBUF];

  SL_ENTER(_("sh_unix_initgroups2"));

  if (NULL == sh_unix_getUIDname (SH_ERR_ERR, in_pid, user, sizeof(user)))
    SL_RETURN((-1), _("sh_unix_initgroups2"));
  status = sh_initgroups (user, in_gid);
  if (status < 0)
    {
      if (errno == EPERM)
	status = 0;
      if (errno == EINVAL)
	status = 0;
    }
  SL_RETURN((status), _("sh_unix_initgroups2"));
}
#else
int  sh_unix_initgroups2 (uid_t in_pid, gid_t in_gid)
{
  (void) in_pid;
  (void) in_gid;
  return 0;
}
#endif

void sh_unix_closeall (int fd, int except, int inchild)
{
  int fdx = fd;
#ifdef _SC_OPEN_MAX
  int fdlimit = sysconf (_SC_OPEN_MAX);
#else
#ifdef OPEN_MAX
  int fdlimit = OPEN_MAX;
#else
  int fdlimit = _POSIX_OPEN_MAX;
#endif
#endif

  SL_ENTER(_("sh_unix_closeall"));

  /* can't happen - so fix it :-(
   */
  if (fdlimit < 0)
    fdlimit = 20;  /* POSIX lower limit */

  if (fdlimit > 65536)
    fdlimit = 65536;

  if (!inchild)
    sl_dropall (fdx, except);
  else
    sl_dropall_dirty (fdx, except);

  /* Close everything from fd (inclusive) up to fdlimit (exclusive). 
   */
  while (fd < fdlimit)
    {
      if (fd == except)
	fd++;
      else if (slib_do_trace != 0 && fd == slib_trace_fd)
	fd++;
      else
	sl_close_fd(FIL__, __LINE__, fd++);
    }

  SL_RET0(_("sh_unix_closeall"));
}

static void sh_unix_setlimits(void)
{
  struct rlimit limits;

  SL_ENTER(_("sh_unix_setlimits"));

  limits.rlim_cur = RLIM_INFINITY;
  limits.rlim_max = RLIM_INFINITY;

#ifdef RLIMIT_CPU
  setrlimit (RLIMIT_CPU,     &limits);
#endif
#ifdef RLIMIT_FSIZE
  setrlimit (RLIMIT_FSIZE,   &limits);
#endif
#ifdef RLIMIT_DATA
  setrlimit (RLIMIT_DATA,    &limits);
#endif
#ifdef RLIMIT_STACK
  setrlimit (RLIMIT_STACK,   &limits);
#endif
#ifdef RLIMIT_RSS
  setrlimit (RLIMIT_RSS,     &limits);
#endif
#ifdef RLIMIT_NPROC
  setrlimit (RLIMIT_NPROC,   &limits);
#endif
#ifdef RLIMIT_MEMLOCK
  setrlimit (RLIMIT_MEMLOCK, &limits);
#endif

#if !defined(SL_DEBUG)
  /* no core dumps
   */
  limits.rlim_cur = 0;
  limits.rlim_max = 0;
#ifdef RLIMIT_CORE
  setrlimit (RLIMIT_CORE,    &limits);
#endif
#else
#ifdef RLIMIT_CORE
  setrlimit (RLIMIT_CORE,    &limits);
#endif
#endif

  limits.rlim_cur = 1024;
  limits.rlim_max = 1024;

#if defined(RLIMIT_NOFILE)
  setrlimit (RLIMIT_NOFILE,  &limits);
#elif defined(RLIMIT_OFILE)
  setrlimit (RLIMIT_OFILE,   &limits);
#endif

  SL_RET0(_("sh_unix_setlimits"));
}

static void sh_unix_copyenv(void)
{
  char ** env0 = environ; 
  char ** env1;
  int   envlen = 0;
  size_t len;

  SL_ENTER(_("sh_unix_copyenv"));

  while (env0 != NULL && env0[envlen] != NULL) { 
    /* printf("%2d: %s\n", envlen, env0[envlen]); */
    ++envlen; 
  }
  ++envlen;

  /* printf("-> %2d: slots allocated\n", envlen); */
  env1 = malloc (sizeof(char *) * envlen);      /* only once */
  if (env1 == NULL)
    {
      fprintf(stderr, _("%s: %d: Out of memory\n"), FIL__, __LINE__);
      SL_RET0(_("sh_unix_copyenv"));
    }
  env0   = environ;
  envlen = 0;

  while (env0 != NULL && env0[envlen] != NULL) {
    len = strlen(env0[envlen]) + 1;
    env1[envlen] = malloc (len); /* only once */
    if (env1[envlen] == NULL)
      {
	fprintf(stderr, _("%s: %d: Out of memory\n"), FIL__, __LINE__);
	SL_RET0(_("sh_unix_copyenv"));
      }
    sl_strlcpy(env1[envlen], env0[envlen], len);
    ++envlen;
  }
  env1[envlen] = NULL;

  environ = env1;
  SL_RET0(_("sh_unix_copyenv"));
}

/* delete all environment variables
 */
static void sh_unix_zeroenv(void)
{
  char * c;
  char ** env;

  SL_ENTER(_("sh_unix_zeroenv"));

  sh_unix_copyenv();
  env = environ;

  while (env != NULL && *env != NULL) {
    c = strchr ((*env), '=');
#ifdef WITH_MYSQL 
    /* 
     * Skip the MYSQL_UNIX_PORT environment variable; MySQL may need it.
     */
    if (0 == sl_strncmp((*env), _("MYSQL_UNIX_PORT="), 16))
      {
	++(env);
	continue;
      }
    if (0 == sl_strncmp((*env), _("MYSQL_TCP_PORT="), 15))
      {
	++(env);
	continue;
      }
    if (0 == sl_strncmp((*env), _("MYSQL_HOME="), 11))
      {
	++(env);
	continue;
      }
#endif
#ifdef WITH_ORACLE
    /* 
     * Skip the ORACLE_HOME environment variable; Oracle may need it.
     */
    if (0 == sl_strncmp((*env), _("ORACLE_HOME="), 12))
      {
	++(env);
	continue;
      }
#endif
    /* 
     * Skip the TZ environment variable.
     */
    if (0 == sl_strncmp((*env), _("TZ="), 3))
      {
	++(env);
	continue;
      }
    ++(env);
    if (c != NULL)
      {
	++c;
	while ((*c) != '\0') {
	  (*c) = '\0';
	  ++c;
	}
      }
  }

#ifdef HAVE_TZSET
  tzset();
#endif

  SL_RET0(_("sh_unix_zeroenv"));
}


static void  sh_unix_resettimer(void)
{
  struct itimerval this_timer;

  SL_ENTER(_("sh_unix_resettimer"));

  this_timer.it_value.tv_sec  = 0;
  this_timer.it_value.tv_usec = 0;

  this_timer.it_interval.tv_sec  = 0;
  this_timer.it_interval.tv_usec = 0;

  setitimer(ITIMER_REAL,    &this_timer, NULL);
#if !defined(SH_PROFILE)
  setitimer(ITIMER_VIRTUAL, &this_timer, NULL);
  setitimer(ITIMER_PROF,    &this_timer, NULL);
#endif

  SL_RET0(_("sh_unix_resettimer"));
}

static void  sh_unix_resetsignals(void)
{
  int  sig_num;
#ifdef NSIG
  int  max_sig = NSIG; 
#else
  int  max_sig = 255;
#endif
  int  test;
  int  status;
  struct sigaction act;
#if !defined(SH_PROFILE)
  struct sigaction oldact;
#endif

  sigset_t set_proc;

  SL_ENTER(_("sh_unix_resetsignals"));
  /* 
   * Reset the current signal mask (inherited from parent process).
   */

  sigfillset(&set_proc);

  do {
    errno = 0;
    test  = sigprocmask(SIG_UNBLOCK, &set_proc, NULL);
  } while (test < 0 && errno == EINTR);

  /* 
   * Reset signal handling.
   */
  
  act.sa_handler = SIG_DFL;         /* signal action           */
  sigemptyset( &act.sa_mask );      /* set an empty mask       */
  act.sa_flags = 0;                 /* init sa_flags           */

  for (sig_num = 1; sig_num <= max_sig; ++sig_num) 
    {
#if !defined(SH_PROFILE)
      test = retry_sigaction(FIL__, __LINE__, sig_num,  &act, &oldact);
#else
      test = 0;
#endif
      if ((test == -1) && (errno != EINVAL)) 
	{
	  char errbuf[SH_ERRBUF_SIZE];
	  status = errno;
	  sh_error_handle ((-1), FIL__, __LINE__, status, MSG_W_SIG,
			   sh_error_message (status, errbuf, sizeof(errbuf)), sig_num);
	}
    }

  SL_RET0(_("sh_unix_resetsignals"));
}

/* Get the local hostname (FQDN)
 */
#include <sys/socket.h> 

/* Required for BSD
 */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <arpa/inet.h>

const char * sh_unix_h_name (struct hostent * host_entry)
{
	char ** p;
	if (strchr(host_entry->h_name, '.')) {
		return host_entry->h_name;
	} else {
		for (p = host_entry->h_aliases; *p; ++p) {
			if (strchr(*p, '.'))
				return *p;
		}
	}
	return host_entry->h_name;
}

/* uname() on FreeBSD is broken, because the 'nodename' buf is too small
 * to hold a valid (leftmost) domain label.
 */
#if defined(HAVE_UNAME) && !defined(HOST_IS_FREEBSD)
#include <sys/utsname.h>
void sh_unix_localhost()
{
  struct utsname   buf;
  struct hostent * he1;
  int              i;
  int              ddot;
  int              len;
  char           * p;
  char             hostname[256];


  SL_ENTER(_("sh_unix_localhost"));

  (void) uname (&buf);
  /* flawfinder: ignore */ /* ff bug, ff sees system() */
  sl_strlcpy (sh.host.system,  buf.sysname, SH_MINIBUF);
  sl_strlcpy (sh.host.release, buf.release, SH_MINIBUF);
  sl_strlcpy (sh.host.machine, buf.machine, SH_MINIBUF);

  /* Workaround for cases where nodename could be 
   * a truncated FQDN.
   */
  if (strlen(buf.nodename) == (sizeof(buf.nodename)-1))
    {
      p = strchr(buf.nodename, '.');
      if (NULL != p) {
	*p = '\0';
	sl_strlcpy(hostname, buf.nodename, 256);
      } else {
#ifdef HAVE_GETHOSTNAME
	if (0 != gethostname(hostname, 256))
	  {
	    sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    _("nodename returned by uname may be truncated"), 
			    _("sh_unix_localhost"));
	    sl_strlcpy (hostname, buf.nodename, 256);
	  }
	else
	  {
	    hostname[255] = '\0';
	  }
#else
	sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			_("nodename returned by uname may be truncated"), 
			_("sh_unix_localhost"));
	sl_strlcpy(hostname, buf.nodename, 256);
#endif
      }
    }
  else
    {
      sl_strlcpy(hostname, buf.nodename, 256);
    }

  SH_MUTEX_LOCK(mutex_resolv);
  he1 = sh_gethostbyname(hostname);

  if (he1 != NULL)
    {
      sl_strlcpy (sh.host.name, sh_unix_h_name(he1), SH_PATHBUF);
    }
  SH_MUTEX_UNLOCK(mutex_resolv);

  if (he1 == NULL)
    {
      dlog(1, FIL__, __LINE__, 
	   _("According to uname, your nodename is %s, but your resolver\nlibrary cannot resolve this nodename to a FQDN. For more information, see the entry about self-resolving under 'Most frequently' in the FAQ that you will find in the docs/ subdirectory.\n"),
	   hostname);
      sl_strlcpy (sh.host.name, hostname,    SH_PATHBUF);
    }
  

  /* check whether it looks like a FQDN
   */
  len = sl_strlen(sh.host.name);
  ddot = 0;
  for (i = 0; i < len; ++i) 
    if (sh.host.name[i] == '.') ++ddot; 

  if (ddot == 0 && he1 != NULL)
    { 
      dlog(1, FIL__, __LINE__, 
	   _("According to uname, your nodename is %s, but your resolver\nlibrary cannot resolve this nodename to a FQDN.\nRather, it resolves this to %s.\nFor more information, see the entry about self-resolving under\n'Most frequently' in the FAQ that you will find in the docs/ subdirectory.\n"),
	   hostname, sh.host.name);
      sl_strlcpy (sh.host.name, 
		  inet_ntoa (*(struct in_addr *) he1->h_addr), 
		  SH_PATHBUF);
      SL_RET0(_("sh_unix_localhost"));
    } 

  if (is_numeric(sh.host.name)) 
    {
      dlog(1, FIL__, __LINE__, 
	   _("According to uname, your nodename is %s, but your resolver\nlibrary cannot resolve this nodename to a FQDN.\nRather, it resolves this to %s.\nFor more information, see the entry about self-resolving under\n'Most frequently' in the FAQ that you will find in the docs/ subdirectory.\n"),
	   hostname, sh.host.name);
    }

  SL_RET0(_("sh_unix_localhost"));
}

#else

/* 
 * --FreeBSD code 
 */
#if defined(HAVE_UNAME)
#include <sys/utsname.h>
#endif
void sh_unix_localhost()
{
#if defined(HAVE_UNAME)
  struct utsname   buf;
#endif
  struct hostent * he1;
  int              i;
  int              ddot;
  int              len;
  char             hostname[1024];


  SL_ENTER(_("sh_unix_localhost"));

#if defined(HAVE_UNAME)
  (void) uname (&buf);
  /* flawfinder: ignore */ /* ff bug, ff sees system() */
  sl_strlcpy (sh.host.system,  buf.sysname, SH_MINIBUF);
  sl_strlcpy (sh.host.release, buf.release, SH_MINIBUF);
  sl_strlcpy (sh.host.machine, buf.machine, SH_MINIBUF);
#endif

  (void) gethostname (hostname, 1024);
  hostname[1023] = '\0';

  SH_MUTEX_LOCK(mutex_resolv);
  he1 = sh_gethostbyname(hostname);

  if (he1 != NULL)
    {
      sl_strlcpy (sh.host.name, sh_unix_h_name(he1), SH_PATHBUF);
    }
  SH_MUTEX_UNLOCK(mutex_resolv);

  if (he1 == NULL)
    {
      dlog(1, FIL__, __LINE__, 
	   _("According to gethostname, your nodename is %s, but your resolver\nlibrary cannot resolve this nodename to a FQDN.\nFor more information, see the entry about self-resolving under\n'Most frequently' in the FAQ that you will find in the docs/ subdirectory.\n"),
	   hostname);
      sl_strlcpy (sh.host.name, _("localhost"), SH_PATHBUF);
      SL_RET0(_("sh_unix_localhost"));
    }

  /* check whether it looks like a FQDN
   */
  len = sl_strlen(sh.host.name);
  ddot = 0;
  for (i = 0; i < len; ++i) 
    if (sh.host.name[i] == '.') ++ddot; 
  if (ddot == 0) 
    {
      dlog(1, FIL__, __LINE__, 
	   _("According to uname, your nodename is %s, but your resolver\nlibrary cannot resolve this nodename to a FQDN.\nRather, it resolves this to %s.\nFor more information, see the entry about self-resolving under\n'Most frequently' in the FAQ that you will find in the docs/ subdirectory.\n"),
	   hostname, sh.host.name);
      sl_strlcpy (sh.host.name, 
		  inet_ntoa (*(struct in_addr *) he1->h_addr), 
		  SH_PATHBUF);
      SL_RET0(_("sh_unix_localhost"));
    }

  if (is_numeric(sh.host.name)) 
    {
      dlog(1, FIL__, __LINE__, 
	   _("According to uname, your nodename is %s, but your resolver\nlibrary cannot resolve this nodename to a FQDN.\nRather, it resolves this to %s.\nFor more information, see the entry about self-resolving under\n'Most frequently' in the FAQ that you will find in the docs/ subdirectory.\n"),
	   hostname, sh.host.name);
    }

  SL_RET0(_("sh_unix_localhost"));
}
#endif


void sh_unix_memlock()
{
  SL_ENTER(_("sh_unix_memlock"));

  /* do this before dropping privileges
   */
#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
  if (skey->mlock_failed == SL_FALSE)
    {
      if ( (-1) == sh_unix_mlock( FIL__, __LINE__, 
				  (char *) skey, sizeof (sh_key_t)) ) 
	{
	  SH_MUTEX_LOCK_UNSAFE(mutex_skey);
	  skey->mlock_failed = SL_TRUE;
	  SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);
	}
    }
#else
  if (skey->mlock_failed == SL_FALSE)
    {
      SH_MUTEX_LOCK_UNSAFE(mutex_skey);
      skey->mlock_failed = SL_TRUE;
      SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);
    }
#endif

  SL_RET0(_("sh_unix_memlock"));
}

#ifdef SH_WITH_SERVER
char * chroot_dir = NULL;

int sh_unix_set_chroot(const char * str)
{
  size_t len;
  static int block = 0;

  if (block == 1)
    return 0;

  if (str && *str == '/')
    {
      len = strlen(str) + 1;
      chroot_dir = malloc(strlen(str) + 1);  /* only once */
      if (!chroot_dir)
	{
	  fprintf(stderr, _("%s: %d: Out of memory\n"), FIL__, __LINE__);
	  return 1;
	}
      sl_strlcpy(chroot_dir, str, len);
      block = 1;
      return 0;
    }
  return 1;
}

int sh_unix_chroot(void)
{
  int status;

  if (chroot_dir != NULL)
    {
      status = retry_aud_chdir(FIL__, __LINE__, chroot_dir);
      if ( (-1) == status ) 
	{
	  char errbuf[SH_ERRBUF_SIZE];
	  status = errno;
	  sh_error_handle ((-1), FIL__, __LINE__, status, MSG_W_CHDIR,
			   sh_error_message (status, errbuf, sizeof(errbuf)), chroot_dir);
	  aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	}
      /* flawfinder: ignore */
      return (chroot(chroot_dir));
    }
  return 0;
}
/* #ifdef SH_WITH_SERVER */
#else
int sh_unix_chroot(void) { return 0; }
#endif

/* daemon mode 
 */
static int block_setdeamon = 0;

int sh_unix_setdeamon(const char * dummy)
{
  int    res = 0;

  SL_ENTER(_("sh_unix_setdeamon"));

  if (block_setdeamon != 0)
    SL_RETURN((0),_("sh_unix_setdeamon"));

  if (dummy == NULL)
    sh.flag.isdaemon = ON;
  else 
    res = sh_util_flagval (dummy, &sh.flag.isdaemon);

  if (sh.flag.opts == S_TRUE)  
    block_setdeamon = 1;
	   
  SL_RETURN(res, _("sh_unix_setdeamon"));
}
#if defined(HAVE_LIBPRELUDE)
#include "sh_prelude.h"
#endif

int sh_unix_setnodeamon(const char * dummy)
{
  int    res = 0;
  
  SL_ENTER(_("sh_unix_setnodeamon"));

  if (block_setdeamon != 0)
    SL_RETURN((0),_("sh_unix_setmodeamon"));

  if (dummy == NULL)
    sh.flag.isdaemon = OFF;
  else 
    res = sh_util_flagval (dummy, &sh.flag.isdaemon);

  if (sh.flag.opts == S_TRUE)  
    block_setdeamon = 1;
	   
  SL_RETURN(res, _("sh_unix_setnodeamon"));
}

int sh_unix_init(int goDaemon)
{
  int    status;
  uid_t  uid;
  pid_t  oldpid = getpid();
#if defined(SH_WITH_SERVER) 
  extern int sh_socket_open_int (void);
#endif
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("sh_unix_init"));

  /* fork twice, exit the parent process
   */
  if (goDaemon == 1) {
    
    switch (aud_fork(FIL__, __LINE__)) {
    case 0:  break;                             /* child process continues */
    case -1: SL_RETURN((-1),_("sh_unix_init")); /* error                   */
    default: aud__exit(FIL__, __LINE__, 0);     /* parent process exits    */
    }

    /* Child processes do not inherit page locks across a fork.
     * Error in next fork would return in this (?) thread of execution.
     */
    sh_unix_memlock();

    setsid();            /* should not fail         */
    sh.pid = (UINT64) getpid();

    switch (aud_fork(FIL__, __LINE__)) {
    case 0:  break;                             /* child process continues */
    case -1: SL_RETURN((-1),_("sh_unix_init")); /* error                   */
    default: aud__exit(FIL__, __LINE__, 0);     /* parent process exits    */
    }

    /* Child processes do not inherit page locks across a fork.
     */
    sh_unix_memlock();
    sh.pid = (UINT64) getpid();

  } else {
    setsid();            /* should not fail         */
  } 

  /* set working directory   
   */
#ifdef SH_PROFILE
  status = 0;
#else
  status = retry_aud_chdir(FIL__, __LINE__, "/");
#endif
  if ( (-1) == status ) 
    {
      status = errno;
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_W_CHDIR,
		       sh_error_message (status, errbuf, sizeof(errbuf)), "/");
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  /* reset timers 
   */
  sh_unix_resettimer();

  /* signal handlers 
   */
  sh_unix_resetsignals();
#if defined(SCREW_IT_UP)
  sh_sigtrap_prepare();
#endif
  sh_unix_siginstall  (goDaemon);

  /* set file creation mask 
   */
  (void) umask (0); /* should not fail */

  /* set resource limits to maximum, and
   * core dump size to zero 
   */
  sh_unix_setlimits();

  /* zero out the environment (like PATH='\0')  
   */
  sh_unix_zeroenv();

  if (goDaemon == 1)
    {
      /* Close first tree file descriptors 
       */ 
      sl_close_fd (FIL__, __LINE__, 0);  /* if running as daemon */
      sl_close_fd (FIL__, __LINE__, 1);  /* if running as daemon */
      sl_close_fd (FIL__, __LINE__, 2);  /* if running as daemon */

      /* Enable full error logging
       */
      sh_error_only_stderr (S_FALSE);

      /* open first three streams to /dev/null 
       */
      status = aud_open(FIL__, __LINE__, SL_NOPRIV, _("/dev/null"), O_RDWR, 0);
      if (status < 0)
	{
	  status = errno;
	  sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGEN, 
			  sh_error_message(status, errbuf, sizeof(errbuf)), _("open"));
	  aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	}

      status = retry_aud_dup(FIL__, __LINE__, 0); 
      if (status >= 0)
	retry_aud_dup(FIL__, __LINE__, 0);

      if (status < 0)
	{
	  status = errno;
	  sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGEN, 
			  sh_error_message(status, errbuf, sizeof(errbuf)), _("dup"));
	  aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	}

      sh_error_enable_unsafe (S_TRUE);
#if defined(HAVE_LIBPRELUDE)
      sh_prelude_reset ();
#endif

      /* --- wait until parent has exited ---
       */
      while (1 == 1)
	{
	  errno = 0;
	  if (0 > aud_kill (FIL__, __LINE__, oldpid, 0) && errno == ESRCH)
	    {
	      break;
	    }
	  retry_msleep(0, 1);
	}

      /* write PID file
       */
      status = sh_unix_write_pid_file();
      if (status < 0)
	{
	  sl_get_euid(&uid);
	  sh_error_handle ((-1), FIL__, __LINE__, status, MSG_PIDFILE,
			   (long) uid, sh.srvlog.alt);
	  aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	}
#if defined(SH_WITH_SERVER) 
      sh_socket_open_int ();
#endif
    }
  else
    {
      sh_error_enable_unsafe (S_TRUE);
#if defined(HAVE_LIBPRELUDE)
      sh_prelude_reset ();
#endif
#if defined(SH_WITH_SERVER) 
      sh_socket_open_int ();
#endif
    }

  /* chroot (this is a no-op if no chroot dir is specified
   */
  status = sh_unix_chroot();
  if (status < 0)
    {
      status = errno;
      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGEN, 
			  sh_error_message(status, errbuf, sizeof(errbuf)), _("chroot"));
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  /* drop capabilities
   */
  sl_drop_cap();

  SL_RETURN((0),_("sh_unix_init"));
}

/* --- run a command, securely --- */

int sh_unix_run_command (const char * str)
{
  pid_t  pid;
  char * arg[4];
  char * env[5];
  char * path = sh_util_strdup(_("/bin/sh"));

  int  status = -1;

  arg[0] = sh_util_strdup(_("/bin/sh"));
  arg[1] = sh_util_strdup(_("-c"));
  arg[2] = sh_util_strdup(str);
  arg[3] = NULL;

  env[0] = sh_util_strdup(_("PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/ucb"));
  env[1] = sh_util_strdup(_("SHELL=/bin/sh"));
  env[2] = sh_util_strdup(_("IFS= \t\n"));
  if (getenv("TZ")) {                         /* flawfinder: ignore */
    char * tz = sh_util_strdup(getenv("TZ")); /* flawfinder: ignore */
    size_t tzlen = strlen(tz);
    if (SL_TRUE == sl_ok_adds (4, tzlen)) {
	env[3] = SH_ALLOC(4+tzlen);
	sl_strlcpy(env[3], "TZ=", 4);
	sl_strlcat(env[3], tz   , 4+tzlen);
    } else {
      env[3] = NULL;
    }
  } else {
    env[3] = NULL;
  }
  env[4] = NULL;

  pid = fork();

  if (pid == (pid_t)(-1))
    {
      return -1;
    }

  else if (pid == 0) /* child */
    {
      memset(skey, 0, sizeof(sh_key_t));
      (void) umask(S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
      sh_unix_closeall (3, -1, SL_TRUE); /* in child process */
      execve(path, arg, env);
      _exit(EXIT_FAILURE);
    }

  else /* parent */
    {
      int r;

      while((r = waitpid(pid, &status, WUNTRACED)) != pid && r != -1) ;

#if !defined(USE_UNO)
      if (r == -1 || !WIFEXITED(status)) 
	{
	  status = -1;
	}
      else
	{
	  status = WEXITSTATUS(status);
	}
#endif
     }

  return status;
}

/********************************************************
 *
 *  TIME
 *
 ********************************************************/

/* Figure out the time offset of the current timezone
 * in a portable way.
 */
char * t_zone(const time_t * xx)
{
  struct tm   aa;
  struct tm   bb;
  struct tm * cc;
  int  sign =  0;
  int  diff =  0;
  int  hh, mm;
  static char tz[64];

  SL_ENTER(_("t_zone"));

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GMTIME_R)
  cc = gmtime_r (xx, &aa);
#else
  cc = gmtime (xx);
  memcpy (&aa, cc, sizeof(struct tm));
#endif

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
  cc = localtime_r (xx, &bb);
#else
  cc = localtime (xx);
  memcpy (&bb, cc, sizeof(struct tm));
#endif

  /* Check for datum wrap-around.
   */
  if      (aa.tm_year < bb.tm_year)
    sign = (-1);
  else if (aa.tm_mon  < bb.tm_mon)
    sign = (-1);
  else if (aa.tm_mday < bb.tm_mday)
    sign = (-1);
  else if (bb.tm_year < aa.tm_year)
    sign = ( 1);
  else if (bb.tm_mon  < aa.tm_mon)
    sign = ( 1);
  else if (bb.tm_mday < aa.tm_mday)
    sign = ( 1);

  diff = aa.tm_hour * 60 + aa.tm_min;
  diff = (bb.tm_hour * 60 + bb.tm_min) - diff;
  diff = diff - (sign * 24 * 60);   /* datum wrap-around correction */
  hh = diff / 60;
  mm = diff - (hh * 60);
  sprintf (tz, _("%+03d%02d"), hh, mm);                /* known to fit  */

  SL_RETURN(tz, _("t_zone"));
}

unsigned long sh_unix_longtime ()
{
  return ((unsigned long)time(NULL));
} 

#ifdef HAVE_GETTIMEOFDAY
unsigned long sh_unix_notime ()
{
  struct timeval  tv;

  gettimeofday (&tv, NULL);

  return ((unsigned long)(tv.tv_sec + tv.tv_usec * 10835 + getpid() + getppid()));
  
}
#endif

static int count_dev_time = 0;

void reset_count_dev_time(void)
{
  count_dev_time = 0;
  return;
}

int sh_unix_settimeserver (const char * address)
{

  SL_ENTER(_("sh_unix_settimeserver"));

  if (address != NULL && count_dev_time < 2 
      && sl_strlen(address) < SH_PATHBUF) 
    {
      if (count_dev_time == 0)
	sl_strlcpy (sh.srvtime.name, address, SH_PATHBUF);
      else
	sl_strlcpy (sh.srvtime.alt,  address, SH_PATHBUF);

      ++count_dev_time;
      SL_RETURN((0), _("sh_unix_settimeserver"));
    }
  SL_RETURN((-1), _("sh_unix_settimeserver"));
}


#ifdef HAVE_NTIME
#define UNIXEPOCH 2208988800UL  /* difference between Unix time and net time 
                                 * The UNIX EPOCH starts in 1970.
                                 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#endif

/* Timeserver service.               */
/* define is missing on HP-UX 10.20  */
#ifndef IPPORT_TIMESERVER 
#define IPPORT_TIMESERVER 37 
#endif

char * sh_unix_time (time_t thetime, char * buffer, size_t len)
{

  int           status;
  char          AsciiTime[81];                       /* local time   */
  time_t        time_now;
  struct tm   * time_ptr;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
  struct tm     time_tm;
#endif
#ifdef SH_USE_XML
  static char   deftime[] = N_("0000-00-00T00:00:00"); /* default time */
#else
  static char   deftime[] = N_("[0000-00-00T00:00:00]"); /* default time */
#endif

#ifdef HAVE_NTIME
  int    fd;                    /* network file descriptor                  */
  u_char net_time[4];           /* remote time in network format            */
  static int failerr = 0;       /* no net time                              */
  int    fail = 0;              /* no net time                              */
  int    errflag;
  char   errmsg[256];
  char   error_call[SH_MINIBUF];
  int    error_num;
#endif
  
  SL_ENTER(_("sh_unix_time"));

#ifdef HAVE_NTIME
  if (thetime == 0) 
    {
      if (sh.srvtime.name[0] == '\0') 
	{
	  fail = 1;
	  (void) time (&time_now);
	} 
      else /* have a timeserver address */
	{ 
	  fd = connect_port_2 (sh.srvtime.name, sh.srvtime.alt, 
			       IPPORT_TIMESERVER, 
			       error_call, &error_num, errmsg, sizeof(errmsg));
	  if (fd >= 0)
	    {
	      if (4 != read_port (fd, (char *) net_time, 4, &errflag, 2))
		{
		  fail = 1;
		  sh_error_handle ((-1), FIL__, __LINE__, errflag, 
				   MSG_E_NLOST, 
				   _("time"), sh.srvtime.name);
		}
	      sl_close_fd(FIL__, __LINE__, fd);
	    }
	  else
	    {
	      sh_error_handle ((-1), FIL__, __LINE__, error_num, 
			       MSG_E_NET, errmsg, error_call,
			       _("time"), sh.srvtime.name);
	      fail = 1;
	    }
	  
	  if (fail == 0) 
	    { 
	      unsigned long   ltmp;
	      UINT32          ttmp;
	      memcpy(&ttmp, net_time, sizeof(UINT32)); ltmp = ttmp;
	      time_now = ntohl(ltmp) - UNIXEPOCH;
	      /* fprintf(stderr, "TIME IS %ld\n", time_now); */
	      if (failerr == 1) {
		failerr = 0;
		sh_error_handle ((-1), FIL__, __LINE__, 0, 
				 MSG_E_NEST, 
				 _("time"), sh.srvtime.name);
	      } 
	    }
	  else
	    {
	      (void) time (&time_now);
	      if (failerr == 0)
		{
		  failerr = 1;
		  sh_error_handle ((-1), FIL__, __LINE__, errflag, 
				   MSG_SRV_FAIL, 
				   _("time"), sh.srvtime.name);
		}
	    }
	}
    }
  else 
    {
      time_now = thetime;
    }

  /* #ifdef HAVE_NTIME */
#else

  if (thetime == 0) 
    {
      (void) time (&time_now);
    } 
  else 
    {
      time_now = thetime;
    }

  /* #ifdef HAVE_NTIME */
#endif

  if (time_now == (-1) )
    {
      sl_strlcpy(buffer, _(deftime), len);
      SL_RETURN(buffer, _("sh_unix_time"));
    }
  else
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
      time_ptr   = localtime_r (&time_now, &time_tm);
#else
      time_ptr   = localtime (&time_now);
#endif
    }
  if (time_ptr != NULL) 
    {
      status = strftime (AsciiTime, sizeof(AsciiTime),
#ifdef SH_USE_XML
			 _("%Y-%m-%dT%H:%M:%S%%s"),
#else
			 _("[%Y-%m-%dT%H:%M:%S%%s]"),
#endif
			 time_ptr);

      sl_snprintf(buffer, len, AsciiTime, t_zone(&time_now));

      if ( (status == 0) || (status == sizeof(AsciiTime)) )
	{
	  sl_strlcpy(buffer, _(deftime), len);
	  SL_RETURN( buffer, _("sh_unix_time"));
	}
      else
	{
	  SL_RETURN(buffer, _("sh_unix_time"));
	}
    }

  /* last resort
   */
  sl_strlcpy(buffer, _(deftime), len);
  SL_RETURN( buffer, _("sh_unix_time"));
}

static int sh_unix_use_localtime = S_FALSE;

/* whether to use localtime for file timesatams in logs
 */
int sh_unix_uselocaltime (const char * c)
{
  int i;
  SL_ENTER(_("sh_unix_uselocaltime"));
  i = sh_util_flagval(c, &(sh_unix_use_localtime));

  SL_RETURN(i, _("sh_unix_uselocaltime"));
}
    
char * sh_unix_gmttime (time_t thetime, char * buffer, size_t len)
{

  int           status;

  struct tm   * time_ptr;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS)
  struct tm     time_tm;
#endif
  char   AsciiTime[81];                       /* GMT time   */
#ifdef SH_USE_XML
  static char   deftime[] = N_("0000-00-00T00:00:00"); /* default time */
#else
  static char   deftime[] = N_("[0000-00-00T00:00:00]"); /* default time */
#endif

  SL_ENTER(_("sh_unix_gmttime"));

  if (sh_unix_use_localtime == S_FALSE)
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GMTIME_R)
      time_ptr   = gmtime_r (&thetime, &time_tm);
#else
      time_ptr   = gmtime (&thetime);
#endif
    }
  else
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
      time_ptr   = localtime_r (&thetime, &time_tm);
#else
      time_ptr   = localtime (&thetime);
#endif
    }
  if (time_ptr != NULL) 
    {
      status = strftime (AsciiTime, 80,
#ifdef SH_USE_XML
			 _("%Y-%m-%dT%H:%M:%S"),
#else
			 _("[%Y-%m-%dT%H:%M:%S]"),
#endif
			 time_ptr);

      if ( (status == 0) || (status == 80) )
	sl_strlcpy(buffer, _(deftime), len);
      else
	sl_strlcpy(buffer, AsciiTime, len);
      SL_RETURN( buffer, _("sh_unix_gmttime"));
    }

  /* last resort
   */
  sl_strlcpy(buffer, _(deftime), len);
  SL_RETURN( buffer, _("sh_unix_gmttime"));
}


char *  sh_unix_getUIDdir (int level, uid_t uid, char * out, size_t len)
{
  struct passwd * tempres;
  int    status = 0;

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWUID_R)
  struct passwd pwd;
  char   * buffer;
#endif
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("sh_unix_getUIDdir"));

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWUID_R)
  buffer = SH_ALLOC(SH_PWBUF_SIZE);
  sh_getpwuid_r(uid, &pwd, buffer, SH_PWBUF_SIZE, &tempres);
#else
  errno = 0;
  tempres = sh_getpwuid(uid);
  status = errno;
#endif

  if (tempres == NULL) {
    sh_error_handle (level, FIL__, __LINE__, EINVAL, MSG_E_PWNULL,
		     sh_error_message(status, errbuf, sizeof(errbuf)),
		     _("getpwuid"), (long) uid, _("completely missing"));
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
    SH_FREE(buffer);
#endif
    SL_RETURN( NULL, _("sh_unix_getUIDdir"));
  }

  if (tempres->pw_dir != NULL) {
    sl_strlcpy(out, tempres->pw_dir, len);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
    SH_FREE(buffer);
#endif
    SL_RETURN( out, _("sh_unix_getUIDdir"));
  } else {
    sh_error_handle (level, FIL__, __LINE__, EINVAL, MSG_E_PWNULL,
		     sh_error_message(status, errbuf, sizeof(errbuf)),
		     _("getpwuid"), (long) uid, _("pw_dir"));
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
    SH_FREE(buffer);
#endif
    SL_RETURN( NULL, _("sh_unix_getUIDdir"));
  }
}

/* ------------------- Caching ----------------*/
#include "zAVLTree.h"

#define CACHE_GID 0
#define CACHE_UID 1

struct user_id {
  char  * name;
  uid_t   id;
  struct user_id * next;
};

static struct user_id  * uid_list = NULL;
static struct user_id  * gid_list = NULL;

SH_MUTEX_STATIC(mutex_cache, PTHREAD_MUTEX_INITIALIZER);

static void sh_userid_free(struct user_id * item)
{
  while (item)
    {
      struct user_id * user = item;
      item = item->next;

      SH_FREE(user->name);
      SH_FREE(user);
    }
  return;
}

void sh_userid_destroy ()
{
  struct user_id * tmp_uid;
  struct user_id * tmp_gid;

  SH_MUTEX_LOCK_UNSAFE(mutex_cache);
  tmp_gid  = gid_list;
  gid_list = NULL;
  tmp_uid  = uid_list;
  uid_list = NULL;
  SH_MUTEX_UNLOCK_UNSAFE(mutex_cache);

  sh_userid_free(tmp_uid);
  sh_userid_free(tmp_gid);
  return;
}

static void sh_userid_additem(struct user_id * list, struct user_id * item)
{
  while (list && list->next)
    list = list->next;
  list->next = item;
  return;
}

static void sh_userid_add(uid_t id, char * username, int which)
{
  size_t len;
  struct user_id * user = SH_ALLOC(sizeof(struct user_id));

  if (username)
    len  = strlen(username) + 1;
  else
    len = 1;

  user->name = SH_ALLOC(len);
  user->id   = id;
  if (username)
    sl_strlcpy(user->name, username, len);
  else
    user->name[0] = '\0';
  user->next = NULL;

  SH_MUTEX_LOCK(mutex_cache);
  if (which == CACHE_UID)
    {
      if (!uid_list)
	uid_list = user;
      else
	sh_userid_additem(uid_list, user);
    }
  else
    {
      if (!gid_list)
	gid_list = user;
      else
	sh_userid_additem(gid_list, user);
    }
  SH_MUTEX_UNLOCK(mutex_cache);

  return;
}

static char * sh_userid_search(struct user_id * list, uid_t id)
{
  while (list)
    {
      if (list->id == id)
	return list->name;
      list = list->next;
    }
  return NULL;
}

static char * sh_userid_get (uid_t id, int which, char * out, size_t len)
{
  char * user = NULL;

  SH_MUTEX_LOCK_UNSAFE(mutex_cache);
  if (which == CACHE_UID)
    user = sh_userid_search(uid_list, id);
  else
    user = sh_userid_search(gid_list, id);
  if (user)
    {
      sl_strlcpy(out, user, len);
      user = out;
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_cache);

  return user;
}

/* --------- end caching code --------- */
  
char *  sh_unix_getUIDname (int level, uid_t uid, char * out, size_t len)
{
  struct passwd * tempres;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWUID_R)
  struct passwd pwd;
  char   * buffer;
#endif
  int             status = 0;
  char errbuf[SH_ERRBUF_SIZE];
  char * tmp;

  SL_ENTER(_("sh_unix_getUIDname"));

  tmp = sh_userid_get(uid, CACHE_UID, out, len);

  if (tmp)
    {
      if (tmp[0] != '\0')
	{
	  SL_RETURN( out, _("sh_unix_getUIDname"));
	}
      else
	{
	  SL_RETURN( NULL, _("sh_unix_getUIDname"));
	}
    }

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWUID_R)
  buffer = SH_ALLOC(SH_PWBUF_SIZE);
  sh_getpwuid_r(uid, &pwd, buffer, SH_PWBUF_SIZE, &tempres);
#else
  errno = 0;
  tempres = sh_getpwuid(uid);
  status = errno;
#endif
 
  if (tempres == NULL) 
    {
      sh_error_handle (level, FIL__, __LINE__, EINVAL, MSG_E_PWNULL,
		       sh_error_message(status, errbuf, sizeof(errbuf)),
		       _("getpwuid"), (long) uid, _("completely missing"));
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
      SH_FREE(buffer);
#endif
      sh_userid_add(uid, NULL, CACHE_UID);
      SL_RETURN( NULL, _("sh_unix_getUIDname"));
    }


  if (tempres->pw_name != NULL) 
    {

      sl_strlcpy(out, tempres->pw_name, len);
      sh_userid_add(uid, out, CACHE_UID);
      
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
      SH_FREE(buffer);
#endif

      SL_RETURN( out, _("sh_unix_getUIDname"));
    } 
  else 
    {
      sh_error_handle (level, FIL__, __LINE__, EINVAL, MSG_E_PWNULL,
		       sh_error_message(status, errbuf, sizeof(errbuf)),
		       _("getpwuid"), (long) uid, _("pw_user"));
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
      SH_FREE(buffer);
#endif
      SL_RETURN( NULL, _("sh_unix_getUIDname"));
    }
  /* notreached */
}

char *  sh_unix_getGIDname (int level, gid_t gid, char * out, size_t len)
{
  struct group  * tempres;
  int             status = 0;

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  struct group    grp;
  char          * buffer;
#endif
  char errbuf[SH_ERRBUF_SIZE];
  char * tmp;
  
  SL_ENTER(_("sh_unix_getGIDname"));

  tmp = sh_userid_get((uid_t)gid, CACHE_GID, out, len);

  if (tmp)
    {
      if (tmp[0] != '\0')
	{
	  SL_RETURN( out, _("sh_unix_getGIDname"));
	}
      else
	{
	  SL_RETURN( NULL, _("sh_unix_getGIDname"));
	}
    }

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  buffer = SH_ALLOC(SH_GRBUF_SIZE);
  status = sh_getgrgid_r(gid, &grp, buffer, SH_GRBUF_SIZE, &tempres);
#else
  errno = 0;
  tempres = sh_getgrgid(gid);
  status = errno;
#endif

  if (tempres == NULL) 
    {
      sh_error_handle (level, FIL__, __LINE__, EINVAL, MSG_E_GRNULL,
		       sh_error_message(status, errbuf, sizeof(errbuf)),
		       _("getgrgid"), (long) gid, _("completely missing"));
      
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
      SH_FREE(buffer);
#endif

      sh_userid_add(gid, NULL, CACHE_GID);
      SL_RETURN( NULL, _("sh_unix_getGIDname"));
    }

  if (tempres->gr_name != NULL) 
    {

      sl_strlcpy(out, tempres->gr_name, len);
      sh_userid_add((uid_t)gid, out, CACHE_GID);
      
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
      SH_FREE(buffer);
#endif

      SL_RETURN( out, _("sh_unix_getGIDname"));
    } 
  else 
    {
      sh_error_handle (level, FIL__, __LINE__, EINVAL, MSG_E_GRNULL,
		       sh_error_message(status, errbuf, sizeof(errbuf)),
		       _("getgrgid"), (long) gid, _("gr_name"));

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
      SH_FREE(buffer);
#endif

      SL_RETURN( NULL, _("sh_unix_getGIDname"));
    }
  /* notreached */
}

int sh_unix_getUser ()
{
  char          * p;
  uid_t  seuid, sruid;
  char   user[USER_MAX];
  char   dir[SH_PATHBUF];

  SL_ENTER(_("sh_unix_getUser"));

  seuid =  geteuid();

  sh.effective.uid = seuid;

  p = sh_unix_getUIDdir (SH_ERR_ERR, seuid, dir, sizeof(dir));

  if (p == NULL)
    SL_RETURN((-1), _("sh_unix_getUser"));
  else
    {
      if (sl_strlen(p) >= SH_PATHBUF) {
	sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, EINVAL, MSG_E_PWLONG,
			 _("getpwuid"), (long) seuid, _("pw_home"));
	SL_RETURN((-1), _("sh_unix_getUser"));
      } else {
	sl_strlcpy ( sh.effective.home, p, SH_PATHBUF);
      }
    }

  sruid = getuid();

  sh.real.uid = sruid;

  p = sh_unix_getUIDname (SH_ERR_ERR, sruid, user, sizeof(user));
  if (p == NULL)
    SL_RETURN((-1), _("sh_unix_getUser"));
  else
    {
      if (sl_strlen(p) >= USER_MAX) {
	sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, EINVAL, MSG_E_PWLONG,
			 _("getpwuid"), (long) sruid, _("pw_user"));
	SL_RETURN((-1), _("sh_unix_getUser"));
      } else {
	sl_strlcpy ( sh.real.user, p, USER_MAX);
      }
    }

  p = sh_unix_getUIDdir (SH_ERR_ERR, sruid, dir, sizeof(dir));

  if (p == NULL)
    SL_RETURN((-1), _("sh_unix_getUser"));
  else
    {
      if (sl_strlen(p) >= SH_PATHBUF) {
	sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, EINVAL, MSG_E_PWLONG,
			 _("getpwuid"), (long) sruid, _("pw_home"));
	SL_RETURN((-1), _("sh_unix_getUser"));
      } else {
	sl_strlcpy ( sh.real.home, p, SH_PATHBUF);
      }
    }

  SL_RETURN((0), _("sh_unix_getUser"));

  /* notreached */
}


int sh_unix_getline (SL_TICKET fd, char * line, int sizeofline)
{
  register int  count;
  register int  n = 0;
  char          c;

  SL_ENTER(_("sh_unix_getline"));

  if (sizeofline < 2) {
    line[0] = '\0';
    SL_RETURN((0), _("sh_unix_getline"));
  }

  --sizeofline;

  while (n < sizeofline) {

    count = sl_read (fd, &c, 1);

    /* end of file
     */
    if (count < 1) {
      line[n] = '\0';
      n = -1;
      break;
    } 

    if (/* c != '\0' && */ c != '\n') {
      line[n] = c;
      ++n;
    } else if (c == '\n') {
      if (n > 0) {
	line[n] = '\0';
	break;
      } else {
	line[n] = '\n'; /* get newline only if only char on line */
	++n;
	line[n] = '\0';
	break;
      }
    } else {
      line[n] = '\0';
      break;
    }

  }


  line[sizeofline] = '\0';  /* make sure line is terminated */
  SL_RETURN((n), _("sh_unix_getline"));
}


#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 

/**************************************************************
 *
 * --- FILE INFO ---
 *
 **************************************************************/

#if (defined(__linux__) && (defined(HAVE_LINUX_EXT2_FS_H) || defined(HAVE_EXT2FS_EXT2_FS_H))) || defined(HAVE_STAT_FLAGS)

#if defined(__linux__)

/* --- Determine ext2fs file attributes. ---
 */
#include <sys/ioctl.h>
#if defined(HAVE_EXT2FS_EXT2_FS_H)
#include <ext2fs/ext2_fs.h>
#else
#include <linux/ext2_fs.h>
#endif

/* __linux__ includes */
#endif

static 
int sh_unix_getinfo_attr (char * name, 
			  unsigned long * flags, 
			  char * c_attr,
			  int fd, struct stat * buf)
{

/* TAKEN FROM:
 *
 * lsattr.c             - List file attributes on an ext2 file system
 *
 * Copyright (C) 1993, 1994  Remy Card <card@masi.ibp.fr>
 *                           Laboratoire MASI, Institut Blaise Pascal
 *                           Universite Pierre et Marie Curie (Paris VI)
 *
 * This file can be redistributed under the terms of the GNU General
 * Public License
 */

#ifdef HAVE_STAT_FLAGS

  SL_ENTER(_("sh_unix_getinfo_attr"));

  *flags = 0;

  /* cast to void to avoid compiler warning about unused parameters */
  (void) fd;
  (void) name;

#ifdef UF_NODUMP
  if (buf->st_flags & UF_NODUMP) {
    *flags |= UF_NODUMP;
    c_attr[0] = 'd';
  }
#endif
#ifdef UF_IMMUTABLE
  if (buf->st_flags & UF_IMMUTABLE) {
    *flags |= UF_IMMUTABLE;
    c_attr[1] = 'i';
  }
#endif
#ifdef UF_APPEND
  if (buf->st_flags & UF_APPEND) {
    *flags |= UF_APPEND;
    c_attr[2] = 'a';
  }
#endif
#ifdef UF_NOUNLINK
  if (buf->st_flags & UF_NOUNLINK) {
    *flags |= UF_NOUNLINK;
    c_attr[3] = 'u';
  }
#endif
#ifdef UF_OPAQUE
  if (buf->st_flags & UF_OPAQUE) {
    *flags |= UF_OPAQUE;
    c_attr[4] = 'o';
  }
#endif
#ifdef SF_ARCHIVED
  if (buf->st_flags & SF_ARCHIVED) {
    *flags |= SF_ARCHIVED;
    c_attr[5] = 'R';
  }
    
#endif
#ifdef SF_IMMUTABLE
  if (buf->st_flags & SF_IMMUTABLE) {
    *flags |= SF_IMMUTABLE;
    c_attr[6] = 'I';
  }
#endif
#ifdef SF_APPEND
  if (buf->st_flags & SF_APPEND) {
    *flags |= SF_APPEND;
    c_attr[7] = 'A';
  }
#endif
#ifdef SF_NOUNLINK
  if (buf->st_flags & SF_NOUNLINK) {
    *flags |= SF_NOUNLINK;
    c_attr[8] = 'U';
  }
#endif

  /* ! HAVE_STAT_FLAGS */
#else

#ifdef HAVE_EXT2_IOCTLS
  int /* fd, */ r, f;
  
  SL_ENTER(_("sh_unix_getinfo_attr"));

  *flags = 0;
  (void) buf;

  /* open() -> aud_open() R.Wichmann 
  fd = aud_open (FIL__, __LINE__, SL_YESPRIV, name, O_RDONLY|O_NONBLOCK, 0);
  */

  if (fd == -1 || name == NULL)
    SL_RETURN(-1, _("sh_unix_getinfo_attr"));

  
  r = ioctl (fd, EXT2_IOC_GETFLAGS, &f);
  /* sl_close_fd (FIL__, __LINE__, fd); */

  if (r == -1)
    SL_RETURN(-1, _("sh_unix_getinfo_attr"));

  if (f == 0)
    SL_RETURN(0, _("sh_unix_getinfo_attr"));

  *flags = f;

/* ! HAVE_EXT2_IOCTLS */
#else 

  SL_ENTER(_("sh_unix_getinfo_attr"));

  *flags = 0;                                     /* modified by R.Wichmann */

/* ! HAVE_EXT2_IOCTLS */
#endif 
/*
 * END
 *
 * lsattr.c             - List file attributes on an ext2 file system
 */

  if (*flags == 0)
    goto theend;

#ifdef EXT2_SECRM_FL
  if ( (*flags & EXT2_SECRM_FL) != 0  )   c_attr[0] = 's';
#endif
#ifdef EXT2_UNRM_FL 
  if ( (*flags & EXT2_UNRM_FL) != 0   )   c_attr[1] = 'u';
#endif
#ifdef EXT2_SYNC_FL
  if ( (*flags & EXT2_SYNC_FL) != 0    )  c_attr[2] = 'S';
#endif
#ifdef EXT2_IMMUTABLE_FL
  if ( (*flags & EXT2_IMMUTABLE_FL) != 0) c_attr[3] = 'i';
#endif
#ifdef EXT2_APPEND_FL
  if ( (*flags & EXT2_APPEND_FL) != 0  )  c_attr[4] = 'a';
#endif
#ifdef EXT2_NODUMP_FL
  if ( (*flags & EXT2_NODUMP_FL) != 0  )  c_attr[5] = 'd';
#endif
#ifdef EXT2_NOATIME_FL
  if ( (*flags & EXT2_NOATIME_FL) != 0)   c_attr[6] = 'A';
#endif
#ifdef EXT2_COMPR_FL
  if ( (*flags & EXT2_COMPR_FL) != 0   )  c_attr[7] = 'c';
#endif

#ifdef EXT2_TOPDIR_FL
  if ( (*flags & EXT2_TOPDIR_FL) != 0  )  c_attr[8] = 'T';
#endif
#ifdef EXT2_DIRSYNC_FL
  if ( (*flags & EXT2_DIRSYNC_FL) != 0 )  c_attr[9] = 'D';
#endif
#ifdef EXT2_NOTAIL_FL
  if ( (*flags & EXT2_NOTAIL_FL) != 0  )  c_attr[10] = 't';
#endif
#ifdef EXT2_JOURNAL_DATA_FL
  if ( (*flags & EXT2_JOURNAL_DATA_FL) != 0)  c_attr[11] = 'j';
#endif

 theend:
  /* ext2 */
#endif

  c_attr[12] = '\0';

  SL_RETURN(0, _("sh_unix_getinfo_attr"));
}
#else
static 
int sh_unix_getinfo_attr (char * name, 
			  unsigned long * flags, 
			  char * c_attr,
			  int fd, struct stat * buf)
{
  return 0;
}

/* defined(__linux__) || defined(HAVE_STAT_FLAGS) */
#endif

/* determine file type
 */
static 
int sh_unix_getinfo_type (struct stat * buf, 
			  ShFileType * type, 
			  char * c_mode)
{
  SL_ENTER(_("sh_unix_getinfo_type"));

  if      ( S_ISREG(buf->st_mode)  ) { 
    (*type)   = SH_FILE_REGULAR;
    c_mode[0] = '-';
  }
  else if ( S_ISLNK(buf->st_mode)  ) {
    (*type)   = SH_FILE_SYMLINK;
    c_mode[0] = 'l';
  }
  else if ( S_ISDIR(buf->st_mode)  ) {
    (*type)   = SH_FILE_DIRECTORY;
    c_mode[0] = 'd';
  }
  else if ( S_ISCHR(buf->st_mode)  ) {
    (*type)   = SH_FILE_CDEV;
    c_mode[0] = 'c';
  }
  else if ( S_ISBLK(buf->st_mode)  ) {
    (*type)   = SH_FILE_BDEV;
    c_mode[0] = 'b';
  }
  else if ( S_ISFIFO(buf->st_mode) ) {
    (*type)   = SH_FILE_FIFO;
    c_mode[0] = '|';
  }
  else if ( S_ISSOCK(buf->st_mode) ) {
    (*type)   = SH_FILE_SOCKET;
    c_mode[0] = 's';
  }
  else if ( S_ISDOOR(buf->st_mode) ) {
    (*type)   = SH_FILE_DOOR;
    c_mode[0] = 'D';
  }
  else if ( S_ISPORT(buf->st_mode) ) {
    (*type)   = SH_FILE_PORT;
    c_mode[0] = 'P';
  }
  else                              {
    (*type)   = SH_FILE_UNKNOWN;
    c_mode[0] = '?';
  }

  SL_RETURN(0, _("sh_unix_getinfo_type"));
}

int sh_unix_get_ftype(char * fullpath)
{
  char        c_mode[CMODE_SIZE];
  struct stat buf;
  ShFileType  type;
  int         res;

  SL_ENTER(_("sh_unix_get_ftype"));

  res = retry_lstat(FIL__, __LINE__, fullpath, &buf);

  if (res < 0)
    SL_RETURN(SH_FILE_UNKNOWN, _("sh_unix_getinfo_type"));

  sh_unix_getinfo_type (&buf, &type, c_mode);

  SL_RETURN(type, _("sh_unix_get_ftype"));
}


static 
int  sh_unix_getinfo_mode (struct stat *buf, 
			   unsigned int * mode, 
			   char * c_mode)
{

  SL_ENTER(_("sh_unix_getinfo_mode"));

  (*mode) = buf->st_mode;

  /* make 'ls'-like string */
  
  if ( (buf->st_mode & S_IRUSR) != 0 )  c_mode[1] = 'r'; 
  if ( (buf->st_mode & S_IWUSR) != 0 )  c_mode[2] = 'w'; 
  if ( (buf->st_mode & S_IXUSR) != 0 ) {
    if ((buf->st_mode & S_ISUID) != 0 ) c_mode[3] = 's';
    else                                c_mode[3] = 'x';
  } else {
    if ((buf->st_mode & S_ISUID) != 0 ) c_mode[3] = 'S';
  }

  if ( (buf->st_mode & S_IRGRP) != 0 )  c_mode[4] = 'r'; 
  if ( (buf->st_mode & S_IWGRP) != 0 )  c_mode[5] = 'w'; 
  if ( (buf->st_mode & S_IXGRP) != 0 )  {
    if ((buf->st_mode & S_ISGID) != 0 ) c_mode[6] = 's';
    else                                c_mode[6] = 'x';
  } else {
    if ((buf->st_mode & S_ISGID) != 0 ) c_mode[6] = 'S';
  } 

  if ( (buf->st_mode & S_IROTH) != 0 )  c_mode[7] = 'r'; 
  if ( (buf->st_mode & S_IWOTH) != 0 )  c_mode[8] = 'w';
#ifdef S_ISVTX  /* not POSIX */
  if ( (buf->st_mode & S_IXOTH) != 0 )  {
    if ((buf->st_mode & S_ISVTX) != 0 ) c_mode[9] = 't';
    else                                c_mode[9] = 'x';
  } else {
    if ((buf->st_mode & S_ISVTX) != 0 ) c_mode[9] = 'T';
  }
#else
  if ( (buf->st_mode & S_IXOTH) != 0 )  c_mode[9] = 'x';
#endif 

  SL_RETURN(0, _("sh_unix_getinfo_mode"));
}


long IO_Limit = 0;

void sh_unix_io_pause ()
{
  long runtime;
  float          someval;
  unsigned long  sometime;

  if (IO_Limit == 0)
    {
      return;
    }
  else
    {
      runtime = (long) (time(NULL) - sh.statistics.time_start);
      
      if (runtime > 0 && (long)(sh.statistics.bytes_hashed/runtime) > IO_Limit)
	{
	  someval  = sh.statistics.bytes_hashed - (IO_Limit * runtime);
	  someval /= (float) IO_Limit;
	  if (someval < 1.0)
	    {
	      someval *= 1000;  /* milliseconds in a second */
	      sometime = (unsigned long) someval;
	      retry_msleep(0, sometime);
	    }
	  else
	    {
	      sometime = (unsigned long) someval;
	      retry_msleep (sometime, 0);
	    }
	}
    }
  return;
}

int sh_unix_set_io_limit (const char * c)
{
  long val;

  SL_ENTER(_("sh_unix_set_io_limit"));

  val = strtol (c, (char **)NULL, 10);
  if (val < 0)
    sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
                      _("set I/O limit"), c);

  val = (val < 0 ? 0 : val);

  IO_Limit = val * 1024;
  SL_RETURN( 0, _("sh_unix_set_io_limit"));
}

/* obtain file info
 */
extern int flag_err_debug;

#include "sh_ignore.h"

int sh_unix_checksum_size (char * filename, struct stat * fbuf, 
			   char * fileHash, int alert_timeout, SL_TICKET fd)
{
  file_type * tmpFile;
  int status;

  SL_ENTER(_("sh_unix_checksum_size"));

  tmpFile = SH_ALLOC(sizeof(file_type));
  tmpFile->link_path = NULL;

  if (sh.flag.checkSum != SH_CHECK_INIT)
    {
      /* lookup file in database */
      status = sh_hash_get_it (filename, tmpFile);
      if (status != 0) {
	goto out;
      }
    }
  else
    {
      tmpFile->size = fbuf->st_size;
    }

  /* if last < current get checksum */
  if (tmpFile->size < fbuf->st_size)
    {
      char hashbuf[KEYBUF_SIZE];
      UINT64 local_length = (UINT64) (tmpFile->size < 0 ? 0 : tmpFile->size);
      sl_strlcpy(fileHash,
		 sh_tiger_generic_hash (filename, fd, &(local_length), 
					alert_timeout, hashbuf, sizeof(hashbuf)),
		 KEY_LEN+1);
      
       /* return */
      if (tmpFile->link_path)   SH_FREE(tmpFile->link_path);
      SH_FREE(tmpFile);
      SL_RETURN( 0, _("sh_unix_checksum_size"));
    }

 out:
  if (tmpFile->link_path)   SH_FREE(tmpFile->link_path);
  SH_FREE(tmpFile);
  sl_strlcpy(fileHash, SH_KEY_NULL, KEY_LEN+1);
  SL_RETURN( -1, _("sh_unix_checksum_size"));
}

int sh_unix_check_selinux = S_FALSE;
int sh_unix_check_acl     = S_FALSE;

#ifdef USE_ACL

#include <sys/acl.h>
static char * sh_unix_getinfo_acl (char * path, int fd, struct stat * buf)
{
  /* system.posix_acl_access, system.posix_acl_default
   */
  char *  out  = NULL;
  char *  collect = NULL;
  char *  tmp;
  char *  out_compact;
  ssize_t len;
  acl_t   result;

  SL_ENTER(_("sh_unix_getinfo_acl"));

  result = (fd == -1) ? 
    acl_get_file (path, ACL_TYPE_ACCESS) :
    acl_get_fd   (fd);

  if (result)
    {
      out = acl_to_text (result, &len);
      if (out && (len > 0)) {
	out_compact = sh_util_acl_compact (out, len);
	acl_free(out);
	if (out_compact) 
	  {
	    collect = sh_util_strconcat (_("acl_access:"), out_compact, NULL);
	    SH_FREE(out_compact);
	  }
      }
      acl_free(result);
    }
  
  
  if ( S_ISDIR(buf->st_mode) ) 
    {
      result = acl_get_file (path, ACL_TYPE_DEFAULT);
      
      if (result)
	{
	  out = acl_to_text (result, &len);
	  if (out && (len > 0)) {
	    out_compact = sh_util_acl_compact (out, len);
	    acl_free(out);
	    if (out_compact) {
	      if (collect) {
		tmp = sh_util_strconcat (_("acl_default:"), 
					 out_compact, ":", collect, NULL);
		SH_FREE(collect);
	      }
	      else {
		tmp = sh_util_strconcat (_("acl_default:"), out_compact, NULL);
	      }
	      SH_FREE(out_compact);
	      collect = tmp;
	    }
	  }
	  acl_free(result);
	}
    }
  
  SL_RETURN((collect),_("sh_unix_getinfo_acl"));
}
#endif

#ifdef USE_XATTR

#include <attr/xattr.h>
static char * sh_unix_getinfo_xattr_int (char * path, int fd, char * name)
{
  char *  out   = NULL;
  char *  tmp   = NULL;
  size_t  size  = 256;
  ssize_t result;

  SL_ENTER(_("sh_unix_getinfo_xattr_int"));

  out = SH_ALLOC(size);

  result = (fd == -1) ? 
    lgetxattr (path, name, out, size-1) :
    fgetxattr (fd,   name, out, size-1);

  if (result == -1 && errno == ERANGE) 
    {
      SH_FREE(out);
      result = (fd == -1) ? 
	lgetxattr (path, name, NULL, 0) :
	fgetxattr (fd,   name, NULL, 0);
      size = result + 1;
      out  = SH_ALLOC(size);
      result = (fd == -1) ? 
	lgetxattr (path, name, out, size-1) :
	fgetxattr (fd,   name, out, size-1);
    }

  if ((result > 0) && ((size_t)result < size))
    {
      out[size-1] = '\0';
      tmp = out;
    }
  else
    {
      SH_FREE(out);
    }

  SL_RETURN((tmp),_("sh_unix_getinfo_xattr_int"));
}


static char * sh_unix_getinfo_xattr (char * path, int fd, struct stat * buf)
{
  /* system.posix_acl_access, system.posix_acl_default, security.selinux 
   */
  char *  tmp;
  char *  out  = NULL;
  char *  collect = NULL;

  SL_ENTER(_("sh_unix_getinfo_xattr"));

#ifdef USE_ACL
  /*
   * we need the acl_get_fd/acl_get_file functions, getxattr will only
   * yield the raw bytes
   */
  if (sh_unix_check_acl == S_TRUE) 
    {
      out = sh_unix_getinfo_acl(path, fd, buf);
      
      if (out)
	{
	  collect = out;
	}
  }
#endif

  if (sh_unix_check_selinux == S_TRUE)
    {
      out = sh_unix_getinfo_xattr_int(path, fd, _("security.selinux"));

      if (out)
	{
	  if (collect) {
	    tmp = sh_util_strconcat(_("selinux:"), out, ":", collect, NULL);
	    SH_FREE(collect);
	  }
	  else {
	    tmp = sh_util_strconcat(_("selinux:"), out, NULL);
	  }
	  SH_FREE(out);
	  collect = tmp;
	}
    }

  SL_RETURN((collect),_("sh_unix_getinfo_xattr"));
}
#endif

#ifdef USE_XATTR
int sh_unix_setcheckselinux (const char * c)
{
  int i;
  SL_ENTER(_("sh_unix_setcheckselinux"));
  i = sh_util_flagval(c, &(sh_unix_check_selinux));

  SL_RETURN(i, _("sh_unix_setcheckselinux"));
}
#endif

#ifdef USE_ACL
int sh_unix_setcheckacl (const char * c)
{
  int i;
  SL_ENTER(_("sh_unix_setcheckacl"));
  i = sh_util_flagval(c, &(sh_unix_check_acl));

  SL_RETURN(i, _("sh_unix_setcheckacl"));
}
#endif

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif    

int sh_unix_getinfo (int level, char * filename, file_type * theFile, 
		     char * fileHash, int policy)
{
  char          timestr[81];
  long          runtim;
  struct stat   buf;
  struct stat   lbuf;
  struct stat   fbuf;
  int           stat_return;
  int           stat_errno = 0;

  ShFileType    type;
  unsigned int  mode;
  char        * tmp;
  char        * tmp2;

  char        * linknamebuf;
  int           linksize;

  extern int get_the_fd (SL_TICKET ticket);

  SL_TICKET     rval_open;
  int           err_open = 0;

  int           fd;
  int           fstat_return;
  int           fstat_errno = 0;
  int           try         = 0;

  sh_string   * content = NULL;
      
  time_t        tend;
  time_t        tstart;


  char * path = NULL;

  int alert_timeout   = 120;

  path = theFile->fullpath;

  SL_ENTER(_("sh_unix_getinfo"));

  /* --- Stat the file, and get checksum. ---
   */
  tstart = time(NULL);

  stat_return = retry_lstat (FIL__, __LINE__, 
			     path /* theFile->fullpath */, &buf);

  if (stat_return)
    stat_errno = errno;

  theFile->link_path = NULL;

 try_again:

  fd           = -1;
  fstat_return = -1;
  rval_open    = -1;

  if (stat_return == 0 && S_ISREG(buf.st_mode)) 
    {
      rval_open = sl_open_fastread (FIL__, __LINE__, 
				    path /* theFile->fullpath */, SL_YESPRIV);
      if (SL_ISERROR(rval_open))
	{
	  char * stale = sl_check_stale();
	  
	  if (stale)
	    {
	      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, err_open, MSG_E_SUBGEN,
			      stale, _("sh_unix_getinfo_open"));
	    }

	  if (errno == EBADF && try == 0) /* obsolete, but we keep this, just in case */
	    {
	      ++try;
	      goto try_again;
	    }
	  err_open = errno;
	}

      alert_timeout = 120; /* this is per 8K block now ! */

      if (path[1] == 'p' && path[5] == '/' && path[2] == 'r' &&
	  path[3] == 'o' && path[4] == 'c' && path[0] == '/')
	{
	  /* seven is magic */
	  alert_timeout = 7;
	}

      fd = get_the_fd(rval_open);
    }

  tend = time(NULL);

  /* An unprivileged user may slow lstat/open to a crawl
   * with clever path/symlink setup
   */
  if ((tend - tstart) > (time_t) /* 60 */ 6)
    {
      tmp2 = sh_util_safe_name (theFile->fullpath);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_TOOLATE,
		       (long)(tend - tstart), tmp2);
      SH_FREE(tmp2);
    }

  if (fd >= 0) 
    {
      fstat_return = retry_fstat (FIL__, __LINE__, fd, &fbuf);

      if (fstat_return)
	{
	  char * stale;

	  fstat_errno = errno;

	  stale = sl_check_stale();

	  if (stale)
	    {
	      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, fstat_errno, 
			      MSG_E_SUBGEN,
			      stale, _("sh_unix_getinfo_fstat"));
	    }

	  if (try == 0) /* obsolete, but we keep this, just in case */
	    {
	      ++try;
	      sl_close(rval_open);
	      goto try_again;
	    }
	}
    }
  else
    {
      fd = -1;
    }
      

  /* ---  case 1: lstat failed  --- 
   */
  if (stat_return != 0) 
    {
      stat_return = errno;
      if (!SL_ISERROR(rval_open))
	  sl_close(rval_open);
      if (sh.flag.checkSum == SH_CHECK_INIT || 
	  (sh_hash_have_it (theFile->fullpath) >= 0 && 
	   (!SH_FFLAG_REPORTED_SET(theFile->file_reported))))
	{
	  if (S_FALSE == sh_ignore_chk_del(theFile->fullpath)) {
	    char errbuf[SH_ERRBUF_SIZE];
	    uid_t euid;
	    (void) sl_get_euid(&euid);
	    tmp2 = sh_util_safe_name (theFile->fullpath);
	    sh_error_handle (level, FIL__, __LINE__, stat_return, MSG_FI_STAT,
			     _("lstat"),
			     sh_error_message (stat_errno, errbuf, sizeof(errbuf)),
			     (long) euid,
			     tmp2);
	    SH_FREE(tmp2);
	  }
	}
      SL_RETURN((-1),_("sh_unix_getinfo"));
    }

  /* ---  case 2: not a regular file  --- 
   */
  else if (! S_ISREG(buf.st_mode))
    {
      if (fileHash != NULL)
	sl_strlcpy(fileHash, SH_KEY_NULL, KEY_LEN+1);
    }
  
  /* ---  case 3a: a regular file, fstat ok --- 
   */
  else if (fstat_return == 0 && 
	   buf.st_mode == fbuf.st_mode &&
	   buf.st_ino  == fbuf.st_ino  &&
	   buf.st_uid  == fbuf.st_uid  &&
	   buf.st_gid  == fbuf.st_gid  &&
	   buf.st_dev  == fbuf.st_dev )
    {
      if (fileHash != NULL)
	{
	  if ((theFile->check_mask & MODI_CHK) == 0)
	    {
	      sl_strlcpy(fileHash, SH_KEY_NULL, KEY_LEN+1);
	    }
	  else if ((theFile->check_mask & MODI_PREL) != 0 && 
		   S_TRUE == sh_prelink_iself(rval_open, fbuf.st_size, 
					      alert_timeout, theFile->fullpath))
	    {
	      if (0 != sh_prelink_run (theFile->fullpath, 
				       fileHash, alert_timeout))
		sl_strlcpy(fileHash, SH_KEY_NULL, KEY_LEN+1);
	    }
	  else
	    {
	      char hashbuf[KEYBUF_SIZE];
	      UINT64 length_nolim = TIGER_NOLIM;

	      if (MODI_TXT_ENABLED(theFile->check_mask) && fbuf.st_size < (10 * SH_TXT_MAX))
		{
		  sl_init_content (rval_open, fbuf.st_size);
		}

	      sl_strlcpy(fileHash,
			 sh_tiger_generic_hash (theFile->fullpath, 
						rval_open, &length_nolim, 
						alert_timeout, 
						hashbuf, sizeof(hashbuf)),
			 KEY_LEN+1);

	      content = sl_get_content(rval_open);
	      content = sh_string_copy(content);

	      if ((theFile->check_mask & MODI_SGROW) != 0)
		{
		  fbuf.st_size = (off_t) length_nolim;
		  buf.st_size  = fbuf.st_size;
		  sl_rewind(rval_open);
		  sh_unix_checksum_size (theFile->fullpath, &fbuf, 
					 &fileHash[KEY_LEN + 1], 
					 alert_timeout, rval_open);
		}
	    }
	}
    }

  /* ---  case 3b: a regular file, fstat ok, but different --- 
   */
  else if (fstat_return == 0 && S_ISREG(fbuf.st_mode))
    {
      memcpy (&buf, &fbuf, sizeof( struct stat ));

      if (fileHash != NULL)
	{
	  if ((theFile->check_mask & MODI_CHK) == 0)
	    {
	      sl_strlcpy(fileHash, SH_KEY_NULL, KEY_LEN+1);
	    }
	  else if (policy == SH_LEVEL_PRELINK &&
		   S_TRUE == sh_prelink_iself(rval_open, fbuf.st_size, 
					      alert_timeout, theFile->fullpath))
	    {
	      if (0 != sh_prelink_run (theFile->fullpath, 
				       fileHash, alert_timeout))
		sl_strlcpy(fileHash, SH_KEY_NULL, KEY_LEN+1);
	    }
	  else
	    {
	      char hashbuf[KEYBUF_SIZE];
	      UINT64 length_nolim = TIGER_NOLIM;

	      if (MODI_TXT_ENABLED(theFile->check_mask) && fbuf.st_size < (10 * SH_TXT_MAX))
		{
		  sl_init_content (rval_open, fbuf.st_size);
		}

	      sl_strlcpy(fileHash, 
			 sh_tiger_generic_hash (theFile->fullpath, rval_open, 
						&length_nolim,
						alert_timeout,
						hashbuf, sizeof(hashbuf)),
			 KEY_LEN + 1);

	      content = sl_get_content(rval_open);
	      content = sh_string_copy(content);

	      if ((theFile->check_mask & MODI_SGROW) != 0) 
		{
		  fbuf.st_size = (off_t) length_nolim;
		  buf.st_size  = fbuf.st_size;
		  sl_rewind(rval_open);
		  sh_unix_checksum_size (theFile->fullpath, &fbuf, 
					 &fileHash[KEY_LEN + 1], 
					 alert_timeout, rval_open);
		}
	    }
	}
    }

  /* ---  case 4: a regular file, fstat failed --- 
   */

  else    /* fstat_return != 0 or !S_ISREG(fbuf.st_mode) or open() failed */
    {
      uid_t   euid;

      if (fileHash != NULL)
	sl_strlcpy(fileHash, SH_KEY_NULL, KEY_LEN+1);

      if ((theFile->check_mask & MODI_CHK) != 0)
	{
	  tmp2 = sh_util_safe_name (theFile->fullpath);


	  if (fd >= 0 && fstat_return != 0)
	    {
	      char errbuf[SH_ERRBUF_SIZE];
	      (void) sl_get_euid(&euid);

	      sh_error_handle (level, FIL__, __LINE__, stat_return, MSG_FI_STAT,
			       _("fstat"),
			       sh_error_message (fstat_errno, errbuf, sizeof(errbuf)),
			       (long) euid,
			       tmp2);
	    }
	  else if (fd >= 0 && !S_ISREG(fbuf.st_mode))
	    {
	      sh_error_handle (level, FIL__, __LINE__, fstat_errno, 
			       MSG_E_NOTREG, tmp2);
	    }
	  else
	    {
	      char errbuf[SH_ERRBUF_SIZE];
	      char errbuf2[SH_ERRBUF_SIZE];
	      sl_strlcpy(errbuf, sl_error_string(rval_open), sizeof(errbuf));
	      sh_error_message(err_open, errbuf2, sizeof(errbuf2));
	      sh_error_handle (level, FIL__, __LINE__, err_open, 
			       MSG_E_READ, errbuf, errbuf2, tmp2);
	    }
	  SH_FREE(tmp2);
	}
    }	  


  /* --- Determine file type. ---
   */
  memset (theFile->c_mode, '-', CMODE_SIZE-1);
  theFile->c_mode[CMODE_SIZE-1] = '\0';

  memset (theFile->link_c_mode, '-', CMODE_SIZE-1);
  theFile->link_c_mode[CMODE_SIZE-1] = '\0';

  sh_unix_getinfo_type (&buf, &type, theFile->c_mode);
  theFile->type = type;

#if defined(__linux__) || defined(HAVE_STAT_FLAGS)

  /* --- Determine file attributes. ---
   */
  memset (theFile->c_attributes, '-', ATTRBUF_SIZE);
  theFile->c_attributes[ATTRBUF_USED] = '\0';
  theFile->attributes      =    0;

  if (theFile->c_mode[0] != 'c' && theFile->c_mode[0] != 'b' &&
      theFile->c_mode[0] != 'l' )
    sh_unix_getinfo_attr(theFile->fullpath, 
			 &theFile->attributes, theFile->c_attributes, 
			 fd, &buf);
#endif

#if defined(USE_XATTR) && defined(USE_ACL)
  if (sh_unix_check_selinux == S_TRUE || sh_unix_check_acl == S_TRUE)
    theFile->attr_string = sh_unix_getinfo_xattr (theFile->fullpath, fd, &buf);
#elif defined(USE_XATTR)
  if (sh_unix_check_selinux == S_TRUE)
    theFile->attr_string = sh_unix_getinfo_xattr (theFile->fullpath, fd, &buf);
#elif defined(USE_ACL)
  if (sh_unix_check_acl == S_TRUE)
    theFile->attr_string = sh_unix_getinfo_acl (theFile->fullpath, fd, &buf);
#else
  theFile->attr_string = NULL;
#endif

  if (!SL_ISERROR(rval_open))
    sl_close(rval_open);


  /* --- I/O limit. --- 
   */
  if (IO_Limit > 0)
    {
      runtim = (long) (time(NULL) - sh.statistics.time_start);
      
      if (runtim > 0 && (long)(sh.statistics.bytes_hashed/runtim) > IO_Limit)
	retry_msleep(1, 0);
    }

  /* --- Determine permissions. ---
   */
  sh_unix_getinfo_mode (&buf, &mode, theFile->c_mode);

  /* --- Trivia. ---
   */
  theFile->dev       = buf.st_dev;
  theFile->ino       = buf.st_ino;
  theFile->mode      = buf.st_mode;
  theFile->hardlinks = buf.st_nlink;
  theFile->owner     = buf.st_uid;  
  theFile->group     = buf.st_gid;  
  theFile->rdev      = buf.st_rdev;
  theFile->size      = buf.st_size;
  theFile->blksize   = (unsigned long) buf.st_blksize;
  theFile->blocks    = (unsigned long) buf.st_blocks;
  theFile->atime     = buf.st_atime;
  theFile->mtime     = buf.st_mtime;
  theFile->ctime     = buf.st_ctime;


  /* --- Owner and group. ---
   */

  if (NULL == sh_unix_getGIDname(SH_ERR_ALL, buf.st_gid, theFile->c_group, GROUP_MAX+1)) {

    tmp2 = sh_util_safe_name (theFile->fullpath);

    if (policy == SH_LEVEL_ALLIGNORE)
      {
	sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, ENOENT, 
			 MSG_FI_NOGRP,
			 (long) buf.st_gid, tmp2);
      }
    else
      {
	sh_error_handle (ShDFLevel[SH_ERR_T_NAME], FIL__, __LINE__, ENOENT, 
			 MSG_FI_NOGRP,
			 (long) buf.st_gid, tmp2);
      }
    SH_FREE(tmp2);
    sl_snprintf(theFile->c_group, GROUP_MAX+1, "%d", (long) buf.st_gid); 
  }

  
  if (NULL == sh_unix_getUIDname(SH_ERR_ALL, buf.st_uid, theFile->c_owner, USER_MAX+1)) {

    tmp2 = sh_util_safe_name (theFile->fullpath);

    if (policy == SH_LEVEL_ALLIGNORE)
      {
	sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, ENOENT, 
			 MSG_FI_NOUSR,
			 (long) buf.st_uid, tmp2);
      }
    else
      {
	sh_error_handle (ShDFLevel[SH_ERR_T_NAME], FIL__, __LINE__, ENOENT, 
			 MSG_FI_NOUSR,
			 (long) buf.st_uid, tmp2);
      }
    SH_FREE(tmp2);
    sl_snprintf(theFile->c_owner, USER_MAX+1, "%d", (long) buf.st_uid); 
  }

  /* --- Output the file. ---
   */
  if (flag_err_debug == SL_TRUE)
    {
      tmp2 = sh_util_safe_name ((filename == NULL) ? 
				theFile->fullpath : filename);
      (void) sh_unix_time(theFile->mtime, timestr, sizeof(timestr));
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_LIST,
		       theFile->c_mode,
		       theFile->hardlinks,
		       theFile->c_owner,
		       theFile->c_group,
		       (unsigned long) theFile->size,
		       timestr,
		       tmp2);
      SH_FREE(tmp2);
    }

  /* --- Check for links. ---
   */
  if (theFile->c_mode[0] == 'l') 
    {
      linknamebuf = SH_ALLOC(PATH_MAX);

      /* flawfinder: ignore */
      linksize    = readlink (theFile->fullpath, linknamebuf, PATH_MAX-1);

      if (linksize < (PATH_MAX-1) && linksize >= 0) 
	linknamebuf[linksize] = '\0';
      else 
	linknamebuf[PATH_MAX-1] = '\0';
      
      if (linksize < 0) 
	{
	  char errbuf[SH_ERRBUF_SIZE];
	  linksize = errno;
	  tmp2 = sh_util_safe_name (theFile->fullpath);
	  sh_error_handle (level, FIL__, __LINE__, linksize, MSG_FI_RDLNK,
			   sh_error_message (linksize, errbuf, sizeof(errbuf)), tmp2);
	  SH_FREE(tmp2);
	  SH_FREE(linknamebuf);
	  theFile->link_path = sh_util_strdup("-");
	  SL_RETURN((-1),_("sh_unix_getinfo"));
	}

      if (linknamebuf[0] == '/') 
	{
	  theFile->link_path = sh_util_strdup (linknamebuf);
	} 
      else 
	{
	  tmp = sh_util_dirname(theFile->fullpath);
	  if (tmp) {
	    theFile->link_path = SH_ALLOC(PATH_MAX);
	    sl_strlcpy (theFile->link_path, tmp, PATH_MAX);
	    SH_FREE(tmp);
	  } else {
	    theFile->link_path = SH_ALLOC(PATH_MAX);
	    theFile->link_path[0] = '\0';
	  }
	  /*
	   * Only attach '/' if not root directory. Handle "//", which
	   * according to POSIX is implementation-defined, and may be
	   * different from "/" (however, three or more '/' will collapse
	   * to one).
	   */
	  tmp = theFile->link_path; while (*tmp == '/') ++tmp;
	  if (*tmp != '\0')
	    {
	      sl_strlcat (theFile->link_path, "/", PATH_MAX);
	    }
	  sl_strlcat (theFile->link_path, linknamebuf, PATH_MAX);
	}
      
      /* stat the link
       */
      stat_return = retry_lstat (FIL__, __LINE__, theFile->link_path, &lbuf); 
      
      /* check for error
       */
      if (stat_return != 0) 
	{ 
	  stat_return = errno;
	  tmp  = sh_util_safe_name (theFile->fullpath);
	  tmp2 = sh_util_safe_name (theFile->link_path);
	  if (stat_return != ENOENT)
	    { 
	      uid_t euid;
	      char errbuf[SH_ERRBUF_SIZE];

	      (void) sl_get_euid(&euid);
	      sh_error_handle (level, FIL__, __LINE__, stat_return, 
			       MSG_FI_STAT,
			       _("lstat"),
			       sh_error_message (stat_return,errbuf, sizeof(errbuf)), 
			       (long) euid,
			       tmp2);
	    }
	  else 
	    {
	      /* a dangling link -- everybody seems to have plenty of them 
	       */
	      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_DLNK,
			       tmp, tmp2);
	    }
	  theFile->linkisok = BAD;
	  SH_FREE(tmp);
	  SH_FREE(tmp2);
	  SH_FREE(linknamebuf);
	  /* 
	   * changed Tue Feb 10 16:16:13 CET 2004:
	   *  add dangling symlinks into database
	   * SL_RETURN((-1),_("sh_unix_getinfo")); 
	   */
	  theFile->linkmode = 0;
	  SL_RETURN((0),_("sh_unix_getinfo")); 
	}
      
      theFile->linkisok = GOOD;
      
      
      /* --- Determine file type. ---
       */
      sh_unix_getinfo_type (&lbuf, &type, theFile->link_c_mode);
      theFile->type = type;
      
      /* --- Determine permissions. ---
       */
      sh_unix_getinfo_mode (&lbuf, &mode, theFile->link_c_mode);
      theFile->linkmode = lbuf.st_mode;
      
      /* --- Output the link. ---
       */
      if (theFile->linkisok == GOOD) 
	{
	  tmp2 = sh_util_safe_name (linknamebuf);      
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_LLNK,
			   theFile->link_c_mode, tmp2);
	  SH_FREE(tmp2);
	}
      SH_FREE(linknamebuf);
    }
  else /* not a link */
    {
      if (content)
	{
#ifdef HAVE_LIBZ
	  unsigned long   clen;
	  unsigned char * compressed;
#ifdef HAVE_COMPRESSBOUND
	  clen       = compressBound(sh_string_len(content));
#else
	  if (sh_string_len(content) > 10*SH_TXT_MAX)
	    clen = SH_TXT_MAX;
	  else
	    clen = 13 + (int)(1.0001*sh_string_len(content));
#endif
	  compressed = SH_ALLOC(clen);
	  if (Z_OK == compress(compressed, &clen, 
			       (unsigned char *) sh_string_str(content), 
			       sh_string_len(content)))
	      {
		if (clen < SH_TXT_MAX)
		  {
		    sh_util_base64_enc_alloc (&(theFile->link_path), 
					      (char *) compressed, clen);
		  }
		else
		  {
		    char tmsg[128];
		    char * tpath = sh_util_safe_name (theFile->fullpath);
		    sl_snprintf(tmsg, sizeof(tmsg), 
				_("compressed file too large (%lu bytes)"),
				clen);
		    sh_error_handle (SH_ERR_WARN, FIL__, __LINE__, -1, 
				     MSG_E_SUBGPATH, tmsg, 
				     _("sh_unix_getinfo"), tpath);
		    SH_FREE(tpath);
		  }
	      }
	  SH_FREE(compressed);
#endif
	  sh_string_destroy(&content);
	}
    } 
  SL_RETURN((0),_("sh_unix_getinfo"));
}

/*  #if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)  */
#endif

int sh_unix_unlock(char * lockfile, char * flag)
{
  int         error = 0;
  
  SL_ENTER(_("sh_unix_unlock"));

  if (sh.flag.isdaemon == S_FALSE && flag == NULL)
    SL_RETURN((0),_("sh_unix_unlock"));

  /* --- Logfile is not locked to us. ---
   */
  if (sh.flag.islocked == BAD && flag != NULL) 
    SL_RETURN((-1),_("sh_unix_unlock"));

  /* --- Check whether the directory is secure. ---
   */
  if (0 != tf_trust_check (lockfile, SL_YESPRIV))
    SL_RETURN((-1),_("sh_unix_unlock"));

  /* --- Delete the lock file. --- 
   */
  error = retry_aud_unlink (FIL__, __LINE__, lockfile);
  
  if (error == 0)
    {
      if (flag != NULL)
	sh.flag.islocked = BAD; /* not locked anymore */
    }
  else if (flag != NULL)
    {
      char errbuf[SH_ERRBUF_SIZE];
      error = errno;
      sh_error_handle ((-1), FIL__, __LINE__, error, MSG_E_UNLNK,
		       sh_error_message(error, errbuf, sizeof(errbuf)), 
		       lockfile);
      SL_RETURN((-1),_("sh_unix_unlock"));
    }
  SL_RETURN((0),_("sh_unix_unlock"));
}

int sh_unix_check_piddir (char * pidpath)
{
  static        struct stat   buf;
  int           status = 0;
  char        * pid_dir;
  
  SL_ENTER(_("sh_unix_check_piddir"));

  pid_dir = sh_util_dirname (pidpath);

  status = retry_lstat (FIL__, __LINE__, pid_dir, &buf);

  if (status < 0 && errno == ENOENT)
    {
      status = mkdir (pid_dir, 0777);
      if (status < 0)
	{
	  sh_error_handle ((-1), FIL__, __LINE__, status,
			   MSG_E_SUBGEN, 
			   _("Cannot create PID directory"),
			   _("sh_unix_check_piddir"));
	  SH_FREE(pid_dir);
	  SL_RETURN((-1),_("sh_unix_check_piddir"));
	}
    }
  else if (!S_ISDIR(buf.st_mode))
    {
      sh_error_handle ((-1), FIL__, __LINE__, status,
		       MSG_E_SUBGEN, 
		       _("Path of PID directory refers to a non-directory object"),
		       _("sh_unix_check_piddir"));
      SH_FREE(pid_dir);
      SL_RETURN((-1),_("sh_unix_check_piddir"));
    }
  SH_FREE(pid_dir);
  SL_RETURN((0),_("sh_unix_check_piddir"));
}

int sh_unix_lock (char * lockfile, char * flag)
{
  int filed;
  int errnum;
  char myPid[64];
  SL_TICKET  fd;
  extern int get_the_fd (SL_TICKET ticket);

  SL_ENTER(_("sh_unix_lock"));

  sprintf (myPid, "%ld\n", (long) sh.pid);             /* known to fit  */

  if (flag == NULL) /* PID file, check for directory */
    {
      if (0 != sh_unix_check_piddir (lockfile))
	{
	  SL_RETURN((-1),_("sh_unix_lock"));
	}
    }

  fd = sl_open_safe_rdwr (FIL__, __LINE__, 
			  lockfile, SL_YESPRIV);      /* fails if file exists */

  if (!SL_ISERROR(fd))
    {
      errnum = sl_write (fd, myPid, sl_strlen(myPid));
      filed = get_the_fd(fd);
      fchmod (filed, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
      sl_close (fd);

      if (!SL_ISERROR(errnum))
	{
	  if (flag != NULL)
	    sh.flag.islocked = GOOD;
	  SL_RETURN((0),_("sh_unix_lock"));
	}
    }

  TPT((0, FIL__, __LINE__, _("msg=<open pid file failed>\n")));
  if (flag != NULL)
    sh.flag.islocked       = BAD;
  SL_RETURN((-1),_("sh_unix_lock"));

  /* notreached */
}


/* check whether file is locked
 */
int sh_unix_test_and_lock (char * filename, char * lockfile)
{
  static        struct stat   buf;
  int           status = 0;


  SL_TICKET     fd;
  char          line_in[128];

  SL_ENTER(_("sh_unix_test_and_lock"));

  status = retry_lstat (FIL__, __LINE__, lockfile, &buf);

  /* --- No lock file found, try to lock. ---
   */

  if (status < 0 && errno == ENOENT)
    {
      if (0 == sh_unix_lock (lockfile, filename))
	{  
	  if (filename != NULL) 
	    sh.flag.islocked = GOOD;
	  SL_RETURN((0),_("sh_unix_test_and_lock"));
	}
      else
	{
	  sh_error_handle ((-1), FIL__, __LINE__, status,
			   MSG_E_SUBGEN, 
			   (filename == NULL) ? _("Cannot create PID file (1)") : _("Cannot create lock file (1)"),
			   _("sh_unix_test_and_lock"));
	  SL_RETURN((-1),_("sh_unix_test_and_lock"));
	}
    }
  else if (status == 0 && buf.st_size == 0)
    {
      if (filename != NULL)
	sh.flag.islocked = GOOD;
      sh_unix_unlock (lockfile, filename);
      if (filename != NULL)
	sh.flag.islocked = BAD;
      if (0 == sh_unix_lock (lockfile, filename))
	{  
	  if (filename != NULL)
	    sh.flag.islocked = GOOD;
	  SL_RETURN((0),_("sh_unix_test_and_lock"));
	}
      else
	{
	  sh_error_handle ((-1), FIL__, __LINE__, status,
			   MSG_E_SUBGEN, 
			   (filename == NULL) ? _("Cannot create PID file (2)") : _("Cannot create lock file (2)"),
			   _("sh_unix_test_and_lock"));
	  SL_RETURN((-1),_("sh_unix_test_and_lock"));
	}
    }

  /* --- Check on lock. ---
   */
  
  if (status >= 0)
    {
       fd = sl_open_read (FIL__, __LINE__, lockfile, SL_YESPRIV);
       if (SL_ISERROR(fd))
	 sh_error_handle ((-1), FIL__, __LINE__, fd,
			  MSG_E_SUBGEN, 
			  (filename == NULL) ? _("Cannot open PID file for read") : _("Cannot open lock file for read"),
			  _("sh_unix_test_and_lock"));
    }
  else
    fd = -1;

  if (!SL_ISERROR(fd))
    {
      /* read the PID in the lock file
       */
      status = sl_read (fd, line_in, sizeof(line_in));
      line_in[sizeof(line_in)-1] = '\0';

      /* convert to numeric
       */
      if (status > 0)
	{
	  errno  = 0;
	  status = strtol(line_in, (char **)NULL, 10);
	  if (errno == ERANGE || status <= 0)
	     {
		sh_error_handle ((-1), FIL__, __LINE__, status,
				 MSG_E_SUBGEN, 
				 (filename == NULL) ? _("Bad PID in PID file") : _("Bad PID in lock file"),
				 _("sh_unix_test_and_lock"));

		status = -1;
	     }
	}
      else
	{
	   sh_error_handle ((-1), FIL__, __LINE__, status,
			    MSG_E_SUBGEN, 
			    (filename == NULL) ? _("Cannot read PID file") : _("Cannot read lock file"),
			    _("sh_unix_test_and_lock"));
	}
      sl_close(fd);

      if (status > 0 && (unsigned int) status == sh.pid)
	{
	  if (filename != NULL)
	    sh.flag.islocked = GOOD;
	  SL_RETURN((0),_("sh_unix_test_and_lock"));
	}


      /* --- Check whether the process exists. ---
       */
      if (status > 0)
	{
	  errno  = 0;
	  status = aud_kill (FIL__, __LINE__, status, 0);

	  /* Does not exist, so remove the stale lock
	   * and create a new one.
	   */
	  if (status < 0 && errno == ESRCH)
	    {
	      if (filename != NULL)
		sh.flag.islocked = GOOD;
	      if (0 != sh_unix_unlock(lockfile, filename) && (filename !=NULL))
		sh.flag.islocked = BAD;
	      else
		{
		  if (0 == sh_unix_lock  (lockfile, filename))
		    {
		      if (filename != NULL)
			sh.flag.islocked = GOOD;
		      SL_RETURN((0),_("sh_unix_test_and_lock"));
		    }
		   else
		    {
		       sh_error_handle ((-1), FIL__, __LINE__, status,
					MSG_E_SUBGEN, 
					(filename == NULL) ? _("Cannot create PID file (3)") : _("Cannot create lock file (3)"),
					_("sh_unix_test_and_lock"));
		    }
		  if (filename != NULL)
		    sh.flag.islocked = BAD;
		}
	    }
	  else
	    {
	      sh_error_handle ((-1), FIL__, __LINE__, status,
			       MSG_E_SUBGEN, 
			       (filename == NULL) ? _("Cannot remove stale PID file, PID may be a running process") : _("Cannot remove stale lock file, PID may be a running process"),
			       _("sh_unix_test_and_lock"));
	      if (filename != NULL)
		sh.flag.islocked = BAD;
	    }
	}
    }
  SL_RETURN((-1),_("sh_unix_testlock"));
}

/* write the PID file
 */
int sh_unix_write_pid_file()
{
  return sh_unix_test_and_lock(NULL, sh.srvlog.alt);
}

/* write lock for filename
 */
int sh_unix_write_lock_file(char * filename)
{
  size_t len;
  int    res;
  char * lockfile;

  if (filename == NULL)
    return (-1);

  len = sl_strlen(filename);
  if (sl_ok_adds(len, 6))
    len += 6;
  lockfile = SH_ALLOC(len);
  sl_strlcpy(lockfile, filename,   len);
  sl_strlcat(lockfile, _(".lock"), len);
  res = sh_unix_test_and_lock(filename, lockfile);
  SH_FREE(lockfile);
  return res;
}

/* rm lock for filename
 */
int sh_unix_rm_lock_file(char * filename)
{
  size_t len;
  int res;
  char * lockfile;

  if (filename == NULL)
    return (-1);

  len = sl_strlen(filename);
  if (sl_ok_adds(len, 6))
    len += 6;
  lockfile = SH_ALLOC(len);
  sl_strlcpy(lockfile, filename,   len);
  sl_strlcat(lockfile, _(".lock"), len);

  res = sh_unix_unlock(lockfile, filename);
  SH_FREE(lockfile);
  return res;
}

/* rm lock for filename
 */
int sh_unix_rm_pid_file()
{
  return sh_unix_unlock(sh.srvlog.alt, NULL);
}

/* Test whether file exists
 */
int sh_unix_file_exists(char * path)
{
  struct stat buf;

  SL_ENTER(_("sh_unix_file_exists"));

  if (0 == retry_lstat(FIL__, __LINE__, path, &buf))
    SL_RETURN( S_TRUE,   _("sh_unix_file_exists"));
  else 
    SL_RETURN( S_FALSE,  _("sh_unix_file_exists"));
}


/* Test whether file exists, is a character device, and allows read
 * access.
 */
int sh_unix_device_readable(int fd)
{
  struct stat buf;

  SL_ENTER(_("sh_unix_device_readable"));

  if (retry_fstat(FIL__, __LINE__, fd, &buf) == -1)
    SL_RETURN( (-1), _("sh_unix_device_readable"));
  else if ( S_ISCHR(buf.st_mode) &&  0 != (S_IROTH & buf.st_mode) ) 
    SL_RETURN( (0), _("sh_unix_device_readable"));
  else 
    SL_RETURN( (-1), _("sh_unix_device_readable"));
}

static char preq[16];

/* return true if database is remote
 */
int file_is_remote ()
{
  static int init = 0;
  struct stat buf;

  SL_ENTER(_("file_is_remote"));

  if (init == 0)
    {
      sl_strlcpy(preq, _("REQ_FROM_SERVER"), 16);
      ++init;
    }
  if (0 == sl_strncmp (sh.data.path, preq, 15))
    {
      if (sh.data.path[15] != '\0') /* should be start of path */
	{
	  if (0 == stat(&(sh.data.path[15]), &buf))
	    {
	      SL_RETURN( S_FALSE, _("file_is_remote"));
	    }
	}
      SL_RETURN( S_TRUE, _("file_is_remote"));
    }
  SL_RETURN( S_FALSE, _("file_is_remote"));
}

/* Return the path to the configuration/database file.
 */
char * file_path(char what, char flag)
{
  static int init = 0;

  SL_ENTER(_("file_path"));

  if (init == 0)
    {
      sl_strlcpy(preq, _("REQ_FROM_SERVER"), 16);
      ++init;
    }

  switch (what)
    {

    case 'C':
      if (0 == sl_strncmp (sh.conf.path, preq, 15))
	{
#if defined(SH_WITH_SERVER)
	  if (sh.flag.isserver == S_TRUE && sl_strlen(sh.conf.path) == 15)
	    SL_RETURN( NULL, _("file_path"));
	  if (sh.flag.isserver == S_TRUE)
	    SL_RETURN( &(sh.conf.path[15]), _("file_path"));
#endif
	  if (flag == 'R')
	    SL_RETURN( preq, _("file_path"));
	  if (flag == 'I')
	    {
	      if (sl_strlen(sh.conf.path) == 15)
		SL_RETURN( NULL, _("file_path"));
	      else
		SL_RETURN( &(sh.conf.path[15]), _("file_path"));
	    }
	  SL_RETURN ( preq, _("file_path"));
	}
      else
	SL_RETURN( sh.conf.path, _("file_path"));
      /* break; *//* unreachable */

    case 'D':
      if (0 == sl_strncmp (sh.data.path, preq, 15))
	{
	  if (flag == 'R')
	    SL_RETURN( preq, _("file_path"));
	  if (flag == 'W' && sl_strlen(sh.data.path) == 15)
	    SL_RETURN (NULL, _("file_path"));
	  if (flag == 'W')
	    SL_RETURN( &(sh.data.path[15]), _("file_path"));
	}
      else
	SL_RETURN( sh.data.path, _("file_path"));
      break;
	
    default:
      SL_RETURN( NULL, _("file_path"));
    }

  return NULL; /* notreached */
}
/************************************************/
/****   Mlock   Utilities                    ****/
/************************************************/

#include <limits.h>

int sh_unix_pagesize()
{
  int pagesize = 4096;
#if defined(_SC_PAGESIZE)
  pagesize = sysconf(_SC_PAGESIZE);
#elif defined(_SC_PAGE_SIZE)
  pagesize = sysconf(_SC_PAGE_SIZE);
#elif defined(HAVE_GETPAGESIZE)
  pagesize = getpagesize();
#elif defined(PAGESIZE)
  pagesize = PAGESIZE;
#endif
  
  return ((pagesize > 0) ? pagesize : 4096);
}

typedef struct sh_page_lt {
  unsigned long  page_start;
  int            page_refcount;
  char           file[64];
  int            line;
  struct sh_page_lt * next;
} sh_page_l;

sh_page_l * sh_page_locked = NULL;
volatile int page_locking = 0;

unsigned long sh_unix_lookup_page (void * in_addr, size_t len, int * num_pages)
{
  int pagesize = sh_unix_pagesize();
  unsigned long  addr = (unsigned long) in_addr;

  unsigned long pagebase;
  unsigned long pagediff;
  unsigned long pagenum   = addr / pagesize;

  SL_ENTER(_("sh_unix_lookup_page"));
#if 0
  fprintf(stderr, "mlock: --> base %ld, pagenum: %ld\n", 
	  addr, pagenum);
#endif

  /* address of first page
   */
  pagebase = pagenum * pagesize;
  
  /* number of pages
   */
  pagediff = (addr + len) - pagebase;
  pagenum  = pagediff / pagesize;
  if (pagenum * pagesize < pagediff)
    ++pagenum;

#if 0
  fprintf(stderr, "mlock: --> pagebase %ld, pagediff %ld, (addr + len) %ld\n", 
	  pagebase, pagediff, (addr + len));
#endif

  *num_pages = pagenum;
  SL_RETURN((pagebase), _("sh_unix_lookup_page"));
}


#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)

SH_MUTEX_STATIC(mutex_mlock,PTHREAD_MUTEX_INITIALIZER);

int sh_unix_mlock (const char * file, int line, void * in_addr, size_t len)
{
  int         num_pages;
  int         status = 0;
  int         pagesize;
  sh_page_l * page_list;
  unsigned long addr;
#ifdef TEST_MLOCK
  int         i = 0;
#endif

  SL_ENTER(_("sh_unix_mlock"));

  /* There's no cancellation point here, except if tracing is on
   */
  SH_MUTEX_LOCK_UNSAFE(mutex_mlock);

  page_list = sh_page_locked;

  if (0 != page_locking)
    {
      status = -1;
      goto exit_mlock;
    }

  page_locking = 1;

  pagesize = sh_unix_pagesize();
  addr = sh_unix_lookup_page (in_addr, len, &num_pages);

#ifdef TEST_MLOCK
  fprintf(stderr, "mlock: addr %ld, base %ld, pages: %d, length %d\n", 
	  (unsigned long) in_addr, addr, num_pages, len);
#endif

  /* increase refcount of locked pages
   * addr is first page; num_pages is #(consecutive pages) to lock
   */

  while ((page_list != NULL) && (num_pages > 0))
    {
#ifdef TEST_MLOCK
      fprintf(stderr, "mlock: check page %d: %ld [%d]\n", 
	      i, page_list->page_start, page_list->page_refcount);
#endif
      if (page_list->page_start == addr)
	{
	  page_list->page_refcount += 1;
	  num_pages -= 1;
	  addr += pagesize;
#ifdef TEST_MLOCK
	  fprintf(stderr, "mlock: found page %d: %ld [%d], next page %ld\n", 
		  i, page_list->page_start, page_list->page_refcount, addr);
#endif
	}
#ifdef TEST_MLOCK
      ++i;
#endif
      page_list = page_list->next;
    }

  /* mlock some more pages, if needed 
   */
  while (num_pages > 0) 
    {
#ifdef TEST_MLOCK
      fprintf(stderr, "mlock: lock  page %d: mlock %ld [num_pages %d]\n", 
	      i, addr, num_pages);
      ++i;
#endif
      page_list = SH_ALLOC(sizeof(sh_page_l));
      page_list->page_start = addr;
      page_list->page_refcount = 1;
      sl_strlcpy(page_list->file, file, 64);
      page_list->line = line;
      status = mlock( (void *) addr, pagesize);
      if (status != 0)
	{
#ifdef TEST_MLOCK
	  char errbuf[SH_ERRBUF_SIZE];
	  fprintf(stderr, "mlock: error: %s\n", 
		  sh_error_message(errno, errbuf, sizeof(errbuf)));
#endif
	  SH_FREE(page_list);
	  page_locking = 0;
	  goto exit_mlock;
	}
      page_list->next = sh_page_locked;
      sh_page_locked  = page_list;
      num_pages -= 1;
      addr += pagesize;
    }
  page_locking = 0;

 exit_mlock:
  SH_MUTEX_UNLOCK_UNSAFE(mutex_mlock);

  SL_RETURN((status), _("sh_unix_mlock"));
}
#else
int sh_unix_mlock (const char * file, int line, void * in_addr, size_t len)
{
  (void) file;    (void) line;
  (void) in_addr; (void) len;
  return -1;
}
#endif

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
int sh_unix_munlock (void * in_addr, size_t len)
{
  int         num_pages;
  int         unlocked;
  int         status;
  int         pagesize;
  sh_page_l * page_list;
  sh_page_l * page_last;
  unsigned long addr;

  int           test_count;
  int           test_status;
  int           test_pages;

#ifdef TEST_MLOCK
  int         i = 0;
#endif

  SL_ENTER(_("sh_unix_munlock"));

  /* There's no cancellation point here, except if tracing is on
   */
  SH_MUTEX_LOCK_UNSAFE(mutex_mlock);

  unlocked  = 0;
  status    = 0;
  page_list = sh_page_locked;

  if (0 != page_locking)
    {
      status = -1;
      goto exit_munlock;
    }
  page_locking = 1;

  pagesize = sh_unix_pagesize();
  addr     = sh_unix_lookup_page (in_addr, len, &num_pages);

#ifdef TEST_MLOCK
  fprintf(stderr, "munlock: in_addr %ld, addr %ld, pages: %d, length %d\n", 
	  (unsigned long) in_addr, addr, num_pages, len);
#endif

  test_pages = num_pages;

  /* reduce refcount of locked pages
   * addr is first page; num_pages is #(consecutive pages) to lock
   */
  while ((page_list != NULL) && (num_pages > 0))
    {
#ifdef TEST_MLOCK
      fprintf(stderr, "munlock: page %d: %ld [%d]\n", 
	      i, page_list->page_start, page_list->page_refcount);
#endif

      test_status = 0;
      for (test_count = 0; test_count < test_pages; ++test_count)
	{
	  if (page_list->page_start == (addr + (test_count * pagesize)))
	    {
	      test_status = 1;
	      break;
	    }
	}

      if (test_status == 1)
	{
	  page_list->page_refcount -= 1;
	  if (page_list->page_refcount == 0)
	    {
	      status = munlock ( (void *) addr, pagesize);
	      ++unlocked;
	    }
	  num_pages -= 1;
#ifdef TEST_MLOCK
	  fprintf(stderr, 
		  "munlock: page %d: %ld [refcount %d], refcount reduced\n", 
		  i, page_list->page_start, page_list->page_refcount);
#endif
	}
#ifdef TEST_MLOCK
      ++i;
#endif
      page_list = page_list->next;
    }

#ifdef TEST_MLOCK
      i = 0;
#endif

  if (unlocked > 0)
    {
      page_list = sh_page_locked;
      page_last = sh_page_locked;

      while ((page_list != NULL) && (unlocked > 0))
	{
	  if (page_list->page_refcount == 0)
	    {
#ifdef TEST_MLOCK
	      fprintf(stderr, "munlock: remove page %d: %ld [refcount %d]\n", 
		      i, page_list->page_start, page_list->page_refcount);
#endif
	      if (page_last != page_list)
		{
		  page_last->next = page_list->next;
		  SH_FREE(page_list);
		  page_list = page_last->next;
		}
	      else
		{
		  page_last = page_list->next;
		  if (page_list == sh_page_locked)
		    sh_page_locked = page_list->next;
		  SH_FREE(page_list);
		  page_list = page_last;
		}
	      --unlocked;
	    }
	  else
	    {
#ifdef TEST_MLOCK
	      fprintf(stderr, "munlock: skip   page %d: %ld [refcount %d]\n", 
		      i, page_list->page_start, page_list->page_refcount);
#endif

	      page_last = page_list;
	      page_list = page_list->next;
	    }
#ifdef TEST_MLOCK
	  ++i;
#endif
	}
    }

  page_locking = 0;

 exit_munlock:
  SH_MUTEX_UNLOCK_UNSAFE(mutex_mlock);
  SL_RETURN((status), _("sh_unix_munlock"));
}
#else
int sh_unix_munlock (void * in_addr, size_t len)
{
  (void) in_addr; (void) len;
  return -1;
}
#endif

int sh_unix_count_mlock()
{
  int i = 0;
  char str[32][64];
  sh_page_l * page_list;

  SL_ENTER(_("sh_unix_count_mlock"));

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
  /* There's no cancellation point here, except if tracing is on
   */
  SH_MUTEX_LOCK_UNSAFE(mutex_mlock);
#endif

  page_list = sh_page_locked;

  while (page_list != NULL)
    {
#ifdef WITH_TPT
      if (i < 32)
	sl_snprintf(str[i], 64, _("file: %s line: %d page: %d"), 
		    page_list->file, page_list->line, i+1);
#endif
      page_list = page_list->next;
      ++i;
    }

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
  SH_MUTEX_UNLOCK_UNSAFE(mutex_mlock);
#endif

#ifdef WITH_TPT
  {
    int j = 0;
    while (j < i && j < 32)
      {
	sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, j, MSG_E_SUBGEN,
			str[j], _("sh_unix_count_mlock"));
	++j;
      }
  }
#endif

  sl_snprintf(str[0], 64, _("%d pages locked"), i);
  sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, i, MSG_E_SUBGEN,
		  str[0], _("sh_unix_count_mlock"));
  SL_RETURN((i), _("sh_unix_count_mlock"));
}

/************************************************/
/************************************************/
/****   Stealth Utilities                    ****/
/************************************************/
/************************************************/
#ifdef SH_STEALTH

void sh_unix_xor_code (char * str, int len)
{
  register int i;

  for (i = 0; i < len; ++i) str[i] ^= (char) XOR_CODE;
  return;
}

#if  !defined(SH_STEALTH_MICRO)


int hideout_hex_block(SL_TICKET fd, unsigned char * str, int len,
		      unsigned long * bytes_read);
unsigned long first_hex_block(SL_TICKET fd, unsigned long * max);

/*
 * --- Get hidden data from a block of hex data. ---
 */
int sh_unix_getline_stealth (SL_TICKET fd, char * str, int len)
{
  int                  add_off = 0, llen;
  static unsigned long off_data   = 0;
  static unsigned long max_data   = 0;
  static unsigned long bytes_read = 0;
  static int           stealth_init = BAD;

  SL_ENTER(_("sh_unix_getline_stealth"));

  if (str == NULL)
    {
      off_data   = 0;
      max_data   = 0;
      bytes_read = 0;
      stealth_init = BAD;
      SL_RETURN(0, _("sh_unix_getline_stealth"));
    }

  /* --- Initialize. ---
   */
  if (stealth_init == BAD)
    {
      off_data = first_hex_block(fd, &max_data);
      if (off_data == 0)
	{
	  dlog(1, FIL__, __LINE__, 
	       _("The stealth config file does not contain any steganographically\nhidden data. This file must be an image file in _uncompressed_\npostscript format.\nTo hide data in it, use:\n   samhain_stealth -s postscript_file orig_config_file\n   mv postscript_file /path/to/config/file\n"));
	  sh_error_handle ((-1), FIL__, __LINE__,  EIO, MSG_P_NODATA,
			   _("Stealth config file."));
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}
      stealth_init = GOOD;
      max_data += off_data;
    }
  
  /* --- Seek to proper position. ---
   */
  if (bytes_read >= max_data || add_off < 0)
    {
      dlog(1, FIL__, __LINE__, 
	   _("The capacity of the container image file for the stealth config file seems to be too small. Your config file is likely truncated.\n"));
      sh_error_handle ((-1), FIL__, __LINE__,  EIO, MSG_P_NODATA,
		       _("Stealth config file."));
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
    }
  sl_seek(fd, off_data);
     
  /* --- Read one line. ---
   */
  add_off   = hideout_hex_block(fd, (unsigned char *) str, len, &bytes_read);
  off_data += add_off;

  llen = sl_strlen(str);
  SL_RETURN(llen, _("sh_unix_getline_stealth"));
}

int hideout_hex_block(SL_TICKET fd, unsigned char * str, int len, 
		      unsigned long * bytes_read)
{

  register int  i, j, k;
  unsigned char c, e;
  register int  num;
  unsigned char mask[9] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
  unsigned long here   = 0;
  unsigned long retval = 0;
  unsigned long bread  = 0;

  SL_ENTER(_("hideout_hex_block"));

  ASSERT_RET((len > 1), _("len > 1"), (0));

  --len;

  i = 0;
  while (i < len)
    {
      for (j = 0; j < 8; ++j)
	{

	  /* --- Get a low byte, modify, read back. --- 
	   */
	  for (k = 0; k < 2; ++k)
	    {
	      /* -- Skip whitespace. ---
	       */
	      c = ' ';
	      do {
		do {
		  num = sl_read (fd, &c, 1);
		} while (num == 0 && errno == EINTR);
		if (num > 0)
		  ++here;
		else if (num == 0)
		  SL_RETURN((0), _("hideout_hex_block"));
		else 
		  SL_RETURN((-1), _("hideout_hex_block"));
	      } while (c == '\n' || c == '\t' || c == '\r' || 
		       c == ' ');
	    }
	  

	  /* --- e is the value of the low byte. ---
	   */
	  e = (unsigned char) sh_util_hexchar( c );
	  if ((e & mask[7]) != 0)  /* bit is set     */
	    str[i] |= mask[j];
	  else                     /* bit is not set */
	    str[i] &= ~mask[j];

	  bread += 1;
	}
      if (str[i] == '\n') break;
      ++i;
    }

  if (i != 0)
    str[i] = '\0';
  else
    str[i+1] = '\0'; /* keep newline and terminate */
  retval += here;
  *bytes_read += (bread/8);

  SL_RETURN(retval, _("hideout_hex_block"));
}

/* --- Get offset of first data block. ---
 */
unsigned long first_hex_block(SL_TICKET fd, unsigned long * max)
{
  unsigned int  i;
  long          num = 1;
  unsigned long lnum;
  char          c;
  int           nothex = 0;
  unsigned long retval = 0;
  unsigned int  this_line = 0;
  char          theline[SH_BUFSIZE];

  SL_ENTER(_("first_hex_block"));

  *max = 0;

  while (1)
    {
      theline[0] = '\0';
      this_line  = 0;
      c          = '\0';
      while (c != '\n' && num > 0 && this_line < (sizeof(theline)-1))
	{
	  do {
	    num = sl_read (fd, &c, 1);
	  } while (num == 0 && errno == EINTR);
	  if (num > 0) 
	    theline[this_line] = c;
	  else           
	    SL_RETURN((0), _("first_hex_block"));
	  ++this_line;
	}
      theline[this_line] = '\0';
      
      /* not only 'newline' */ 
      if (this_line > 60)
	{
	  nothex  = 0;
	  i       = 0;
	  while (nothex == 0 && i < (this_line-1))
	    {
	      if (! isxdigit((int)theline[i])) nothex = 1;
	      ++i;
	    }
	  if (nothex == 1) retval += this_line;
	}
      else
	{
	  nothex = 1;
	  retval += this_line;
	}

      if (nothex == 0)
	{
	  *max = 0; 
	  do {
	    do {
	      num = sl_read (fd, theline, SH_BUFSIZE);
	    } while (num == 0 && errno == EINTR);
	    if (num > 0)
	      {
		lnum = (unsigned long) num;
		for (i = 0; i < lnum; ++i)
		  { 
		    c = theline[i];
		    if (c == '\n' || c == '\t' || c == '\r' || c == ' ') 
		      ;
		    else if (!isxdigit((int)c))
		      break;
		    else
		      *max += 1;
		  }
	      }
	  } while (num > 0);

	  *max /= 16;
	  SL_RETURN((retval), _("first_hex_block"));
	}

    }
  /* SL_RETURN((0), _("first_hex_block")); *//* unreachable */
}

 /* if !defined(SH_STEALTH_MICRO) */
#endif 

 /* ifdef SH_STEALTH */
#endif

/*
 * anti-debugger code
 */
#if defined(SCREW_IT_UP)
volatile int sh_not_traced = 0;

#ifdef HAVE_GETTIMEOFDAY
struct timeval  save_tv;
#endif

void sh_sigtrap_handler (int signum)
{
#ifdef HAVE_GETTIMEOFDAY
  struct timeval  tv;
  long   difftv;
  
  gettimeofday(&tv, NULL);
  difftv = (tv.tv_sec - save_tv.tv_sec) * 1000000 + 
    (tv.tv_usec - save_tv.tv_usec);
  if (difftv > 500000)
    raise(SIGKILL);
#endif
  sh_not_traced += signum;
  return;
}
#endif
