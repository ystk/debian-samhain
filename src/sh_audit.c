/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2010 Rainer Wichmann                                      */
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

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#if !defined(SH_COMPILE_STATIC) && defined(__linux__) && defined(HAVE_AUPARSE_H) && defined(HAVE_AUPARSE_LIB)
#include <auparse.h>

#include "samhain.h"
#include "sh_error.h"
#include "sh_extern.h"
#include "sh_utils.h"

#undef  FIL__
#define FIL__  _("sh_audit.c")

#define REC_SIZE_SYSCALL 32
#define REC_SIZE_EXE     64
#define REC_SIZE_SUCCESS 32

struct recordState {
  char syscall[REC_SIZE_SYSCALL];
  char exe[REC_SIZE_EXE];
  char success[REC_SIZE_SUCCESS];
  unsigned int auid;
  unsigned int uid;
  unsigned int gid; 
  unsigned int euid; 
  unsigned int egid;
  unsigned int fsuid; 
  unsigned int fsgid;
  time_t time;
  unsigned int milli;
};

static int listRecords (auparse_state_t * au, struct recordState * state)
{
  if (auparse_first_record(au) != 1)
    return -1;

  state->time  = auparse_get_time(au);
  state->milli = auparse_get_milli(au);

  if (auparse_find_field(au, _("syscall")))
    sl_strlcpy(state->syscall, auparse_interpret_field(au), REC_SIZE_SYSCALL);

  if (auparse_find_field(au, _("success")))
    strncpy(state->success, auparse_interpret_field(au), REC_SIZE_SUCCESS);

  if (auparse_find_field(au, "uid"))
    state->uid = auparse_get_field_int(au);
  if (auparse_find_field(au, "gid"))
    state->gid = auparse_get_field_int(au);

  if (auparse_find_field(au, _("euid")))
    state->euid = auparse_get_field_int(au);
  if (auparse_find_field(au, _("fsuid")))
    state->fsuid = auparse_get_field_int(au);

  auparse_first_field(au);

  if (auparse_find_field(au, _("auid")))
    state->auid = auparse_get_field_int(au);

  auparse_first_field(au);

  if (auparse_find_field(au, _("egid")))
    state->egid = auparse_get_field_int(au);
  if (auparse_find_field(au, _("fsgid")))
    state->fsgid = auparse_get_field_int(au);

  auparse_first_field(au);

  if (auparse_find_field(au, "exe"))
    sl_strlcpy(state->exe, auparse_interpret_field(au), REC_SIZE_EXE);

  return 0;
}
    
static char * doAuparse (char * file, time_t time, char * result, size_t rsize)
{
  struct recordState state;
  struct recordState stateFetched;

  auparse_state_t * au = auparse_init(AUSOURCE_LOGS, NULL);

  if (!au)
    {
      char ebuf[SH_ERRBUF_SIZE];
      int  errnum = errno;

      sl_snprintf(ebuf, sizeof(ebuf), _("Error in auparse_init() - %s\n"), 
		  strerror(errnum));
      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, errnum, MSG_E_SUBGEN,
		       ebuf,
		       _("doAuparse") );
      return NULL;
    }

  if (ausearch_add_interpreted_item(au, _("name"), "=", file, 
				    AUSEARCH_RULE_CLEAR) != 0)
    {
      goto err;
    }

  if (time != 0)
    {
      ausearch_add_timestamp_item(au, ">=", time-1, 0, AUSEARCH_RULE_AND);
      ausearch_add_timestamp_item(au, "<=", time+1, 0, AUSEARCH_RULE_AND);
    }

  if (ausearch_set_stop(au, AUSEARCH_STOP_RECORD) != 0)
    {
      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       _("Error in ausearch_set_stop\n"),
		       _("doAuparse") );
      goto err;
    }

  memset(&state, '\0', sizeof(state));

  while (ausearch_next_event(au) == 1) 
    {
      memset(&stateFetched, '\0', sizeof(state));
      listRecords(au, &stateFetched);
      if (0 == strcmp(stateFetched.success, "yes"))
	{
	  memcpy(&state, &stateFetched, sizeof(state));
	}
      auparse_next_event(au);
    }

  if (0 == strcmp(state.success, "yes"))
    {
      char * tmp_exe = sh_util_safe_name(state.exe);
      sl_snprintf(result, rsize, 
		  _("time=%lu.%u, syscall=%s, auid=%u, uid=%u, gid=%u, euid=%u, egid=%u, fsuid=%u, fsgid=%u, exe=%s"),
		  (unsigned long) state.time, state.milli, 
		  state.syscall,
		  state.auid, state.uid, state.gid, state.euid, state.egid, 
		  state.fsuid, state.fsgid, tmp_exe);
      SH_FREE(tmp_exe);
      auparse_destroy(au);
      return result;
    }

 err:
  auparse_destroy(au);
  return NULL;
}

static int sh_audit_checkdaemon();
static int  actl_pnum = -1;
static char * actl_paths[4] = 
  { 
    N_("/sbin/auditctl"), 
    N_("/usr/sbin/auditctl"),
    N_("/bin/auditctl"), 
    N_("/usr/bin/auditctl") 
  };


/* Public function to fetch an audit record for path 'file', time 'time'
 * The 'result' array should be sized ~256 char. 
 */
char * sh_audit_fetch (char * file, time_t time, char * result, size_t rsize)
{
  char * res = NULL;

  if (sh_audit_checkdaemon() >= 0)
    {
      res = doAuparse (file, time, result, rsize);

      if (!res)
	{
	  res = doAuparse (file, 0, result, rsize);
	}
    }
  return res;
}

void sh_audit_delete_all ()
{
  int p = sh_audit_checkdaemon();

  if (p >= 0)
    {
      char command[64];

      sl_snprintf(command, sizeof(command), _("%s -D -k samhain"),
		  _(actl_paths[p]));
      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
		       0, MSG_E_SUBGEN,
		       _("Deleting audit daemon rules with key samhain"),
		       _("sh_audit_delete_all") );
      sh_ext_system(command);
    }
  return;
}

void sh_audit_mark (char * file)
{
  static int flushRules = 0;

  int p = sh_audit_checkdaemon();

  /* Flush all rules at startup.
   */
  if (flushRules == 0)
    {
      sh_audit_delete_all ();
      flushRules = 1;
    }

  if (p >= 0)
    {
      size_t len = strlen(file) + 64;
      char * command = SH_ALLOC(len);
      char * safe;

      sl_snprintf(command, len, _("%s -w %s -p wa -k samhain"),
		  _(actl_paths[p]),
		  file);

      safe = sh_util_safe_name_keepspace(command);
      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
		       0, MSG_E_SUBGEN,
		       safe,
		       _("sh_audit_mark") );
      SH_FREE(safe);

      sh_ext_system(command);
    }
  return;
}


static int sh_audit_checkdaemon()
{
  int  i;
  static int flag = 0;
  char command[64];
  char * p;

  if (flag != 0)
    return -1;

  if (actl_pnum >= 0)
    return actl_pnum;

  for (i = 0; i < 4; ++i)
    {
      if (0 == access(_(actl_paths[i]), F_OK))/* flawfinder: ignore */
	{
	  if (0 == access(_(actl_paths[i]), X_OK))/* flawfinder: ignore */
	    {
	      actl_pnum = i;
	      break;
	    }
	  else
	    {
	      char ebuf[SH_ERRBUF_SIZE];
	      int  errnum = errno;
	      
	      sl_snprintf(ebuf, sizeof(ebuf), 
			  _("Cannot execute auditctl - %s\n"), 
			  strerror(errnum));
	      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
			       errnum, MSG_E_SUBGEN,
			       ebuf,
			       _("sh_audit_checkdaemon") );
	      flag = 1;
	      actl_pnum = -1;
	      return -1;
	    }
	}
    }

  if (actl_pnum == -1 && flag == 0)
    {
      char ebuf[SH_ERRBUF_SIZE];
      int  errnum = errno;
      
      sl_snprintf(ebuf, sizeof(ebuf), 
		  _("Cannot find auditctl - %s\n"), 
		  strerror(errnum));
      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
		       errnum, MSG_E_SUBGEN,
		       ebuf,
		       _("sh_audit_checkdaemon") );
      flag = 1;
      actl_pnum = -1;
      return -1;
    }

  /* We found an executable auditctl */

  sl_snprintf(command, sizeof(command), _("%s -s"), _(actl_paths[actl_pnum]));
  sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
		   0, MSG_E_SUBGEN,
		   command,
		   _("sh_audit_checkdaemon") );
  p = sh_ext_popen_str (command);

  if (p)
    {
      int retval = -1;
      if (strstr(p, _(" pid=0 ")))
	{
	  sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
			   0, MSG_E_SUBGEN,
			   _("Audit daemon for Linux kernel audit system is not running"),
			   _("sh_audit_checkdaemon") );
	  flag = 1;
	  actl_pnum = -1;
	}
      else
	{
	  retval = actl_pnum;
	  sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
			   retval, MSG_E_SUBGEN,
			   _("Audit daemon is running"),
			   _("sh_audit_checkdaemon") );
	}
      SH_FREE(p);
      return retval;
    }

  sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
		   errno, MSG_E_SUBGEN,
		   _("No output from auditctl -s"),
		   _("sh_audit_checkdaemon") );
  flag = 1;
  actl_pnum = -1;
  return -1;
}

/* HAVE_AUPARSE_H */
#else
char * sh_audit_fetch (char * file, time_t time, char * result, size_t rsize)
{
  (void) file;
  (void) time;
  (void) result;
  (void) rsize;

  return 0;
}
void sh_audit_mark (char * file)
{
  (void) file;
  return;
}
void sh_audit_delete_all ()
{
  return;
}
#endif

/* client || standalone */
#endif

