/**************************************
 **
 ** PARSER RULES
 **
 ** (a) must set record->host 
 **     (eventually to dummy value)
 **
 ** (b) must set record->prefix
 **     (itoa(status)) 
 **
 **
 **************************************/

#include "config_xor.h"

#ifdef USE_LOGFILE_MONITOR

#undef  FIL__
#define FIL__  _("sh_log_parse_apache.c")

#include <string.h>
#include <time.h>

/* Debian/Ubuntu: libpcre3-dev */
#ifdef HAVE_PCRE_PCRE_H
#include <pcre/pcre.h>
#else
#include <pcre.h>
#endif

#include "samhain.h"
#include "sh_log_check.h"
#include "sh_string.h"

struct sh_fileinfo_generic {
  pcre * line_regex;
  int  * line_ovector;         /* captured substrings     */
  int    line_ovecnum;         /* how many captured       */
  
  int    pos_host;
  int    pos_status;
  int    pos_time;
  char * format_time;
};

static void default_time (struct sh_logrecord * record)
{
  struct tm ts;
  char   tmp[80];
  size_t len;

  record->timestamp = time(NULL);
  
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
  localtime_r (&(record->timestamp), &ts);
#else
  memcpy(&ts, localtime(&(record->timestamp)), sizeof(struct tm));
#endif
  len = strftime(tmp, sizeof(tmp), _("%Y-%m-%dT%H:%M:%S"), &ts);

  record->timestr   = sh_string_new_from_lchar(tmp, len);

  return;
}

static void default_host (struct sh_logrecord * record)
{
  record->host      = sh_string_new_from_lchar(sh.host.name, strlen(sh.host.name));
  return;
}

sh_string * sh_read_shell (sh_string * record, struct sh_logfile * logfile)
{
  return sh_command_reader (record, logfile);
}

struct sh_logrecord * sh_parse_shell (sh_string * logline, void * fileinfo)
{
  (void) fileinfo;

  if (logline)
    {
      struct sh_logrecord * record = SH_ALLOC(sizeof(struct sh_logrecord));

      default_time(record);
      default_host(record);

      record->message   = sh_string_new_from_lchar(sh_string_str(logline), 
						   sh_string_len(logline));
      record->pid       = PID_INVALID;
      return record;
    }
  return NULL;
}

void * sh_eval_fileinfo_generic(char * str)
{
  (void) str;

  return NULL;
}

struct sh_logrecord * sh_parse_generic (sh_string * logline, void * fileinfo)
{
  (void) logline;
  (void) fileinfo;

  return NULL;
}

#endif
