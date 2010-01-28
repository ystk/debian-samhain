/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000, 2001, 2002 Rainer Wichmann                    */
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

/* define this if you want version 1.3 style database file */
/* #define OLD_BUG */

/* make sure state changes of a file are always reported, even
 *  with reportonlyonce=true
 */
/* #define REPLACE_OLD *//* moved to samhain.h */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#else
#ifdef MAJOR_IN_SYSMACROS
#include <sys/sysmacros.h>
#endif
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

#include "sh_hash.h"
#include "sh_utils.h"
#include "sh_error.h"
#include "sh_tiger.h"
#include "sh_gpg.h"
#include "sh_unix.h"
#include "sh_files.h"
#include "sh_ignore.h"
#include "sh_pthread.h"

#if defined(SH_WITH_CLIENT)
#include "sh_forward.h"
#endif


#define SH_KEY_NULL _("000000000000000000000000000000000000000000000000")


#undef  FIL__
#define FIL__  _("sh_hash.c")

SH_MUTEX_STATIC(mutex_hash,PTHREAD_MUTEX_INITIALIZER);

const char notalink[2] = { '-', '\0' };

static char * all_items (file_type * theFile, char * fileHash, int is_new);

#define QUOTE_CHAR '='

char * unquote_string (const char * str, size_t len)
{
  int    i = 0, t1, t2;
  char * tmp = NULL;
  size_t l2, j, k = 0;

  SL_ENTER(_("unquote_string"));

  if (str != NULL)
    {
      l2  = len - 2;
      tmp = SH_ALLOC(len + 1);

      for (j = 0; j <= len; ++j)
	{
	  if (str[j] != QUOTE_CHAR)
	    {
	      tmp[k] = str[j];
	    }
	  else if (str[j] == QUOTE_CHAR && j < l2)
	    {
	      t1 = sh_util_hexchar(str[j+1]);
	      t2 = sh_util_hexchar(str[j+2]);
	      if ((t1|t2) >= 0)
		{
		  i = 16 * t1 + t2;
		  tmp[k] = i; 
		  j += 2;
		}
	      else
		{
		  tmp[k] = str[j];
		}
	    }
	  else
	    tmp[k] = str[j];
	  ++k;
	}
    }
  SL_RETURN(tmp, _("unquote_string"));
}


static char * int2hex (unsigned char i, char * i2h)
{
  static char hexchars[] = "0123456789ABCDEF";

  i2h[0] = hexchars[(((i) & 0xF0) >> 4)]; /* high */
  i2h[1] = hexchars[((i) & 0x0F)];        /* low  */

  return i2h;
}


char * quote_string (const char * str, size_t len)
{
  char * tmp;
  char * tmp2;
  size_t l2, j, i = 0, k = 0;
  char   i2h[2];

  SL_ENTER(_("quote_string"));

  if (str == NULL)
    {
      SL_RETURN(NULL, _("quote_string"));
    }

  for (j = 0; j < len; ++j)
    if (str[j] == '\n' || str[j] == QUOTE_CHAR) ++i;

  l2 = len + 1;
  if (sl_ok_muls(3, i) && sl_ok_adds(l2, (3*i)))
    {
      tmp = SH_ALLOC(len + 1 + 3*i);
    }
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		      _("integer overflow"), 
		      _("quote_string"));
      SL_RETURN(NULL, _("quote_string"));
    }

  for (j = 0; j <= len; ++j)
    {
      if (str[j] == '\n')
	{
	  tmp2 = int2hex((unsigned char) '\n', i2h); /* was 'n', fixed in 1.5.4 */
	  tmp[k] = QUOTE_CHAR; ++k;
	  tmp[k] = tmp2[0];    ++k;
	  tmp[k] = tmp2[1];
	}
      else if (str[j] == QUOTE_CHAR)
	{
	  tmp2 = int2hex((unsigned char) QUOTE_CHAR, i2h);
	  tmp[k] = QUOTE_CHAR; ++k;
	  tmp[k] = tmp2[0];    ++k;
	  tmp[k] = tmp2[1];
	}
      else
	{
	  tmp[k] = str[j];
	}
      ++k;
    }
  SL_RETURN(tmp, _("quote_string"));
}

static UINT32 * swap_32 (UINT32 * iptr)
{
#ifdef WORDS_BIGENDIAN
  unsigned char swap;
  unsigned char * ii = (unsigned char *) iptr;
  swap = ii[0]; ii[0] = ii[3]; ii[3] = swap;
  swap = ii[1]; ii[1] = ii[2]; ii[2] = swap;
  return iptr;
#else
  return iptr;
#endif
}

static UINT64 *  swap_64 (UINT64 * iptr)
{
#ifdef WORDS_BIGENDIAN
#ifdef UINT64_IS_32
  swap_32 ((UINT32*) iptr);
#else
  unsigned char swap;
  unsigned char * ii = (unsigned char *) iptr;
  swap = ii[0]; ii[0] = ii[7]; ii[7] = swap;
  swap = ii[1]; ii[1] = ii[6]; ii[6] = swap;
  swap = ii[2]; ii[2] = ii[5]; ii[5] = swap;
  swap = ii[3]; ii[3] = ii[4]; ii[4] = swap;
#endif
  return iptr;
#else
  return iptr;
#endif
}

static unsigned short *  swap_short (unsigned short * iptr)
{
#ifdef WORDS_BIGENDIAN
  if (sizeof(short) == 4)
    swap_32 ((UINT32*) iptr);
  else
    {
      /* alignment problem */
      unsigned char swap;
      static unsigned short ooop;
      unsigned char * ii;
      ooop = *iptr;
      ii = (unsigned char *) &ooop;
      /* printf("SWAP0: %hd  %d\n", *iptr, sizeof(unsigned short)); */
      swap = ii[0]; ii[0] = ii[1]; ii[1] = swap;
      /* printf("SWAP1: %hd\n", (unsigned short) ooop); */
#ifndef OLD_BUG
      return &ooop;
#endif
    }
  return iptr;
#else
  return iptr;
#endif
}


typedef struct store_info {

  UINT32           mode;
  UINT32           linkmode;

  UINT64           dev;
  UINT64           rdev;
  UINT32           hardlinks;
  UINT32           ino;
  UINT64           size;
  UINT64           atime;
  UINT64           mtime;
  UINT64           ctime;
  UINT32           owner;
  UINT32           group;

#ifdef OLD_BUG
#if defined(__linux__)
  UINT32           attributes;
  char             c_attributes[ATTRBUF_SIZE];
#endif
#else
  /* #if defined(__linux__) */
  UINT32           attributes;
  char             c_attributes[ATTRBUF_SIZE];
  /* endif                  */
#endif
  unsigned short   mark;
  char             c_owner[USER_MAX+2];
  char             c_group[GROUP_MAX+2];
  char             c_mode[CMODE_SIZE];
  char             checksum[KEY_LEN+1];
} sh_filestore_t;
  
typedef struct file_info {
  sh_filestore_t   theFile;
  char           * fullpath;
  char           * linkpath;
  char           * attr_string;
  int              fflags;
  unsigned long    modi_mask;
  struct           file_info * next;
} sh_file_t;

  static const char  *policy[] = {
    N_("[]"),
    N_("[ReadOnly]"),
    N_("[LogFiles]"),
    N_("[GrowingLogs]"),
    N_("[IgnoreNone]"),
    N_("[IgnoreAll]"),
    N_("[Attributes]"),
    N_("[User0]"),
    N_("[User1]"),
    N_("[User2]"),
    N_("[User3]"),
    N_("[User4]"),
    N_("[Prelink]"),
    NULL
  };


/**********************************
 *
 * hash table functions
 *
 **********************************
 */

#include "sh_hash.h"

/* must fit an int              */
/* #define TABSIZE 2048         */
#define TABSIZE 65536

/* must fit an unsigned short   */
/* changed for V0.8, as the     */
/* database format has changed  */

/* changed again for V0.9       */
/* #define REC_MAGIC 19         */
/* changed again for V1.3       */
#ifdef OLD_BUG
#define REC_MAGIC 20
#else
/* changed again for V1.4       */
#define REC_MAGIC 21
#endif

#define REC_FLAGS_ATTR (1<<8)
#define REC_FLAGS_MASK 0xFF00

/**************************************************************
 *
 * create a file_type from a sh_file_t
 *
 **************************************************************/
static file_type * sh_hash_create_ft (const sh_file_t * p, char * fileHash)
{
  file_type * theFile;

  SL_ENTER(_("sh_hash_create_ft"));

  theFile = SH_ALLOC(sizeof(file_type));

  sl_strlcpy(theFile->c_mode, p->theFile.c_mode, 11);
  theFile->mode  =  p->theFile.mode;
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  sl_strlcpy(theFile->c_attributes, p->theFile.c_attributes, ATTRBUF_SIZE);
  theFile->attributes =  p->theFile.attributes;
#endif

  sl_strlcpy(theFile->fullpath, p->fullpath, PATH_MAX);
  if (p->linkpath != NULL /* && theFile->c_mode[0] == 'l' */)
    {
      theFile->link_path = sh_util_strdup(p->linkpath);
    }
  else
    {
      theFile->link_path = NULL;
    }
  sl_strlcpy(fileHash, p->theFile.checksum, KEY_LEN+1);
  
  theFile->mtime =  p->theFile.mtime;
  theFile->ctime =  p->theFile.ctime;
  theFile->atime =  p->theFile.atime;
  
  theFile->size  =  p->theFile.size;
  
  sl_strlcpy(theFile->c_group, p->theFile.c_group, GROUP_MAX+2);
  theFile->group =  p->theFile.group;
  sl_strlcpy(theFile->c_owner, p->theFile.c_owner, USER_MAX+2);
  theFile->owner =  p->theFile.owner;
  
  theFile->ino   =  p->theFile.ino;
  theFile->rdev  =  p->theFile.rdev;
  theFile->dev   =  p->theFile.dev;
  theFile->hardlinks = p->theFile.hardlinks;

  if (p->attr_string)
    theFile->attr_string = sh_util_strdup(p->attr_string);
  else
    theFile->attr_string = NULL;

  SL_RETURN((theFile), _("sh_hash_create_ft"));
}

static sh_file_t * hashsearch (char * s);

static sh_file_t * tab[TABSIZE];

/**************************************************************
 *
 * compute hash function
 *
 **************************************************************/

static int hashfunc(char *s) 
{
  unsigned int n = 0; 

  for ( ; *s; s++) 
    n = 31 * n + *s; 

  return n & (TABSIZE - 1); /* % TABSIZE */; 
} 


int hashreport_missing( char *fullpath, int level)
{
  sh_file_t * p;
  char * tmp;
  char   fileHash[KEY_LEN + 1];
  file_type * theFile;
  char * str;
  char hashbuf[KEYBUF_SIZE];
  int  retval;

  /* --------  find the entry for the file ----------------       */

  SH_MUTEX_LOCK(mutex_hash);

  retval = 0;

  if (sl_strlen(fullpath) <= MAX_PATH_STORE) 
    p = hashsearch(fullpath);
  else 
    p = hashsearch( sh_tiger_hash(fullpath, 
				  TIGER_DATA, 
				  sl_strlen(fullpath),
				  hashbuf, sizeof(hashbuf))
		    );
  if (p == NULL)
    {
      retval = -1;
      goto unlock_and_return;
    }

  theFile = sh_hash_create_ft (p, fileHash);
  str = all_items(theFile, fileHash, 0);
  tmp = sh_util_safe_name(fullpath);
  sh_error_handle (level, FIL__, __LINE__, 0, 
		   MSG_FI_MISS2, tmp, str);
  SH_FREE(tmp);
  SH_FREE(str);
  if (theFile->attr_string) SH_FREE(theFile->attr_string);
  if (theFile->link_path)   SH_FREE(theFile->link_path);
  SH_FREE(theFile);

 unlock_and_return:
  ; /* 'label at end of compound statement */
  SH_MUTEX_UNLOCK(mutex_hash);
  return retval;
}


/**************************************************************
 *
 * search for files not visited, and check whether they exist
 *
 **************************************************************/
static void hash_unvisited (int j, 
			    sh_file_t *prev, sh_file_t *p, ShErrLevel level)
{
  struct stat buf;
  int i;
  char * tmp;
  char * ptr;
  char   fileHash[KEY_LEN + 1];
  file_type * theFile;

  char * str;


  SL_ENTER(_("hash_unvisited"));

  if (p->next != NULL)
    hash_unvisited (j, p, p->next, level);

  if (p->fullpath == NULL)
    {
      SL_RET0(_("hash_unvisited"));
    }

  /* Not a fully qualified path, i.e. some info stored by some module
   */
  if (p->fullpath[0] != '/')
    {
      SL_RET0(_("hash_unvisited"));
    }

  /* visited   flag not set: not seen; 
   * checked   flag     set: not seen (i.e. missing), and already checked 
   * reported  flag not set: not reported yet
   * allignore flag not set: not under IgnoreAll
   *
   * Files/directories under IgnoreAll are noticed as missing already
   * during the file check.
   */
  if (((!SH_FFLAG_VISITED_SET(p->fflags)) || SH_FFLAG_CHECKED_SET(p->fflags)) 
      && (!SH_FFLAG_REPORTED_SET(p->fflags))
      && (!SH_FFLAG_ALLIGNORE_SET(p->fflags)))
    {
      i = retry_lstat(FIL__, __LINE__, p->fullpath, &buf);

      /* if file does not exist
       */
      if (0 != i)
	{
	  ptr = sh_util_dirname (p->fullpath);
	  if (ptr)
	    {
	      /* If any of the parent directories is under IgnoreAll
	       */
	      if (0 != sh_files_is_allignore(ptr))
		level = ShDFLevel[SH_LEVEL_ALLIGNORE];
	      SH_FREE(ptr);
	    }

	  /* Only report if !SH_FFLAG_CHECKED_SET
	   */
	  if (!SH_FFLAG_CHECKED_SET(p->fflags))
	    {
	      if (S_FALSE == sh_ignore_chk_del(p->fullpath))
		{
		  tmp = sh_util_safe_name(p->fullpath);

		  theFile = sh_hash_create_ft (p, fileHash);
		  str = all_items(theFile, fileHash, 0);
		  sh_error_handle (level, FIL__, __LINE__, 0, 
				   MSG_FI_MISS2, tmp, str);
		  SH_FREE(str);
		  if (theFile->attr_string) SH_FREE(theFile->attr_string);
		  if (theFile->link_path)   SH_FREE(theFile->link_path);
		  SH_FREE(theFile);

		  SH_FREE(tmp);
		}
	    }

	  /* We rewrite the db on update, thus we need to keep this
	   * if the user does not want to purge it from the db.
	   */

	  if ((sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE) || 
	      (S_TRUE == sh.flag.update && S_TRUE == sh_util_ask_update(p->fullpath)))
	    {
#ifdef REPLACE_OLD
	      /* Remove the old entry
	       */
	      if (prev == p)
		tab[j] = p->next;
	      else
		prev->next = p->next;
	      if (p->fullpath)
		{
		  SH_FREE(p->fullpath);
		  p->fullpath = NULL;
		}
	      if (p->linkpath)
		{
		  if (p->linkpath != notalink)
		    SH_FREE(p->linkpath);
		  p->linkpath = NULL;
		}
	      if (p->attr_string)
		{
		  SH_FREE(p->attr_string);
		  p->attr_string = NULL;
		}
	      SH_FREE(p);
	      p = NULL;
	      SL_RET0(_("hash_unvisited"));
#else
	      SET_SH_FFLAG_REPORTED(p->fflags); 
#endif
	    }
	}
    }

  else if (SH_FFLAG_VISITED_SET(p->fflags) && SH_FFLAG_REPORTED_SET(p->fflags) 
	   && (!SH_FFLAG_ALLIGNORE_SET(p->fflags)))
    {
      if (S_FALSE == sh_ignore_chk_new(p->fullpath))
	{
	  tmp = sh_util_safe_name(p->fullpath);

	  theFile = sh_hash_create_ft (p, fileHash);
	  str = all_items(theFile, fileHash, 0);
	  sh_error_handle (level, FIL__, __LINE__, 0, 
			   MSG_FI_MISS2, tmp, str);
	  SH_FREE(str);
	  if (theFile->attr_string)
	    SH_FREE(theFile->attr_string);
	  SH_FREE(theFile);

	  SH_FREE(tmp);
	}

      CLEAR_SH_FFLAG_REPORTED(p->fflags);
    }

  if (sh.flag.reportonce == S_FALSE)
    CLEAR_SH_FFLAG_REPORTED(p->fflags);

  CLEAR_SH_FFLAG_VISITED(p->fflags);
  CLEAR_SH_FFLAG_CHECKED(p->fflags);

  SL_RET0(_("hash_unvisited"));
}


/*********************************************************************
 *
 * Search for files in the database that have been deleted from disk.
 *
 *********************************************************************/
void sh_hash_unvisited (ShErrLevel level)
{
  int i;

  SL_ENTER(_("sh_hash_unvisited"));

  SH_MUTEX_LOCK(mutex_hash);
  for (i = 0; i < TABSIZE; ++i)
    {
      if (tab[i] != NULL) 
	hash_unvisited (i, tab[i], tab[i], level);
    }
  SH_MUTEX_UNLOCK(mutex_hash);

  SL_RET0(_("hash_unvisited"));
}


/**********************************************************************
 *
 * delete hash array
 *
 **********************************************************************/
static void hash_kill (sh_file_t *p)
{
  SL_ENTER(_("hash_kill"));

  if (p == NULL)
    SL_RET0(_("hash_kill"));

  if (p->next != NULL)
    hash_kill (p->next);

  if (p->fullpath)
    {
      SH_FREE(p->fullpath);
      p->fullpath = NULL;
    }
  if (p->linkpath)
    {
      if (p->linkpath != notalink)
	SH_FREE(p->linkpath);
      p->linkpath = NULL;
    }
  if (p->attr_string)
    {
      SH_FREE(p->attr_string);
      p->attr_string = NULL;
    }
  SH_FREE(p);
  p = NULL;
  SL_RET0(_("hash_kill"));
}


/***********************************************************************
 *
 * get info out of hash array
 *
 ***********************************************************************/
static sh_file_t * hashsearch (char * s) 
{
  sh_file_t * p;

  SL_ENTER(_("hashsearch"));

  if (s)
    {
      for (p = tab[hashfunc(s)]; p; p = p->next)
	if ((p->fullpath != NULL) && (0 == strcmp(s, p->fullpath))) 
	  SL_RETURN( p, _("hashsearch"));
    } 
  SL_RETURN( NULL, _("hashsearch"));
} 


/***********************************************************************
 *
 * insert into hash array
 *
 ***********************************************************************/
static void hashinsert (sh_file_t * s) 
{
  sh_file_t * p;
  sh_file_t * q;
  int key;

  SL_ENTER(_("hashinsert"));

  key = hashfunc(s->fullpath);

  if (tab[key] == NULL) 
    {
      tab[key] = s;
      tab[key]->next = NULL;
      SL_RET0(_("hashinsert"));
    } 
  else 
    {
      p = tab[key];
      while (1) 
	{
	  if (p && p->fullpath && 
	      0 == strcmp(s->fullpath, p->fullpath))
	    {
	      q = p->next;
	      SH_FREE(p->fullpath);
	      if(p->linkpath && p->linkpath != notalink)
		SH_FREE(p->linkpath);
	      if(p->attr_string)
		SH_FREE(p->attr_string);
	      memcpy(p, s, sizeof(sh_file_t));
	      p->next = q;
	      SH_FREE(s);
	      s = NULL;
	      SL_RET0(_("hashinsert"));
	    }
	  else 
	    if (p->next == NULL) 
	      {
		p->next = s;
		p->next->next = NULL;
		SL_RET0(_("hashinsert"));
	      }
	  p = p->next;
	}
    }
  /* notreached */
}


/******************************************************************
 *
 * Get a single line
 *
 ******************************************************************/
static FILE * sh_fin_fd = NULL;

static int sh_hash_getline (FILE * fd, char * line, int sizeofline)
{
  register int  n = 0;
  char        * res;

  if (sizeofline < 2) {
    if (sizeofline > 0) line[0] = '\0';
    return 0;
  }
  res = fgets(line, sizeofline, fd);
  if (res == NULL)
    {
      line[0] = '\0';
      return -1;
    }
  n = strlen(line);
  if (n > 0) {
    --n;
    line[n] = '\0'; /* remove terminating '\n' */
  }
  return n;
}

static void sh_hash_getline_end (void)
{
  sl_fclose (FIL__, __LINE__, sh_fin_fd);
  sh_fin_fd = NULL;
  return;
}

/******************************************************************
 *
 * ------- Check functions -------
 *
 ******************************************************************/

static int IsInit = 0;


/******************************************************************
 *
 * Fast forward to start of data
 *
 ******************************************************************/
int sh_hash_setdataent (SL_TICKET fd, char * line, int size, const char * file)
{
  long i;
  extern int get_the_fd (SL_TICKET ticket);

  SL_ENTER(_("sh_hash_setdataent"));

  sl_rewind (fd);

  if (sh_fin_fd != NULL)
    {
      sl_fclose (FIL__, __LINE__, sh_fin_fd);
      sh_fin_fd = NULL;
    }

  sh_fin_fd = fdopen(dup(get_the_fd(fd)), "rb");
  if (!sh_fin_fd)
    {
      dlog(1, FIL__, __LINE__, 
	   _("The file signature database: %s is not readable.\n"),
	   (NULL == file) ? _("(null)") : file);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_P_NODATA,
		       ( (NULL == file) ? _("(null)") : file)
		       );
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
    }

  while (1) 
    {
      i =  sh_hash_getline (sh_fin_fd, line, size);
      if (i < 0 ) 
	{
	  SH_FREE(line);
	  dlog(1, FIL__, __LINE__, 
	       _("The file signature database: %s does not\ncontain any data, or the start-of-file marker is missing (unlikely,\nunless modified by hand).\n"),
	       (NULL == file) ? _("(null)") : file);
	       
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_P_NODATA,
			   ( (NULL == file) ? _("(null)") : file)
			   );
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}

#if defined(SH_STEALTH)
      if (0 == sl_strncmp (line, N_("[SOF]"), 5)) 
#else
      if (0 == sl_strncmp (line, _("[SOF]"),  5)) 
#endif
	break;
    }
  SL_RETURN( 1, _("sh_hash_setdataent"));
}

static int sh_hash_setdataent_old (SL_TICKET fd, char * line, int size, 
				   char * file)
{
  long i;

  SL_ENTER(_("sh_hash_setdataent_old"));

  sl_rewind (fd);

  while (1) 
    {
      i =  sh_unix_getline (fd, line, size-1);
      if (i < 0 ) 
	{
	  SH_FREE(line);
	  dlog(1, FIL__, __LINE__, 
	       _("The file signature database: %s does not\ncontain any data, or the start-of-file marker is missing (unlikely,\nunless modified by hand).\n"),
	       (NULL == file) ? _("(null)") : file);
	       
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_P_NODATA,
			   ( (NULL == file) ? _("(null)") : file)
			   );
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}

#if defined(SH_STEALTH)
      if (0 == sl_strncmp (line, N_("[SOF]"), 5)) 
#else
      if (0 == sl_strncmp (line, _("[SOF]"),  5)) 
#endif
	break;
    }
  SL_RETURN( 1, _("sh_hash_setdataent_old"));
}

/******************************************************************
 *
 * Read next record
 *
 ******************************************************************/
sh_file_t *  sh_hash_getdataent (SL_TICKET fd, char * line, int size)
{
  sh_file_t * p;
  sh_filestore_t ft;
  long i;
  size_t len;
  char * fullpath;
  char * linkpath;
  char * attr_string = NULL;
  char * tmp;

  SL_ENTER(_("sh_hash_getdataent"));

  (void) fd;

  /* Read next record -- Part One 
   */
  p = SH_ALLOC(sizeof(sh_file_t));

  i = fread (&ft, sizeof(sh_filestore_t), 1, sh_fin_fd);
  /* i = sl_read(fd, &ft, sizeof(sh_filestore_t)); */
  /* if ( SL_ISERROR(i) || i == 0) */
  if (i < 1)
    {
      SH_FREE(p);
      SL_RETURN( NULL, _("sh_hash_getdataent"));
    }

  swap_32(&(ft.mode));
  swap_32(&(ft.linkmode));
  swap_64(&(ft.dev));
  swap_64(&(ft.rdev));
  swap_32(&(ft.hardlinks));
  swap_32(&(ft.ino));
  swap_64(&(ft.size));
  swap_64(&(ft.atime));
  swap_64(&(ft.mtime));
  swap_64(&(ft.ctime));
  swap_32(&(ft.owner));
  swap_32(&(ft.group));
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  swap_32(&(ft.attributes));
#endif
#ifdef OLD_BUG
  swap_short(&(ft.mark));
#else
  ft.mark = *(swap_short(&(ft.mark)));
#endif

  if ((ft.mark & ~REC_FLAGS_MASK) != REC_MAGIC)
    {
      SH_FREE(p);
      SL_RETURN( NULL, _("sh_hash_getdataent"));
    }

  /* Read next record -- Part Two -- Fullpath
   */
  i =  sh_hash_getline (sh_fin_fd, line, size);
  if (i <= 0 ) 
    {
      SH_FREE(line);
      SH_FREE(p);
      dlog(1, FIL__, __LINE__, 
	   _("There is a corrupt record in the file signature database: %s\nThe file path is missing.\n"),
	   (NULL == file_path('D', 'R'))? _("(null)"):file_path('D', 'R'));
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_P_NODATA,
			   ( (NULL == file_path('D', 'R')) ? _("(null)") :
			     file_path('D', 'R'))
			    );
      aud_exit (FIL__, __LINE__,EXIT_FAILURE);
    }

  tmp = unquote_string (line, i);
  len = sl_strlen(tmp)+1;
  fullpath = SH_ALLOC(len);
  (void) sl_strlcpy (fullpath, tmp, len);
  if (tmp)
    SH_FREE(tmp);
  if (fullpath[len-2] == '\n')
    fullpath[len-2] = '\0';

  /* Read next record -- Part Three -- Linkpath
   */
  i =  sh_hash_getline (sh_fin_fd, line, size);
  if (i <= 0 ) 
    {
      SH_FREE(line);
      SH_FREE(fullpath);
      SH_FREE(p);
      dlog(1, FIL__, __LINE__, 
	   _("There is a corrupt record in the file signature database: %s\nThe link path (or its placeholder) is missing.\n"),
	   (NULL == file_path('D', 'R'))? _("(null)"):file_path('D', 'R'));
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_P_NODATA,
		       ( (NULL == file_path('D', 'R')) ? _("(null)") :
			 file_path('D', 'R'))
		       );
      aud_exit (FIL__, __LINE__,EXIT_FAILURE);
    }

  tmp = unquote_string (line, i);

  if ( tmp && tmp[0] == '-' && 
       (tmp[1] == '\0' || (tmp[1] == '\n' && tmp[2] == '\0')))
    {
      linkpath = (char *)notalink;
    }
  else
    {
      len = sl_strlen(tmp);
      linkpath = sh_util_strdup_l(tmp, len);
      if (len > 0 && linkpath[len-1] == '\n')
	linkpath[len-1] = '\0';
    }

  if (tmp)
    SH_FREE(tmp);

  /* Read next record -- Part Four -- attr_string
   */
  if ((ft.mark & REC_FLAGS_ATTR) != 0)
    {
      i =  sh_hash_getline (sh_fin_fd, line, size);
      if (i <= 0 ) 
	{
	  SH_FREE(line);
	  SH_FREE(fullpath);
	  if (linkpath != notalink)
	    SH_FREE(linkpath);
	  SH_FREE(p);
	  dlog(1, FIL__, __LINE__, 
	       _("There is a corrupt record in the file signature database: %s\nThe attribute string is missing.\n"),
	       (NULL == file_path('D', 'R'))? _("(null)"):file_path('D', 'R'));
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_P_NODATA,
			   ( (NULL == file_path('D', 'R')) ? _("(null)") :
			     file_path('D', 'R'))
			   );
	  aud_exit (FIL__, __LINE__,EXIT_FAILURE);
	}

      tmp = unquote_string (line, i);

      len = sl_strlen(tmp)+1;
      attr_string = SH_ALLOC(len);
      (void) sl_strlcpy (attr_string, tmp, len);
      if (tmp)
	SH_FREE(tmp);
      if (attr_string[len-2] == '\n')
	attr_string[len-2] = '\0';
    }

  /* Read next record -- Part Four -- Decode
   */
#if defined(SH_STEALTH)
  sh_do_decode(fullpath,    sl_strlen(fullpath));
  
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  sh_do_decode(ft.c_attributes,   sl_strlen(ft.c_attributes));
#endif
  
  sh_do_decode(ft.c_mode,   sl_strlen(ft.c_mode));
  sh_do_decode(ft.c_owner,  sl_strlen(ft.c_owner));
  sh_do_decode(ft.c_group,  sl_strlen(ft.c_group));
  sh_do_decode(ft.checksum, sl_strlen(ft.checksum));
  
  
  if (ft.c_mode[0] == 'l' && linkpath != notalink)
    {  
      sh_do_decode(linkpath, sl_strlen(linkpath));
    }
  if ((ft.mark & REC_FLAGS_ATTR) != 0)
    {  
      sh_do_decode(attr_string, sl_strlen(attr_string));
    }
#endif

  memcpy( &(*p).theFile, &ft, sizeof(sh_filestore_t) );

  /* init fflags, such that suid files in 
   * database are recognized as such 
   */
  {
    mode_t mode = (mode_t) ft.mode;

    if (S_ISREG(mode) &&
	(0 !=(S_ISUID & mode) ||
#if defined(HOST_IS_LINUX)
	 (0 !=(S_ISGID & mode) && 
	  0 !=(S_IXGRP & mode)) 
#else  
	 0 !=(S_ISGID & mode)
#endif
	 )
	)
      p->fflags = SH_FFLAG_SUIDCHK;

    else
      p->fflags = 0;
  }
      
  p->modi_mask = 0L;
  p->fullpath  = fullpath;
  p->linkpath  = linkpath;

  p->attr_string = attr_string;

  /* set to an invalid value 
   */
  ft.mark = (REC_MAGIC + 5);

  SL_RETURN( p, _("sh_hash_getdataent"));
}

/******************************************************************
 *
 * Initialize
 *
 ******************************************************************/
void sh_hash_init ()
{

#define FGETS_BUF 16384

  sh_file_t * p;
  SL_TICKET fd;
  long i;
  int count = 0;
  char * line = NULL;

#if defined(WITH_GPG) || defined(WITH_PGP)
  extern int get_the_fd (SL_TICKET ticket);
  FILE *   fin_cp = NULL;

  char * buf  = NULL;
  int    bufc;
  int    flag_pgp;
  int    flag_nohead;
  SL_TICKET fdTmp = (-1);
  SL_TICKET open_tmp (void);
#endif
  char hashbuf[KEYBUF_SIZE];

  volatile int  retval  = 0;
  volatile int  exitval = EXIT_SUCCESS;

  SL_ENTER(_("sh_hash_init"));

  SH_MUTEX_LOCK(mutex_hash);

#if defined(WITH_GPG) || defined(WITH_PGP)
  flag_pgp = S_FALSE;
  flag_nohead = S_FALSE;
#endif

  if (IsInit == 1)
    { 
      goto unlock_and_return;
    }

  fd = (-1);

#if defined(SH_WITH_CLIENT)

  /* Data file from Server
   */

  if (fd == (-1) && 0 == sl_strcmp(file_path('D', 'R'), _("REQ_FROM_SERVER")))
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_D_DSTART);
      fd = sh_forward_req_file(_("DATA"));
      if (SL_ISERROR(fd))
	{
	  dlog(1, FIL__, __LINE__, 
	       _("Could not retrieve the file signature database from the server(errnum = %ld).\nPossible reasons include:\n - the server is not running,\n - session key negotiation failed (see the manual for proper setup), or\n - the server cannot access the file.\n"), fd); 
	  sh_error_handle ((-1), FIL__, __LINE__, fd, MSG_EXIT_ABORT1, 
			   sh.prg_name);
	  retval = 1; exitval = EXIT_FAILURE;
	  goto unlock_and_return;
	}
      sl_rewind (fd);

      sl_strlcpy (sh.data.hash, 
		  sh_tiger_hash (file_path('C', 'R'),  
				 fd, TIGER_NOLIM, hashbuf, sizeof(hashbuf)),
		  KEY_LEN+1);
      sl_rewind (fd);
    }
  else 
#endif
    /* Local data file
     */

    if (fd == (-1))
      {
	if ( SL_ISERROR(fd = sl_open_read(FIL__, __LINE__, 
					  file_path('D', 'R'), SL_YESPRIV))) 
	  {
	    TPT(( 0, FIL__, __LINE__, _("msg=<Error opening: %s>\n"), 
		  file_path('D', 'R')));
	    dlog(1, FIL__, __LINE__, 
		 _("Could not open the local file signature database for reading because\nof the following error: %s (errnum = %ld)\nIf this is a permission problem, you need to change file permissions\nto make the file readable for the effective UID: %d\n"), 
		 sl_get_errmsg(), fd, (int) sl_ret_euid());
	    sh_error_handle ((-1), FIL__, __LINE__, fd, MSG_EXIT_ABORT1, 
			     sh.prg_name);
	    retval = 1; exitval = EXIT_FAILURE;
	    goto unlock_and_return;
	  }
	
	TPT(( 0, FIL__, __LINE__, _("msg=<Opened database: %s>\n"), 
	      file_path('D', 'R')));

	if (0 != sl_strncmp(sh.data.hash, 
			    sh_tiger_hash (file_path('D', 'R'), fd, TIGER_NOLIM, 
					   hashbuf, sizeof(hashbuf)),
			    KEY_LEN)
	    && sh.flag.checkSum != SH_CHECK_INIT) 
	  {
	    dlog(1, FIL__, __LINE__, 
		 _("The checksum of the file signature database has changed since startup: %s -> %s\n"),
		 sh.data.hash, sh_tiger_hash (file_path('D', 'R'), fd, TIGER_NOLIM, 
					   hashbuf, sizeof(hashbuf)));
	    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_AUTH,
			     ( (NULL == file_path('D', 'R')) ? _("(null)") :
			       file_path('D', 'R') )
			     );
	    retval = 1; exitval = EXIT_FAILURE;
	    goto unlock_and_return;
	  }
	sl_rewind (fd);

      } /* new 1.4.8 */

  if (sig_termfast == 1)  /* SIGTERM */
    {
      TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
      --sig_raised; --sig_urgent;
      retval = 1; exitval = EXIT_SUCCESS;
      goto unlock_and_return;
    }

#if defined(WITH_GPG) || defined(WITH_PGP)
  /* new 1.4.8: also checked for server data */

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

      if (sig_termfast == 1)  /* SIGTERM */
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
	  --sig_raised; --sig_urgent;
	  retval = 1; exitval = EXIT_SUCCESS;
	  goto unlock_and_return;
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
  sl_close(fd);
  sl_fclose(FIL__, __LINE__, fin_cp); /* fin_cp = fdopen(dup(), "rb"); */

  fd = fdTmp;
  sl_rewind (fd);

  /* Validate signature of open file.
   */
  if (0 != sh_gpg_check_sign (0, fd, 2))
    {
      retval = 1; exitval = EXIT_FAILURE;
      goto unlock_and_return;
    }
  sl_rewind (fd);
#endif
  /* } new 1.4.8 check sig also for files downloaded from server */

  line = SH_ALLOC(MAX_PATH_STORE+2);

  /* fast forward to start of data
   */
  sh_hash_setdataent(fd, line, MAX_PATH_STORE+1, file_path('D', 'R'));

  for (i = 0; i < TABSIZE; ++i) 
    tab[i] = NULL;

  while (1) 
    {
      if (sig_termfast == 1)  /* SIGTERM */
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
	  --sig_raised; --sig_urgent;
	  retval = 1; exitval = EXIT_SUCCESS;
	  SH_FREE(line);
	  line = NULL;
	  goto unlock_and_return;
	}

      p = sh_hash_getdataent (fd, line, MAX_PATH_STORE+1);
      if (p != NULL)
	{
	  hashinsert (p); 
	  ++count;
	}
      else
	break;
    }

  /* Initialization completed.
   */
  IsInit = 1;

  if (line != NULL)
    SH_FREE(line);

  /* Always keep db in memory, so we have no open file
   */
  sl_close (fd);
  sh_hash_getline_end();
  fd = -1;

 unlock_and_return:
  ; /* 'label at end of compound statement */
  SH_MUTEX_UNLOCK(mutex_hash);
  if (retval == 0)
    {
      SL_RET0(_("sh_hash_init"));
    }
  aud_exit (FIL__, __LINE__, exitval);
}
  
/*****************************************************************
 *
 * delete hash array
 *
 *****************************************************************/
void sh_hash_hashdelete ()
{
  int i;

  SL_ENTER(_("sh_hash_hashdelete"));
  SH_MUTEX_LOCK(mutex_hash);

  if (IsInit == 0) 
    goto unlock_and_exit;

  for (i = 0; i < TABSIZE; ++i) 
    if (tab[i] != NULL)
      { 
	hash_kill (tab[i]);
	tab[i] = NULL;
      }
  IsInit = 0;

 unlock_and_exit:
  ; /* 'label at end of compound statement */
  SH_MUTEX_UNLOCK(mutex_hash);
  SL_RET0(_("sh_hash_hashdelete"));
}

/******************************************************************
 *
 * Insert a file into the database.
 *
 ******************************************************************/ 
static int       pushdata_isfirst =  1;
static SL_TICKET pushdata_fd      = -1;

static int       pushdata_stdout  =  S_FALSE;

static char * sh_db_version_string = NULL;

int sh_hash_pushdata_stdout (const char * str)
{
  if (!str)
    { pushdata_stdout  =  S_TRUE; return 0; }
  return -1;
}

int sh_hash_version_string(const char * str)
{
  if (str)
    {
      if (sh_db_version_string != NULL) {
	SH_FREE(sh_db_version_string);
      }
      if (0 == sl_strncmp(str, _("NULL"), 4))
	{
	  sh_db_version_string = NULL;
	  return 0;
	}
      sh_db_version_string = sh_util_strdup(str);
      return 0;
    }
  return -1;
}

static int sh_loosedircheck = S_FALSE;

int sh_hash_loosedircheck(const char * str)
{
  return sh_util_flagval(str, &sh_loosedircheck);
}


static void sh_hash_pushdata_int (file_type * buf, char * fileHash)
{
  static long p_count = 0;

  int         status = 0;

  char      * tmp;
  size_t      tmp_len = 0;
  size_t      old_len = 0;
  size_t      path_len = 0;

  sh_filestore_t p;

  struct stat sbuf;

  char *  fullpath = NULL;
  char *  linkpath = NULL;
  char *  attr_string = NULL;

  char * line = NULL;

  char   timestring[81];

#if !defined(__linux__) && !defined(HAVE_STAT_FLAGS)
  int    i;
#endif

  SL_ENTER(_("sh_hash_pushdata_int"));

  fullpath = SH_ALLOC(MAX_PATH_STORE+1);
  linkpath = SH_ALLOC(MAX_PATH_STORE+1);

  linkpath[0] =  '-'; 
  linkpath[1] = '\0'; 
  fullpath[0] =  '-'; 
  fullpath[1] = '\0';

  if (!buf) {
    memset(&p, '\0', sizeof(sh_filestore_t));
  }

  if ((pushdata_stdout == S_TRUE) && (sh.flag.update == S_TRUE))
    {
      dlog(1, FIL__, __LINE__, 
	   _("You cannot write the database to stdout when you use update rather than init.\n"));
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORTS,
		      _("Writing database to stdout with update"), 
		      sh.prg_name, 
		      _("sh_hash_pushdata_int"));
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  if ((pushdata_stdout == S_TRUE) && (sl_is_suid()))
    {
      dlog(1, FIL__, __LINE__, 
	   _("You cannot write the database to stdout when running with suid privileges.\n"));
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORTS,
		      _("Writing database to stdout when suid"), 
		      sh.prg_name, 
		      _("sh_hash_pushdata_int"));
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }


  if ((pushdata_isfirst == 1) && (pushdata_stdout == S_FALSE) && 
      ( (NULL == file_path('D', 'W')) || 
	(0 == sl_strcmp(file_path('D', 'W'), _("REQ_FROM_SERVER"))) ))
    {
      dlog(1, FIL__, __LINE__, 
	   _("You need to configure a local path for initializing the database\nlike ./configure --with-data-file=REQ_FROM_SERVER/some/local/path\n"));
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORTS,
		      _("No local path for database specified"), 
		      sh.prg_name, 
		      _("sh_hash_pushdata_int"));
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }


  if ((pushdata_isfirst == 1) && (pushdata_stdout == S_FALSE))  
    {
      /* Warn that file already exists; file_path != NULL here because
       * checked above
       */
      if (0 == retry_lstat(FIL__, __LINE__, file_path('D', 'W'), &sbuf))
	{
	  if (sh.flag.update == S_FALSE)
	    {
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_FI_DBEX,
			      file_path('D', 'W'));
	    }
	}
    }


  if (sh.flag.update == S_FALSE)
    {
      if (pushdata_stdout == S_FALSE && pushdata_fd == -1)
	{
	  if ( SL_ISERROR(pushdata_fd = sl_open_write(FIL__, __LINE__, 
						      file_path('D', 'W'), 
						      SL_YESPRIV))) 
	    {
	      SH_FREE(fullpath);
	      SH_FREE(linkpath);
	      sh_error_handle((-1), FIL__, __LINE__, pushdata_fd, MSG_E_ACCESS,
			      geteuid(), file_path('D', 'W'));
	      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	    }

	  if (SL_ISERROR(status = sl_lock (pushdata_fd)))
	    {
	      SH_FREE(fullpath);
	      SH_FREE(linkpath);
	      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGPATH,
			      _("Failed to lock baseline database"), _("sh_hash_pushdata_int"),
			      file_path('D', 'W'));
	      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	    }

	  if ( SL_ISERROR(status = sl_forward(pushdata_fd))) 
	    {
	      SH_FREE(fullpath);
	      SH_FREE(linkpath);
	      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGPATH,
			      _("Failed to seek to end of baseline database"),
			      _("sh_hash_pushdata_int"),
			      file_path('D', 'W'));
	      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	    }
	}
    }
  else /* update == TRUE */
    {
      if (pushdata_isfirst == 1)
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Update.>\n")))
	    if ( SL_ISERROR(pushdata_fd = sl_open_rdwr(FIL__, __LINE__, 
						       file_path('D', 'W'), 
						       SL_YESPRIV))){
	      SH_FREE(fullpath);
	      SH_FREE(linkpath);
	      sh_error_handle((-1), FIL__, __LINE__, pushdata_fd, MSG_E_ACCESS,
			      geteuid(), file_path('D', 'W'));
	      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	    }

	  if (SL_ISERROR(status = sl_lock (pushdata_fd)))
	    {
	      SH_FREE(fullpath);
	      SH_FREE(linkpath);
	      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGPATH,
			      _("Failed to lock baseline database"), _("sh_hash_pushdata_int"),
			      file_path('D', 'W'));
	      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	    }

	  line = SH_ALLOC(MAX_PATH_STORE+1);
	  if (SL_ISERROR(sh_hash_setdataent_old (pushdata_fd, line, 
						 MAX_PATH_STORE, 
						 file_path('D', 'W'))))
	    {
	      SH_FREE(fullpath);
	      SH_FREE(linkpath);
	      SH_FREE(line);
	      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
	    }
	  SH_FREE(line);
	}
    }
	 
  if (buf != NULL && buf->fullpath != NULL) {

    old_len = sl_strlen(buf->fullpath);
#if defined(SH_STEALTH)
    sh_do_encode(buf->fullpath, old_len);
#endif
    tmp = quote_string(buf->fullpath, old_len);
    tmp_len = sl_strlen(tmp);
#if defined(SH_STEALTH)
    sh_do_decode(buf->fullpath, old_len);
#endif

    if (tmp && tmp_len <= MAX_PATH_STORE) 
      {
	sl_strlcpy(fullpath, buf->fullpath, MAX_PATH_STORE+1);
      } 
    else 
      {
	char hashbuf[KEYBUF_SIZE];

	sl_strlcpy(fullpath, 
		   sh_tiger_hash (buf->fullpath,
				  TIGER_DATA, old_len, 
				  hashbuf, sizeof(hashbuf)), 
		   KEY_LEN+1);
      }
    if (tmp) SH_FREE(tmp);
  }

  path_len = sl_strlen(fullpath);
#if defined(SH_STEALTH)
  sh_do_encode(fullpath, path_len);
#endif

  tmp = quote_string(fullpath, path_len);
  if (tmp) {
    sl_strlcpy(fullpath, tmp, MAX_PATH_STORE+1);
    SH_FREE(tmp);
  }

  if (buf != NULL /* && buf->c_mode[0] == 'l' */ && buf->link_path != NULL) 
    {  

      old_len = sl_strlen(buf->link_path);
#if defined(SH_STEALTH)
      if (buf->c_mode[0] == 'l')
	sh_do_encode(buf->link_path, old_len);
#endif
      tmp = quote_string(buf->link_path, old_len);
      tmp_len = sl_strlen(tmp);
#if defined(SH_STEALTH)
      if (buf->c_mode[0] == 'l')
	sh_do_decode(buf->link_path, old_len);
#endif

      if (tmp && tmp_len <= MAX_PATH_STORE) 
	{
	  sl_strlcpy(linkpath, buf->link_path, MAX_PATH_STORE+1);  
	} 
      else 
	{
	  char hashbuf[KEYBUF_SIZE];
	  sl_strlcpy(linkpath, 
		     sh_tiger_hash (buf->link_path,
				    TIGER_DATA, old_len,
				    hashbuf, sizeof(hashbuf)),
		     KEY_LEN+1);
	}
      if (tmp) SH_FREE(tmp);

      path_len = sl_strlen(linkpath);
#if defined(SH_STEALTH)
      if (buf->c_mode[0] == 'l')
	sh_do_encode(linkpath, path_len);
#endif
      tmp = quote_string(linkpath, path_len);
      if (tmp)
	{
	  sl_strlcpy(linkpath, tmp, MAX_PATH_STORE+1);
	  SH_FREE(tmp);
	}
    }

  if (buf != NULL && buf->attr_string != NULL) 
    {
      old_len = sl_strlen(buf->attr_string);
#if defined(SH_STEALTH)
      sh_do_encode(buf->attr_string, old_len);
#endif
      tmp = quote_string(buf->attr_string, old_len);
      if (tmp)
	{
	  attr_string = tmp;
	  tmp = NULL;
	}
#if defined(SH_STEALTH)
      sh_do_decode(buf->attr_string, old_len);
#endif
    }


  if (buf != NULL) {
    p.mark = REC_MAGIC;
    if (attr_string)
      p.mark |= REC_FLAGS_ATTR;
    sl_strlcpy(p.c_mode,   buf->c_mode,   CMODE_SIZE);
    sl_strlcpy(p.c_group,  buf->c_group,  GROUP_MAX+1);
    sl_strlcpy(p.c_owner,  buf->c_owner,  USER_MAX+1);
    if (fileHash) {
      sl_strlcpy(p.checksum, fileHash,      KEY_LEN+1);
    }
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
    sl_strlcpy(p.c_attributes, buf->c_attributes, ATTRBUF_SIZE);
#else
    for (i = 0; i < ATTRBUF_USED; ++i) p.c_attributes[i] = '-';
    p.c_attributes[ATTRBUF_USED] = '\0';
#endif
    
#if defined(SH_STEALTH)
    sh_do_encode(p.c_mode,   sl_strlen(p.c_mode));
    sh_do_encode(p.c_owner,  sl_strlen(p.c_owner));
    sh_do_encode(p.c_group,  sl_strlen(p.c_group));
    sh_do_encode(p.checksum, sl_strlen(p.checksum));

    sh_do_encode(p.c_attributes,   sl_strlen(p.c_attributes));
#endif
    
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
    p.attributes  = (UINT32) buf->attributes;
#else
    p.attributes  = 0;
#endif
    p.linkmode    = (UINT32) buf->linkmode;
    p.hardlinks   = (UINT32) buf->hardlinks;
    p.dev   = (UINT64) buf->dev;
    p.rdev  = (UINT64) buf->rdev;
    p.mode  = (UINT32) buf->mode;
    p.ino   = (UINT32) buf->ino;
    p.size  = (UINT64) buf->size;
    p.mtime = (UINT64) buf->mtime;
    p.atime = (UINT64) buf->atime;
    p.ctime = (UINT64) buf->ctime;
    p.owner = (UINT32) buf->owner;
    p.group = (UINT32) buf->group;
    
    swap_32(&(p.mode));
    swap_32(&(p.linkmode));
    swap_64(&(p.dev));
    swap_64(&(p.rdev));
    swap_32(&(p.hardlinks));
    swap_32(&(p.ino));
    swap_64(&(p.size));
    swap_64(&(p.atime));
    swap_64(&(p.mtime));
    swap_64(&(p.ctime));
    swap_32(&(p.owner));
    swap_32(&(p.group));
    swap_32(&(p.attributes));

#ifdef OLD_BUG
    swap_short(&(p.mark));
#else
    p.mark = *(swap_short(&(p.mark)));
#endif
  }

  /* write the start marker 
   */
  if (pushdata_isfirst == 1) 
    {
      if (sh.flag.update == S_FALSE)
	{
	  if (sh_db_version_string != NULL)
	    {
	      if (pushdata_stdout == S_FALSE)
		{
		  sl_write (pushdata_fd, _("\n#Host "), 7);
		  sl_write (pushdata_fd, sh.host.name, 
			    sl_strlen(sh.host.name));
		  sl_write (pushdata_fd, _(" Version "), 9);
		  sl_write (pushdata_fd, sh_db_version_string, 
			    sl_strlen(sh_db_version_string));
		  sl_write (pushdata_fd, _(" Date "), 6);
		  (void) sh_unix_time(0, timestring, sizeof(timestring));
		  sl_write (pushdata_fd, timestring, sl_strlen(timestring));
		  sl_write (pushdata_fd,        "\n", 1);
		} else {
		  printf ("%s",_("\n#Host "));
		  printf ("%s", sh.host.name);
		  printf ("%s",_(" Version "));
		  printf ("%s", sh_db_version_string);
		  printf ("%s",_(" Date "));
		  (void) sh_unix_time(0, timestring, sizeof(timestring));
		  printf ("%s\n", timestring);
		}
	    }

	  if (pushdata_stdout == S_FALSE)
	    {
#if defined(SH_STEALTH)
	      sl_write      (pushdata_fd,        "\n", 1);
	      sl_write_line (pushdata_fd, N_("[SOF]"), 5);
#else
	      sl_write_line (pushdata_fd, _("\n[SOF]"),  6);
#endif
	    }
	  else 
	    {
#if defined(SH_STEALTH)
	      printf ("\n%s\n", N_("[SOF]"));
#else
	      printf ("%s\n", _("\n[SOF]"));
#endif
	    }
	}
      pushdata_isfirst = 0;
    }
      
  if (pushdata_stdout == S_FALSE)
    {
      sl_write      (pushdata_fd,       &p, sizeof(sh_filestore_t));
      sl_write_line_fast (pushdata_fd, fullpath, sl_strlen(fullpath));
      sl_write_line_fast (pushdata_fd, linkpath, sl_strlen(linkpath));
      if (attr_string)
	sl_write_line_fast (pushdata_fd, attr_string, sl_strlen(attr_string));
    } else {
      if (fwrite (&p, sizeof(sh_filestore_t), 1, stdout))
	{
	  printf ("%s\n", fullpath);
	  printf ("%s\n", linkpath);
	  if (attr_string)
	    printf ("%s\n", attr_string);
	}
      else
	{
	  perror(_("Error writing database"));
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}
    }

  ++p_count;

  if ((sh.flag.update != S_TRUE) && (pushdata_stdout == S_FALSE))
    {
      if (sh.flag.checkSum != SH_CHECK_INIT || (buf == NULL && fileHash == NULL))
	{
	  sl_close (pushdata_fd);
	  pushdata_fd = -1;
	}
    }

  SH_FREE(fullpath);
  SH_FREE(linkpath);
  if (attr_string)
    SH_FREE(attr_string);

  SL_RET0(_("sh_hash_pushdata_int"));
}

SH_MUTEX_STATIC(mutex_writeout,PTHREAD_MUTEX_INITIALIZER);

void sh_hash_pushdata (file_type * buf, char * fileHash)
{
  SH_MUTEX_LOCK(mutex_writeout); 
  sh_hash_pushdata_int (buf, fileHash);
  SH_MUTEX_UNLOCK(mutex_writeout); 
  return;
}


int sh_hash_writeout()
{
  sh_file_t * p;
  int         i;
  file_type * f;
  char   fileHash[KEY_LEN + 1];

  SL_ENTER(_("sh_hash_writeout"));

  if (S_TRUE == file_is_remote())
    {
      sh_error_handle((-1), FIL__, __LINE__, S_FALSE, MSG_E_SUBGEN, 
		      _("Baseline database is remote"), _("sh_hash_writeout"));
      SL_RETURN (1, _("sh_hash_writeout"));
    }

  SH_MUTEX_LOCK(mutex_writeout); 
  if (!SL_ISERROR(pushdata_fd))
    {
      sl_close(pushdata_fd);
      pushdata_fd = -1;
    }
  pushdata_isfirst =  1;


  SH_MUTEX_LOCK(mutex_hash);
  for (i = 0; i < TABSIZE; ++i)
    {
      for (p = tab[i]; p; p = p->next)
	{
	  f = sh_hash_create_ft (p, fileHash);
	  sh_hash_pushdata_int (f, fileHash);
	  if (f->attr_string) SH_FREE(f->attr_string);
	  if (f->link_path)   SH_FREE(f->link_path);
	  SH_FREE(f);
	}
    }
  SH_MUTEX_UNLOCK(mutex_hash);

  if (!SL_ISERROR(pushdata_fd))
    {
      sl_close(pushdata_fd);
      pushdata_fd = -1;
    }
  pushdata_isfirst =  1;
  SH_MUTEX_UNLOCK(mutex_writeout); 

  SL_RETURN (0, _("sh_hash_writeout"));
}


/*********************************************************************
 *
 * Check whether a file is present in the database.
 *
 *********************************************************************/
static sh_file_t *  sh_hash_have_it_int (char * newname)
{
  sh_file_t * p;
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_hash_have_it_int"));

  if (newname == NULL)
    SL_RETURN( (NULL), _("sh_hash_have_it_int"));

  if (sl_strlen(newname) <= MAX_PATH_STORE) 
    p = hashsearch(newname);
  else 
    p = hashsearch ( sh_tiger_hash(newname, TIGER_DATA, sl_strlen(newname),
				   hashbuf, sizeof(hashbuf)) );
  if (p == NULL) 
     SL_RETURN( (NULL), _("sh_hash_have_it_int"));

  SL_RETURN( (p), _("sh_hash_have_it_int"));
}

int sh_hash_have_it (char * newname)
{
  sh_file_t * p;
  int retval;

  if (IsInit != 1) 
    sh_hash_init();

  SH_MUTEX_LOCK(mutex_hash);

  retval = 0;

  p = sh_hash_have_it_int (newname);

  if (!p) 
    retval = (-1);
  else if ((!SH_FFLAG_ALLIGNORE_SET(p->fflags)) && 
	   (p->modi_mask & MODI_CHK) != 0 &&
	   (p->modi_mask & MODI_MOD) != 0)
    retval = 1;
  SH_MUTEX_UNLOCK(mutex_hash);

  return retval;
}

int sh_hash_get_it (char * newname, file_type * tmpFile)
{
  sh_file_t * p;
  int retval;

  if (IsInit != 1) 
    sh_hash_init();

  tmpFile->link_path   = NULL;
  tmpFile->attr_string = NULL;

  SH_MUTEX_LOCK(mutex_hash);

  retval = (-1);

  p = sh_hash_have_it_int (newname);
  if (p)
    {
      sl_strlcpy(tmpFile->fullpath,  p->fullpath, PATH_MAX);
      if (p->linkpath)
	tmpFile->link_path = sh_util_strdup (p->linkpath);
      tmpFile->size  = p->theFile.size;
      tmpFile->mtime = p->theFile.mtime;
      tmpFile->ctime = p->theFile.ctime;
      tmpFile->attr_string = NULL;
      retval = 0;
    }
  SH_MUTEX_UNLOCK(mutex_hash);

  return retval;
}

int sh_hash_getflags (char * filename)
{
  sh_file_t * p;
  int retval;

  if (IsInit != 1) 
    sh_hash_init();

  SH_MUTEX_LOCK(mutex_hash);
  p = sh_hash_have_it_int (filename);
  if (p)
    retval = p->fflags;
  else
    retval = -1;
  SH_MUTEX_UNLOCK(mutex_hash);
  return retval;
}

int sh_hash_setflags (char * filename, int flags)
{
  sh_file_t * p;
  int retval;

  if (IsInit != 1) 
    sh_hash_init();

  SH_MUTEX_LOCK(mutex_hash);
  p = sh_hash_have_it_int (filename);
  if (p)
    {
      p->fflags = flags;
      retval = 0;
    }
  else
    retval = -1;
  SH_MUTEX_UNLOCK(mutex_hash);
  return retval;
}

/* needs lock to be threadsafe
 */
void sh_hash_addflag (char * filename, int flag_to_set)
{
  sh_file_t * p;

  if (IsInit != 1) 
    sh_hash_init();

  SH_MUTEX_LOCK(mutex_hash);
  p = sh_hash_have_it_int (filename);
  if (p)
    {
      p->fflags |= flag_to_set;
    }
  SH_MUTEX_UNLOCK(mutex_hash);
  return;
}

/*****************************************************************
 *
 * Set a file's status to 'visited'. This is required for
 * files that should be ignored, and may be present in the
 * database, but not on disk.
 *
 *****************************************************************/
static int sh_hash_set_visited_int (char * newname, int flag)
{
  sh_file_t * p;
  char hashbuf[KEYBUF_SIZE];
  int  retval;

  SL_ENTER(_("sh_hash_set_visited_int"));

  if (newname == NULL)
    SL_RETURN((-1), _("sh_hash_set_visited_int"));

  if (IsInit != 1) 
    sh_hash_init();

  SH_MUTEX_LOCK(mutex_hash);

  if (sl_strlen(newname) <= MAX_PATH_STORE) 
    p = hashsearch(newname);
  else 
    p = hashsearch (sh_tiger_hash(newname, TIGER_DATA, sl_strlen(newname),
				  hashbuf, sizeof(hashbuf)));
  
  if (p)
    {
      if (flag == SH_FFLAG_CHECKED)
	{
	  CLEAR_SH_FFLAG_REPORTED(p->fflags);
	  CLEAR_SH_FFLAG_VISITED(p->fflags);
	  SET_SH_FFLAG_CHECKED(p->fflags);
	}
      else
	{
	  SET_SH_FFLAG_VISITED(p->fflags);
	  CLEAR_SH_FFLAG_CHECKED(p->fflags);
	  if (flag == SH_FFLAG_REPORTED)
	    SET_SH_FFLAG_REPORTED(p->fflags);
	  else
	    CLEAR_SH_FFLAG_REPORTED(p->fflags);
	}
      retval = 0;
    }
  else
    retval = -1;

  SH_MUTEX_UNLOCK(mutex_hash);
  SL_RETURN((retval), _("sh_hash_set_visited_int"));
}


/* cause the record to be deleted without a 'missing' message
 */
int sh_hash_set_missing (char * newname)
{
  int i;
  SL_ENTER(_("sh_hash_set_visited"));
  i = sh_hash_set_visited_int(newname, SH_FFLAG_CHECKED);
  SL_RETURN(i, _("sh_hash_set_visited"));
}

/* mark the file as visited and reported
 */
int sh_hash_set_visited (char * newname)
{
  int i;
  SL_ENTER(_("sh_hash_set_visited"));
  i = sh_hash_set_visited_int(newname, SH_FFLAG_REPORTED);
  SL_RETURN(i, _("sh_hash_set_visited"));
}

/* mark the file as visited and NOT reported
 * used to avoid deletion of file from internal database
 */
int sh_hash_set_visited_true (char * newname)
{
  int i;
  SL_ENTER(_("sh_hash_set_visited_true"));
  i = sh_hash_set_visited_int(newname, 0);
  SL_RETURN(i, _("sh_hash_set_visited_true"));
}


/******************************************************************
 *
 * Data entry for arbitrary data into database
 *
 ******************************************************************/

void sh_hash_push2db (char * key, unsigned long val1, 
		      unsigned long val2, unsigned long val3,
		      unsigned char * str, int size)
{
  int         i = 0;
  char      * p;
  char        i2h[2];
  file_type * tmpFile = SH_ALLOC(sizeof(file_type));

  tmpFile->attr_string = NULL;
  tmpFile->link_path   = NULL;

  sl_strlcpy(tmpFile->fullpath, key, PATH_MAX);
  tmpFile->size  = val1;
  tmpFile->mtime = val2;
  tmpFile->ctime = val3;

  tmpFile->atime = 0;
  tmpFile->mode  = 0;
  tmpFile->owner = 0;
  tmpFile->group = 0;
  sl_strlcpy(tmpFile->c_owner, _("root"), 5);
  sl_strlcpy(tmpFile->c_group, _("root"), 5);

  if ((str != NULL) && (size < (PATH_MAX/2)-1))
    {
      tmpFile->c_mode[0] = 'l';  
      tmpFile->c_mode[1] = 'r'; tmpFile->c_mode[2]  = 'w';
      tmpFile->c_mode[3] = 'x'; tmpFile->c_mode[4]  = 'r'; 
      tmpFile->c_mode[5] = 'w'; tmpFile->c_mode[6]  = 'x'; 
      tmpFile->c_mode[7] = 'r'; tmpFile->c_mode[8]  = 'w'; 
      tmpFile->c_mode[9] = 'x'; tmpFile->c_mode[10] = '\0';
      tmpFile->link_path = SH_ALLOC((size * 2) + 2);
      for (i = 0; i < size; ++i)
	{
	  p = sh_util_charhex (str[i],i2h);
	  tmpFile->link_path[2*i]   = p[0];
	  tmpFile->link_path[2*i+1] = p[1];
	  tmpFile->link_path[2*i+2] = '\0';
	}
    }
  else
    {
      for (i = 0; i < 10; ++i) 
	tmpFile->c_mode[i] = '-';
      tmpFile->c_mode[10] = '\0';
      tmpFile->link_path = sh_util_strdup("-");
    }

  if (sh.flag.checkSum == SH_CHECK_CHECK && 
      sh.flag.update == S_TRUE)
    sh_hash_pushdata_memory (tmpFile, SH_KEY_NULL);
  else
    sh_hash_pushdata (tmpFile, SH_KEY_NULL);

  if (tmpFile->link_path) SH_FREE(tmpFile->link_path);
  SH_FREE(tmpFile);
  return;
}

extern int sh_util_hextobinary (char * binary, char * hex, int bytes);

char * sh_hash_db2pop (char * key, unsigned long * val1, 
		       unsigned long * val2, unsigned long * val3,
		       int * size)
{
  size_t      len;
  char      * p;
  int         i;
  char      * retval = NULL;
  file_type * tmpFile = SH_ALLOC(sizeof(file_type));
  
  *size = 0;

  if (0 == sh_hash_get_it (key, tmpFile))
    {
      *val1 = tmpFile->size;
      *val2 = tmpFile->mtime;
      *val3 = tmpFile->ctime;

      if (tmpFile->link_path && tmpFile->link_path[0] != '-')
	{
	  len = strlen(tmpFile->link_path);

	  p = SH_ALLOC((len/2)+1);
	  i = sh_util_hextobinary (p, tmpFile->link_path, len);

	  if (i == 0)
	    {
	      *size = (len/2);
	      p[*size] = '\0';
	      retval = p;
	    }
	  else
	    {
	      SH_FREE(p);
	      *size = 0;
	    }
	}
      else
	{
	  *size = 0;
	}
    }
  else
    {
      *size = -1;
      *val1 =  0;
      *val2 =  0;
      *val3 =  0;
    }
  if (tmpFile->link_path) SH_FREE(tmpFile->link_path);
  SH_FREE(tmpFile);
  return retval;
}




/******************************************************************
 *
 * Data entry in hash table
 *
 ******************************************************************/
sh_file_t * sh_hash_push_int (file_type * buf, char * fileHash)
{
  sh_file_t    * fp;
  sh_filestore_t p;

  size_t len;
  char * fullpath;
  char * linkpath;
  char * attr_string = NULL;
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_hash_push_int"));

  fp = SH_ALLOC(sizeof(sh_file_t));

  p.mark = REC_MAGIC;
  if (buf->attr_string)
    p.mark |= REC_FLAGS_ATTR;
  sl_strlcpy(p.c_mode,   buf->c_mode,   11);
  sl_strlcpy(p.c_group,  buf->c_group,  GROUP_MAX+1);
  sl_strlcpy(p.c_owner,  buf->c_owner,  USER_MAX+1);
  sl_strlcpy(p.checksum, fileHash,      KEY_LEN+1);
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  sl_strlcpy(p.c_attributes, buf->c_attributes, 13);
#endif

#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  p.attributes  = (UINT32) buf->attributes;
#endif
  p.linkmode    = (UINT32) buf->linkmode;
  p.hardlinks   = (UINT32) buf->hardlinks;
  p.dev   = (UINT64) buf->dev;
  p.rdev  = (UINT64) buf->rdev;
  p.mode  = (UINT32) buf->mode;
  p.ino   = (UINT32) buf->ino;
  p.size  = (UINT64) buf->size;
  p.mtime = (UINT64) buf->mtime;
  p.atime = (UINT64) buf->atime;
  p.ctime = (UINT64) buf->ctime;
  p.owner = (UINT32) buf->owner;
  p.group = (UINT32) buf->group;

  memcpy( &(*fp).theFile, &p, sizeof(sh_filestore_t) );
  fp->fflags    = 0;  /* init fflags */
  fp->modi_mask = 0L;

  if (buf->attr_string)
    attr_string = sh_util_strdup(buf->attr_string);
  fp->attr_string = attr_string;

  len = sl_strlen(buf->fullpath);
  if (len <= MAX_PATH_STORE) 
    {
      fullpath = SH_ALLOC(len+1);
      sl_strlcpy(fullpath, buf->fullpath, len+1);
    } 
  else 
    {
      fullpath = SH_ALLOC(KEY_LEN + 1);
      sl_strlcpy(fullpath, 
		 sh_tiger_hash (buf->fullpath, TIGER_DATA, len,
				hashbuf, sizeof(hashbuf)), 
		 KEY_LEN+1);
    }
  fp->fullpath  = fullpath;

  if (buf->link_path)
    {  
      len = sl_strlen(buf->link_path);
      if (len <= MAX_PATH_STORE) 
	{
	  linkpath = SH_ALLOC(len+1);
	  sl_strlcpy(linkpath, buf->link_path, len+1);
	} 
      else 
	{
	  linkpath = SH_ALLOC(KEY_LEN + 1);
	  sl_strlcpy(linkpath, 
		     sh_tiger_hash (buf->link_path, TIGER_DATA, len,
				    hashbuf, sizeof(hashbuf)), 
		     KEY_LEN+1);
	}
      fp->linkpath  = linkpath;
    }
  else
    fp->linkpath  = NULL;

  SL_RETURN( fp, _("sh_hash_push_int"));
}

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

#ifndef PRIu64
#ifdef  HAVE_LONG_32
#define PRIu64 "llu"
#else
#define PRIu64 "lu"
#endif
#endif

char * sh_hash_size_format()
{
  static char form_rval[81];

  SL_ENTER(_("sh_hash_size_format"));


#ifdef SH_USE_XML
  sl_snprintf(form_rval, 80, _("%s%s%s%s%s"), 
	      _("size_old=\"%"), PRIu64, _("\" size_new=\"%"), PRIu64, "\" ");
#else
  sl_snprintf(form_rval, 80, _("%s%s%s%s%s"), 
	      _("size_old=<%"), PRIu64, _(">, size_new=<%"), PRIu64, ">, ");
#endif

  SL_RETURN( form_rval, _("sh_hash_size_format"));
}


#ifdef SH_USE_XML
static char * all_items (file_type * theFile, char * fileHash, int is_new)
{
  char timstr1c[32];
  char timstr1a[32];
  char timstr1m[32];

  char * tmp_lnk;
  char * format;

  char * tmp = SH_ALLOC(SH_MSG_BUF);
  char * msg = SH_ALLOC(SH_MSG_BUF);

  tmp[0] = '\0';
  msg[0] = '\0';


#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  if (is_new)
    format = _("mode_new=\"%s\" attr_new=\"%s\" imode_new=\"%ld\" iattr_new=\"%ld\" ");
  else 
    format = _("mode_old=\"%s\" attr_old=\"%s\" imode_old=\"%ld\" iattr_old=\"%ld\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_mode,
	      theFile->c_attributes,
	      (long) theFile->mode,
	      (long) theFile->attributes
	      );
#else
  if (is_new)
    format = _("mode_new=\"%s\" imode_new=\"%ld\" ");
  else
    format = _("mode_old=\"%s\" imode_old=\"%ld\" ");

  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_mode,
	      (long) theFile->mode
	      );
#endif
  sl_strlcat(msg, tmp, SH_MSG_BUF);

  if (is_new)
    format = _("hardlinks_new=\"%lu\" ");
  else
    format = _("hardlinks_old=\"%lu\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      (unsigned long) theFile->hardlinks);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("idevice_new=\"%lu\" ");
  else
    format = _("idevice_old=\"%lu\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format, (unsigned long) theFile->rdev);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("inode_new=\"%lu\" ");
  else
    format = _("inode_old=\"%lu\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format, (unsigned long) theFile->ino);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  /* 
   * also report device for prelude
   */
#if defined(HAVE_LIBPRELUDE)
  if (is_new)
    format = _("dev_new=\"%lu,%lu\" ");
  else
    format = _("dev_old=\"%lu,%lu\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,		      
	      (unsigned long) major(theFile->dev),
	      (unsigned long) minor(theFile->dev));
  sl_strlcat(msg, tmp, SH_MSG_BUF);
#endif


  if (is_new)
    format = _("owner_new=\"%s\" iowner_new=\"%ld\" ");
  else
    format = _("owner_old=\"%s\" iowner_old=\"%ld\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_owner, (long) theFile->owner);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("group_new=\"%s\" igroup_new=\"%ld\" ");
  else
    format = _("group_old=\"%s\" igroup_old=\"%ld\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_group, (long) theFile->group);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		(UINT64) 0, (UINT64) theFile->size);
  else
    sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		(UINT64) theFile->size, (UINT64) 0);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  (void) sh_unix_gmttime (theFile->ctime, timstr1c,  sizeof(timstr1c));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("ctime_new=\"%s\" "), timstr1c);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("ctime_old=\"%s\" "), timstr1c);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  (void) sh_unix_gmttime (theFile->atime, timstr1a,  sizeof(timstr1a));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("atime_new=\"%s\" "), timstr1a);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("atime_old=\"%s\" "), timstr1a);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  (void) sh_unix_gmttime (theFile->mtime, timstr1m,  sizeof(timstr1m));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("mtime_new=\"%s\" "), timstr1m);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("mtime_old=\"%s\" "), timstr1m);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("chksum_new=\"%s\" "), fileHash);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("chksum_old=\"%s\" "), fileHash);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  if (theFile->c_mode[0] == 'l' || 
      (theFile->link_path != NULL && theFile->link_path[0] != '-'))
    {
      tmp_lnk     = sh_util_safe_name(theFile->link_path);
      if (tmp_lnk)
	{
	  if (is_new)
	    sl_snprintf(tmp, SH_MSG_BUF, _("link_new=\"%s\" "), tmp_lnk);
	  else
	    sl_snprintf(tmp, SH_MSG_BUF, _("link_old=\"%s\" "), tmp_lnk);
	  SH_FREE(tmp_lnk);
	  sl_strlcat(msg, tmp, SH_MSG_BUF);
	} 
    }

  if (theFile->attr_string)
    {
      tmp_lnk     = sh_util_safe_name(theFile->attr_string);
      if (tmp_lnk)
	{
	  if (is_new)
	    sl_snprintf(tmp, SH_MSG_BUF, _("acl_new=\"%s\" "), tmp_lnk);
	  else
	    sl_snprintf(tmp, SH_MSG_BUF, _("acl_old=\"%s\" "), tmp_lnk);
	  SH_FREE(tmp_lnk);
	  sl_strlcat(msg, tmp, SH_MSG_BUF);
	} 
    }

  
  SH_FREE(tmp);
  return (msg);
}
#else
static char * all_items (file_type * theFile, char * fileHash, int is_new)
{
  char timstr1c[32];
  char timstr1a[32];
  char timstr1m[32];

  char * tmp_lnk;
  char * format;

  char * tmp = SH_ALLOC(SH_MSG_BUF);
  char * msg = SH_ALLOC(SH_MSG_BUF);

  tmp[0] = '\0';
  msg[0] = '\0';


#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  if (is_new)
    format = _("mode_new=<%s>, attr_new=<%s>, imode_new=<%ld>, iattr_new=<%ld>, ");
  else 
    format = _("mode_old=<%s>, attr_old=<%s>, imode_old=<%ld>, iattr_old=<%ld>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_mode,
	      theFile->c_attributes,
	      (long) theFile->mode,
	      (long) theFile->attributes
	      );
#else
  if (is_new)
    format = _("mode_new=<%s>, imode_new=<%ld>, ");
  else
    format = _("mode_old=<%s>, imode_old=<%ld>, ");

  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_mode,
	      (long) theFile->mode
	      );
#endif
  sl_strlcat(msg, tmp, SH_MSG_BUF);

  if (is_new)
    format = _("hardlinks_new=<%lu>, ");
  else
    format = _("hardlinks_old=<%lu>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      (unsigned long) theFile->hardlinks);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("idevice_new=<%lu>, ");
  else
    format = _("idevice_old=<%lu>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format, (unsigned long) theFile->rdev);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("inode_new=<%lu>, ");
  else
    format = _("inode_old=<%lu>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format, (unsigned long) theFile->ino);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  /* 
   * also report device for prelude
   */
#if defined(HAVE_LIBPRELUDE)
  if (is_new)
    format = _("dev_new=<%lu,%lu>, ");
  else
    format = _("dev_old=<%lu,%lu>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,		      
	      (unsigned long) major(theFile->dev),
	      (unsigned long) minor(theFile->dev));
  sl_strlcat(msg, tmp, SH_MSG_BUF);
#endif

  if (is_new)
    format = _("owner_new=<%s>, iowner_new=<%ld>, ");
  else
    format = _("owner_old=<%s>, iowner_old=<%ld>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_owner, (long) theFile->owner);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("group_new=<%s>, igroup_new=<%ld>, ");
  else
    format = _("group_old=<%s>, igroup_old=<%ld>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_group, (long) theFile->group);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		(UINT64) 0, (UINT64) theFile->size);
  else
    sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		(UINT64) theFile->size, (UINT64) 0);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  (void) sh_unix_gmttime (theFile->ctime, timstr1c,  sizeof(timstr1c));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("ctime_new=<%s>, "), timstr1c);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("ctime_old=<%s>, "), timstr1c);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  (void) sh_unix_gmttime (theFile->atime, timstr1a,  sizeof(timstr1a));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("atime_new=<%s>, "), timstr1a);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("atime_old=<%s>, "), timstr1a);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  (void) sh_unix_gmttime (theFile->mtime, timstr1m,  sizeof(timstr1m));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("mtime_new=<%s>, "), timstr1m);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("mtime_old=<%s>, "), timstr1m);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("chksum_new=<%s>"), fileHash);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("chksum_old=<%s>"), fileHash);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  if (theFile->c_mode[0] == 'l' || 
      (theFile->link_path != NULL && theFile->link_path[0] != '-'))
    {
      tmp_lnk     = sh_util_safe_name(theFile->link_path);
      if (tmp_lnk)
	{
	  if (is_new)
	    sl_snprintf(tmp, SH_MSG_BUF, _(", link_new=<%s> "), tmp_lnk);
	  else
	    sl_snprintf(tmp, SH_MSG_BUF, _(", link_old=<%s> "), tmp_lnk);
	  SH_FREE(tmp_lnk);
	  sl_strlcat(msg, tmp, SH_MSG_BUF);
	} 
    }
  
  if (theFile->attr_string)
    {
      tmp_lnk     = sh_util_safe_name(theFile->attr_string);
      if (tmp_lnk)
	{
	  if (is_new)
	    sl_snprintf(tmp, SH_MSG_BUF, _(", acl_new=<%s> "), tmp_lnk);
	  else
	    sl_snprintf(tmp, SH_MSG_BUF, _(", acl_old=<%s> "), tmp_lnk);
	  SH_FREE(tmp_lnk);
	  sl_strlcat(msg, tmp, SH_MSG_BUF);
	} 
    }

  SH_FREE(tmp);
  return (msg);
}
#endif

void sh_hash_pushdata_memory (file_type * theFile, char * fileHash)
{
  sh_file_t * p;

  SL_ENTER(_("sh_hash_pushdata_memory"));

  p = sh_hash_push_int(theFile, fileHash);
  if (p) 
    {
      SH_MUTEX_LOCK(mutex_hash);
      hashinsert (p);
      p->modi_mask = theFile->check_mask;
      SH_MUTEX_UNLOCK(mutex_hash);
    }

  SL_RET0(_("sh_hash_pushdata_memory"));
}


/*****************************************************************
 *
 * Compare a file with the database status.
 *
 *****************************************************************/
int sh_hash_compdata (int class, file_type * theFile, char * fileHash,
		      char * policy_override, int severity_override)
{
  char * msg;
  sh_file_t * p;
  char * tmp;
  char * tmp_path;
  char * tmp_lnk;
  char * tmp_lnk_old;

  char * str;

  char timstr1c[32];
  char timstr2c[32];
  char timstr1a[32];
  char timstr2a[32];
  char timstr1m[32];
  char timstr2m[32];
  char linkHash[KEY_LEN+1];
  char * linkComp;
  int  maxcomp;

  char change_code[16];
  int  i;

  unsigned long modi_mask;

  char log_policy[32];
  volatile int  log_severity;
  char hashbuf[KEYBUF_SIZE];

  int  retval;

  SL_ENTER(_("sh_hash_compdata"));

  if (IsInit != 1) sh_hash_init();

  if (severity_override < 0)
    log_severity = ShDFLevel[class];
  else
    log_severity = severity_override;

  if (policy_override != NULL)
    sl_strlcpy (log_policy, policy_override, 32);

  /* --------  find the entry for the file ----------------       */

  SH_MUTEX_LOCK(mutex_hash);

  modi_mask = 0;
  retval    = 0;

  if (sl_strlen(theFile->fullpath) <= MAX_PATH_STORE) 
    p = hashsearch(theFile->fullpath);
  else 
    p = hashsearch( sh_tiger_hash(theFile->fullpath, 
				  TIGER_DATA, 
				  sl_strlen(theFile->fullpath),
				  hashbuf, sizeof(hashbuf))
		    );


  /* --------- Not found in database. ------------
   */

  if (p == NULL) 
    {
      if (S_FALSE == sh_ignore_chk_new(theFile->fullpath))
	{
	  tmp = sh_util_safe_name(theFile->fullpath);

	  str = all_items (theFile, fileHash, 1);
	  sh_error_handle (log_severity, FIL__, __LINE__, 0, 
			   MSG_FI_ADD2, 
			   tmp, str);
	  SH_FREE(str);

	  SH_FREE(tmp);
	}

      if (sh.flag.reportonce == S_TRUE)
	SET_SH_FFLAG_REPORTED(theFile->file_reported);

      if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	{
	  p = sh_hash_push_int(theFile, fileHash);
	  if (p)
	    {
	      hashinsert (p);
	      p->modi_mask = theFile->check_mask;
	    }
	}

      else if (S_TRUE == sh.flag.update)
	{
	  if (S_TRUE == sh_util_ask_update (theFile->fullpath))
	    {
	      p = sh_hash_push_int(theFile, fileHash);
	      if (p)
		{
		  hashinsert (p);
		  p->modi_mask = theFile->check_mask;
		}
	    }
	  else
	    {
	      retval = 1;
	      goto unlock_and_return;
	    }
	}

      goto unlock_and_return;
    }

  p->modi_mask = theFile->check_mask;

  /* initialize change_code */
  for (i = 0; i < 15; ++i)
    change_code[i] = '-';
  change_code[15] = '\0';

  TPT ((0, FIL__, __LINE__, _("file=<%s>, cs_old=<%s>, cs_new=<%s>\n"),
	theFile->fullpath, fileHash, p->theFile.checksum));

  if ( (fileHash != NULL) && (p->theFile.checksum != NULL)   && 
       (strncmp (fileHash, p->theFile.checksum, KEY_LEN) != 0) && 
       (theFile->check_mask & MODI_CHK) != 0)
    {
      if ((theFile->check_mask & MODI_SGROW) == 0)
	{
	  modi_mask |= MODI_CHK;
	  change_code[0] = 'C';
	  TPT ((0, FIL__, __LINE__, _("mod=<checksum>")));
	}
      else
	{
	  if (0 != strncmp (&fileHash[KEY_LEN + 1], 
			    p->theFile.checksum, KEY_LEN))
	    {
	      modi_mask |= MODI_CHK;
	      change_code[0] = 'C';
	      TPT ((0, FIL__, __LINE__, _("mod=<checksum>")));
	    }
	  else
	    {
	      p->theFile.size  = theFile->size;
	      sl_strlcpy(p->theFile.checksum, fileHash, KEY_LEN+1);
	    }
	}
    } 

  if (p->theFile.c_mode[0] == 'l') 
    {
      if (!(theFile->link_path) &&
	  (theFile->check_mask & MODI_LNK) != 0)
	{
	  linkComp = NULL;
	  modi_mask |= MODI_LNK;
	  change_code[1] = 'L';
	  TPT ((0, FIL__, __LINE__, _("mod=<link>")));
	}
      else
	{
	  if (sl_strlen(theFile->link_path) >= MAX_PATH_STORE) 
	    {
	      sl_strlcpy(linkHash, 
			 sh_tiger_hash(theFile->link_path, 
				       TIGER_DATA,
				       sl_strlen(theFile->link_path),
				       hashbuf, sizeof(hashbuf)), 
			 MAX_PATH_STORE+1);
	      linkComp = linkHash;
	      maxcomp  = KEY_LEN;
	    } 
	  else 
	    {
	      linkComp = theFile->link_path;
	      maxcomp  = MAX_PATH_STORE;
	    }
	  
	  if ( sl_strncmp (linkComp, p->linkpath, maxcomp) != 0 &&
	       (theFile->check_mask & MODI_LNK) != 0)
	    {
	      modi_mask |= MODI_LNK;
	      change_code[1] = 'L';
	      TPT ((0, FIL__, __LINE__, _("mod=<link>")));
	    } 
	}
    }

  if (p->theFile.c_mode[0] == 'c' || p->theFile.c_mode[0] == 'b') 
    {
      if ( ( major(theFile->rdev) != major((dev_t)p->theFile.rdev) || 
	     minor(theFile->rdev) != minor((dev_t)p->theFile.rdev) ) &&
	   (theFile->check_mask & MODI_RDEV) != 0)
	{
	  modi_mask |= MODI_RDEV;
	  change_code[2] = 'D';
	  TPT ((0, FIL__, __LINE__, _("mod=<rdev>")));
	} 
    }
      
  /* cast to UINT32 in case ino_t is not 32bit
   */
  if ( (UINT32) theFile->ino != (UINT32) p->theFile.ino  &&
       (theFile->check_mask & MODI_INO) != 0)
    {
      modi_mask |= MODI_INO;
      change_code[3] = 'I';
      TPT ((0, FIL__, __LINE__, _("mod=<inode>")));
    } 
    
  if ( theFile->hardlinks != (nlink_t) p->theFile.hardlinks &&
       (theFile->check_mask & MODI_HLN) != 0)
    {
      modi_mask |= MODI_HLN;
      change_code[4] = 'H';
      TPT ((0, FIL__, __LINE__, _("mod=<hardlink>")));
    } 


  if ( (  (theFile->mode != p->theFile.mode)
#if defined(USE_ACL) || defined(USE_XATTR)
	  || ( (sh_unix_check_selinux|sh_unix_check_acl) &&
	       ( 
		(theFile->attr_string == NULL && p->attr_string != NULL) ||
		(theFile->attr_string != NULL && p->attr_string == NULL) ||
		(theFile->attr_string != NULL && 0 != strcmp(theFile->attr_string, p->attr_string))
		)
	       )
#endif
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
          || (theFile->attributes != p->theFile.attributes)
#endif
	  )
       && (theFile->check_mask & MODI_MOD) != 0)
    {
      modi_mask |= MODI_MOD;
      change_code[5] = 'M';
      TPT ((0, FIL__, __LINE__, _("mod=<mode>")));
      /* 
       * report link path if switch link/no link 
       */
      if ((theFile->check_mask & MODI_LNK) != 0 &&
	  (theFile->c_mode[0] != p->theFile.c_mode[0]) &&
	  (theFile->c_mode[0] == 'l' || p->theFile.c_mode[0] == 'l'))
	{
	  modi_mask |= MODI_LNK;
	  change_code[1] = 'L';
	  TPT ((0, FIL__, __LINE__, _("mod=<link>")));
	}
    } 

  if ( theFile->owner != (uid_t) p->theFile.owner &&
       (theFile->check_mask & MODI_USR) != 0)
    {
      modi_mask |= MODI_USR;
      change_code[6] = 'U';
      TPT ((0, FIL__, __LINE__, _("mod=<user>")));
    } 

  if ( theFile->group != (gid_t) p->theFile.group &&
       (theFile->check_mask & MODI_GRP) != 0)
    {
      modi_mask |= MODI_GRP;
      change_code[7] = 'G';
      TPT ((0, FIL__, __LINE__, _("mod=<group>")));
    } 

  
  if ( theFile->mtime != (time_t) p->theFile.mtime &&
       (theFile->check_mask & MODI_MTM) != 0)
    {
      modi_mask |= MODI_MTM;
      change_code[8] = 'T';
      TPT ((0, FIL__, __LINE__, _("mod=<mtime>")));
    } 
  
  if ( (theFile->check_mask & MODI_ATM) != 0 &&
       theFile->atime != (time_t) p->theFile.atime)
    {
      modi_mask |= MODI_ATM;
      change_code[8] = 'T';
      TPT ((0, FIL__, __LINE__, _("mod=<atime>")));
    } 

  
  /* Resetting the access time will set a new ctime. Thus, either we ignore
   * the access time or the ctime for NOIGNORE
   */
  if ( theFile->ctime != (time_t) p->theFile.ctime &&
       (theFile->check_mask & MODI_CTM) != 0)
    {
      modi_mask |= MODI_CTM;
      change_code[8] = 'T';
      TPT ((0, FIL__, __LINE__, _("mod=<ctime>")));
    } 

  if ( theFile->size != (off_t) p->theFile.size &&
       (theFile->check_mask & MODI_SIZ) != 0)
    {
      if ((theFile->check_mask & MODI_SGROW) == 0 || 
	  theFile->size < (off_t) p->theFile.size)
	{
	  modi_mask |= MODI_SIZ;
	  change_code[9] = 'S';
	  TPT ((0, FIL__, __LINE__, _("mod=<size>")));
	}
    }
  change_code[10] = '\0';

  /* --- Directories special case ---
   */
  if (p->theFile.c_mode[0] == 'd'                               &&
      0 == (modi_mask & ~(MODI_SIZ|MODI_ATM|MODI_CTM|MODI_MTM)) && 
      sh_loosedircheck == S_TRUE)
    {
      modi_mask = 0;
    }

  /* --- Report full details. ---
   */
  if (modi_mask != 0 && sh.flag.fulldetail == S_TRUE)
    {
      if ((theFile->check_mask & MODI_ATM) == 0)
	modi_mask = MASK_READONLY_;
      else
	modi_mask = MASK_NOIGNORE_;
    }

  /* --- Report on modified files. ---
   */
  if (modi_mask != 0 && (!SH_FFLAG_REPORTED_SET(p->fflags)))
    { 
      tmp = SH_ALLOC(SH_MSG_BUF);
      msg = SH_ALLOC(SH_MSG_BUF);
      msg[0] = '\0';

      if (   ((modi_mask & MODI_MOD) != 0)
#if defined(HAVE_LIBPRELUDE)
	     || ((modi_mask & MODI_USR) != 0)
	     || ((modi_mask & MODI_GRP) != 0)
#endif
	     )
	{
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
	  sl_snprintf(tmp, SH_MSG_BUF, 
#ifdef SH_USE_XML
		      _("mode_old=\"%s\" mode_new=\"%s\" attr_old=\"%s\" attr_new=\"%s\" imode_old=\"%ld\" imode_new=\"%ld\" iattr_old=\"%ld\" iattr_new=\"%ld\" "),
#else
		      _("mode_old=<%s>, mode_new=<%s>, attr_old=<%s>, attr_new=<%s>, "),
#endif
		      p->theFile.c_mode, theFile->c_mode,
		      p->theFile.c_attributes, theFile->c_attributes
#ifdef SH_USE_XML
		      , (long) p->theFile.mode, (long) theFile->mode,
		      (long) p->theFile.attributes, 
		      (long) theFile->attributes
#endif
		      );
#else
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("mode_old=\"%s\" mode_new=\"%s\" imode_old=\"%ld\" imode_new=\"%ld\" "),
		      p->theFile.c_mode, theFile->c_mode,
		      (long) p->theFile.mode, (long) theFile->mode);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("mode_old=<%s>, mode_new=<%s>, "),
		      p->theFile.c_mode, theFile->c_mode);
#endif
#endif
	  sl_strlcat(msg, tmp, SH_MSG_BUF);

#if defined(USE_ACL) || defined(USE_XATTR)
	  if (theFile->attr_string != NULL || p->attr_string != NULL)
	    {
	      sl_snprintf(tmp, SH_MSG_BUF, 
#ifdef SH_USE_XML
			  _("acl_old=\"%s\" acl_new=\"%s\" "),
#else
			  _("acl_old=<%s>, acl_new=<%s>, "),
#endif
			  (p->attr_string)       ? p->attr_string       : _("none"), 
			  (theFile->attr_string) ? theFile->attr_string : _("none"));
	      
	      sl_strlcat(msg, tmp, SH_MSG_BUF);
	    }
#endif

#ifdef REPLACE_OLD
	  if ((modi_mask & MODI_MOD) != 0)
	    {
	      /*
	       * We postpone update if sh.flag.update == S_TRUE because
	       * in interactive mode the user may not accept the change.
	       */
	      if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
		{
		  sl_strlcpy(p->theFile.c_mode, theFile->c_mode, 11);
		  p->theFile.mode = theFile->mode;
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
		  sl_strlcpy(p->theFile.c_attributes,theFile->c_attributes,16);
		  p->theFile.attributes = theFile->attributes;
#endif
#if defined(USE_ACL) || defined(USE_XATTR)
		  if      (p->attr_string == NULL && theFile->attr_string != NULL)
		    { p->attr_string = sh_util_strdup (theFile->attr_string); }
		  else if (p->attr_string != NULL && theFile->attr_string == NULL)
		    { SH_FREE(p->attr_string); p->attr_string = NULL; }
		  else if (theFile->attr_string != NULL && p->attr_string != NULL)
		    { 
		      if (0 != strcmp(theFile->attr_string, p->attr_string))
			{
			  SH_FREE(p->attr_string);
			  p->attr_string = sh_util_strdup (theFile->attr_string);
			}
		    }
#endif
		}
	    }
#endif
	}

      if ((modi_mask & MODI_HLN) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF, 
#ifdef SH_USE_XML
		      _("hardlinks_old=\"%lu\" hardlinks_new=\"%lu\" "),
#else
		      _("hardlinks_old=<%lu>, hardlinks_new=<%lu>, "),
#endif
		      (unsigned long) p->theFile.hardlinks, 
		      (unsigned long) theFile->hardlinks);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.hardlinks = theFile->hardlinks;
#endif
	}

      if ((modi_mask & MODI_RDEV) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF,
#ifdef SH_USE_XML 
		      _("device_old=\"%lu,%lu\" device_new=\"%lu,%lu\" idevice_old=\"%lu\" idevice_new=\"%lu\" "),
#else
		      _("device_old=<%lu,%lu>, device_new=<%lu,%lu>, "),
#endif
		      (unsigned long) major(p->theFile.rdev), 
		      (unsigned long) minor(p->theFile.rdev), 
		      (unsigned long) major(theFile->rdev),
		      (unsigned long) minor(theFile->rdev)
#ifdef SH_USE_XML 
		      , (unsigned long) p->theFile.rdev, 
		      (unsigned long) theFile->rdev
#endif
		      );
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.rdev = theFile->rdev;
#endif
	}

      if ((modi_mask & MODI_INO) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF,
#ifdef SH_USE_XML 
		      _("inode_old=\"%lu\" inode_new=\"%lu\" "),
#else
		      _("inode_old=<%lu>, inode_new=<%lu>, "),
#endif
		      (unsigned long) p->theFile.ino, 
		      (unsigned long) theFile->ino);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    {
	      p->theFile.ino = theFile->ino;
	      p->theFile.dev = theFile->dev;
	    }
#endif
	}


      /* 
       * also report device for prelude
       */
#if defined(HAVE_LIBPRELUDE)
      if ((modi_mask & MODI_INO) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF,
#ifdef SH_USE_XML 
		      _("dev_old=\"%lu,%lu\" dev_new=\"%lu,%lu\" "),
#else
		      _("dev_old=<%lu,%lu>, dev_new=<%lu,%lu>, "),
#endif
		      (unsigned long) major(p->theFile.dev),
		      (unsigned long) minor(p->theFile.dev),
		      (unsigned long) major(theFile->dev),
		      (unsigned long) minor(theFile->dev)
		      );
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.dev = theFile->dev;
#endif
	}
#endif

      if (   ((modi_mask & MODI_USR) != 0)
#if defined(HAVE_LIBPRELUDE)
	  || ((modi_mask & MODI_MOD) != 0)
#endif
	  )
	{
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("owner_old=\"%s\" owner_new=\"%s\" iowner_old=\"%ld\" iowner_new=\"%ld\" "),
#else
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("owner_old=<%s>, owner_new=<%s>, iowner_old=<%ld>, iowner_new=<%ld>, "),
#endif
		      p->theFile.c_owner, theFile->c_owner, 
		      (long) p->theFile.owner, (long) theFile->owner
		      );
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if ((modi_mask & MODI_USR) != 0) {
	    if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	      {
		sl_strlcpy(p->theFile.c_owner, theFile->c_owner, USER_MAX+2);
		p->theFile.owner = theFile->owner;
	      }
	  }
#endif
	}

      if (   ((modi_mask & MODI_GRP) != 0)
#if defined(HAVE_LIBPRELUDE)
	  || ((modi_mask & MODI_MOD) != 0)
#endif
	  )
	{
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("group_old=\"%s\" group_new=\"%s\" igroup_old=\"%ld\" igroup_new=\"%ld\" "),
		      p->theFile.c_group, theFile->c_group,
		      (long) p->theFile.group, (long) theFile->group);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("group_old=<%s>, group_new=<%s>, igroup_old=<%ld>, igroup_new=<%ld>, "),
		      p->theFile.c_group, theFile->c_group,
		      (long) p->theFile.group, (long) theFile->group);
#endif

	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
          if ((modi_mask & MODI_GRP) != 0) {
	    if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	      {
		sl_strlcpy(p->theFile.c_group, theFile->c_group, GROUP_MAX+2);
		p->theFile.group = theFile->group;
	      }
	  }
#endif
	}

      if ((modi_mask & MODI_SIZ) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		      (UINT64) p->theFile.size, 
		      (UINT64) theFile->size);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.size = theFile->size;
#endif
	}

      if ((modi_mask & MODI_CTM) != 0)
	{
	  (void) sh_unix_gmttime (p->theFile.ctime, timstr1c, sizeof(timstr1c));
	  (void) sh_unix_gmttime (theFile->ctime,   timstr2c, sizeof(timstr2c));
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, _("ctime_old=\"%s\" ctime_new=\"%s\" "),
		      timstr1c, timstr2c);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("ctime_old=<%s>, ctime_new=<%s>, "),
		      timstr1c, timstr2c);
#endif
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.ctime = theFile->ctime;
#endif
	}

      if ((modi_mask & MODI_ATM) != 0)
	{
	  (void) sh_unix_gmttime (p->theFile.atime, timstr1a, sizeof(timstr1a));
	  (void) sh_unix_gmttime (theFile->atime,   timstr2a, sizeof(timstr2a));
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, _("atime_old=\"%s\" atime_new=\"%s\" "),
		      timstr1a, timstr2a);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("atime_old=<%s>, atime_new=<%s>, "),
		      timstr1a, timstr2a);
#endif
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.atime = theFile->atime;
#endif
	}

      if ((modi_mask & MODI_MTM) != 0)
	{
	  (void) sh_unix_gmttime (p->theFile.mtime, timstr1m, sizeof(timstr1m));
	  (void) sh_unix_gmttime (theFile->mtime,   timstr2m, sizeof(timstr2m));
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, _("mtime_old=\"%s\" mtime_new=\"%s\" "),
		      timstr1m, timstr2m);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("mtime_old=<%s>, mtime_new=<%s>, "),
		      timstr1m, timstr2m);
#endif
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.mtime = theFile->mtime;
#endif
	}


      if ((modi_mask & MODI_CHK) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF, 
#ifdef SH_USE_XML
		      _("chksum_old=\"%s\" chksum_new=\"%s\" "),
#else
		      _("chksum_old=<%s>, chksum_new=<%s>, "),
#endif
		      p->theFile.checksum, fileHash);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    {
	      sl_strlcpy(p->theFile.checksum, fileHash, KEY_LEN+1);
	      if ((theFile->check_mask & MODI_SGROW) != 0)	      
		p->theFile.size  = theFile->size;
	    }
#endif
	  /* FIXME is this correct? */
	  if (theFile->c_mode[0] != 'l' && theFile->link_path &&
	      strlen(theFile->link_path) > 2)
	    modi_mask |= MODI_LNK;
	}


      if ((modi_mask & MODI_LNK) != 0 /* && theFile->c_mode[0] == 'l' */)
	{
	  if (theFile->link_path)
	    tmp_lnk     = sh_util_safe_name(theFile->link_path);
	  else
	    tmp_lnk     = sh_util_strdup("-");
	  if (p->linkpath)
	    tmp_lnk_old = sh_util_safe_name(p->linkpath);
	  else
	    tmp_lnk_old = sh_util_strdup("-");
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, _("link_old=\"%s\" link_new=\"%s\" "),
		      tmp_lnk_old, tmp_lnk);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("link_old=<%s>, link_new=<%s>"),
		      tmp_lnk_old, tmp_lnk);
#endif
	  SH_FREE(tmp_lnk);
	  SH_FREE(tmp_lnk_old);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
#ifdef REPLACE_OLD
	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    {
	      if (p->linkpath != NULL && p->linkpath != notalink)
		SH_FREE(p->linkpath);
	      if (!(theFile->link_path) || 
		  (theFile->link_path[0] == '-' && theFile->link_path[1] == '\0'))
		p->linkpath = (char *)notalink;
	      else
		p->linkpath = sh_util_strdup(theFile->link_path);
	    }
#endif
	}


      tmp_path = sh_util_safe_name(theFile->fullpath);
      sh_error_handle(log_severity, FIL__, __LINE__, 
		      (long) modi_mask, MSG_FI_CHAN,
		      (policy_override == NULL) ? _(policy[class]):log_policy,
		      change_code, tmp_path, msg);

      SH_FREE(tmp_path);
      SH_FREE(tmp);
      SH_FREE(msg);

#ifndef REPLACE_OLD
      SET_SH_FFLAG_REPORTED(p->fflags);
#endif

      if (S_TRUE  == sh.flag.update)
	{
	  if (S_FALSE == sh_util_ask_update(theFile->fullpath))
	    {
	      /* user does not want to update, thus we replace
	       * with data from the baseline database
	       */
	      sl_strlcpy(theFile->c_mode, p->theFile.c_mode, 11);
	      theFile->mode  =  p->theFile.mode;
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
	      sl_strlcpy(theFile->c_attributes, p->theFile.c_attributes, 16);
	      theFile->attributes =  p->theFile.attributes;
#endif
#if defined(USE_ACL) || defined(USE_XATTR)
	      if      (theFile->attr_string == NULL && p->attr_string != NULL)
		{ theFile->attr_string = sh_util_strdup (p->attr_string); }
	      else if (theFile->attr_string != NULL && p->attr_string == NULL)
		{ SH_FREE(theFile->attr_string); theFile->attr_string = NULL; }
	      else if (theFile->attr_string != NULL && p->attr_string != NULL)
		{ 
		  if (0 != strcmp(theFile->attr_string, p->attr_string))
		    {
		      SH_FREE(theFile->attr_string);
		      theFile->attr_string = sh_util_strdup (p->attr_string);
		    }
		}
#endif
	      
	      if (theFile->c_mode[0] == 'l') /* c_mode is already copied */
		{
		  if (theFile->link_path)
		    SH_FREE(theFile->link_path);
		  if (p->linkpath)
		    theFile->link_path = sh_util_strdup(p->linkpath);
		  else
		    theFile->link_path = sh_util_strdup("-");
		}
	      else
		{
		  if (theFile->link_path)
		    SH_FREE(theFile->link_path);
		  if (p->linkpath && p->linkpath != notalink)
		    theFile->link_path = sh_util_strdup(p->linkpath);
		  else
		    theFile->link_path = NULL;
		}
	      
	      sl_strlcpy(fileHash, p->theFile.checksum, KEY_LEN+1);
	      
	      theFile->mtime =  p->theFile.mtime;
	      theFile->ctime =  p->theFile.ctime;
	      theFile->atime =  p->theFile.atime;
	      
	      theFile->size  =  p->theFile.size;
	      
	      sl_strlcpy(theFile->c_group, p->theFile.c_group, GROUP_MAX+2);
	      theFile->group =  p->theFile.group;
	      sl_strlcpy(theFile->c_owner, p->theFile.c_owner, USER_MAX+2);
	      theFile->owner =  p->theFile.owner;
	      
	      theFile->ino   =  p->theFile.ino;
	      theFile->rdev  =  p->theFile.rdev;
	      theFile->dev   =  p->theFile.dev;
	      theFile->hardlinks = p->theFile.hardlinks;
	      
	      SET_SH_FFLAG_VISITED(p->fflags);
	      CLEAR_SH_FFLAG_CHECKED(p->fflags);
	      retval = 1;
	      goto unlock_and_return;
	    }
	  else /* if (sh.flag.reportonce == S_TRUE) */
	    {
	      /* we replace the data in the in-memory copy of the
	       * baseline database, because otherwise we would get
	       * another warning if the suidcheck runs
	       */
	      sl_strlcpy(p->theFile.c_mode, theFile->c_mode, 11);
	      p->theFile.mode  =  theFile->mode;
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
	      sl_strlcpy(p->theFile.c_attributes, theFile->c_attributes, 16);
	      p->theFile.attributes = theFile->attributes;
#endif
#if defined(USE_ACL) || defined(USE_XATTR)
	      if      (p->attr_string == NULL && theFile->attr_string != NULL)
		{ p->attr_string = sh_util_strdup (theFile->attr_string); }
	      else if (p->attr_string != NULL && theFile->attr_string == NULL)
		{ SH_FREE(p->attr_string); p->attr_string = NULL; }
	      else if (theFile->attr_string != NULL && p->attr_string != NULL)
		{ 
		  if (0 != strcmp(theFile->attr_string, p->attr_string))
		    {
		      SH_FREE(p->attr_string);
		      p->attr_string = sh_util_strdup (theFile->attr_string);
		    }
		}
#endif
	      
	      if (theFile->c_mode[0] == 'l' || theFile->link_path)
		{
                  if (p->linkpath != NULL && p->linkpath != notalink)
		    SH_FREE(p->linkpath);
		  p->linkpath = sh_util_strdup(theFile->link_path);
		}
	      else
		{
	          if (p->linkpath != NULL && p->linkpath != notalink) {
		    SH_FREE(p->linkpath);
		  }
		  p->linkpath = (char *)notalink;
		}
	      
	      sl_strlcpy(p->theFile.checksum, fileHash, KEY_LEN+1);
	      
	      p->theFile.mtime = theFile->mtime;
	      p->theFile.ctime = theFile->ctime;
	      p->theFile.atime = theFile->atime;
	      
	      p->theFile.size  = theFile->size;
	      
	      sl_strlcpy(p->theFile.c_group, theFile->c_group, GROUP_MAX+2);
	      p->theFile.group =  theFile->group;
	      sl_strlcpy(p->theFile.c_owner, theFile->c_owner, USER_MAX+2);
	      p->theFile.owner =  theFile->owner;
	      
	      p->theFile.ino  = theFile->ino;
	      p->theFile.rdev = theFile->rdev;
	      p->theFile.dev  = theFile->dev;
	      p->theFile.hardlinks = theFile->hardlinks;
	    }
	}
    }

  SET_SH_FFLAG_VISITED(p->fflags);
  CLEAR_SH_FFLAG_CHECKED(p->fflags);

 unlock_and_return:
  ; /* 'label at end of compound statement */
  SH_MUTEX_UNLOCK(mutex_hash);
  SL_RETURN(retval, _("sh_hash_compdata"));
}

int hash_full_tree () 
{
  sh_file_t * p;
  int         i;

  SL_ENTER(_("sh_hash_compdata"));

  if (IsInit != 1) 
    SL_RETURN(0, _("sh_hash_compdata"));

  SH_MUTEX_LOCK_UNSAFE(mutex_hash);
  for (i = 0; i < TABSIZE; ++i)
    {
      for (p = tab[i]; p; p = p->next)
	CLEAR_SH_FFLAG_ALLIGNORE(p->fflags);
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_hash);
  SL_RETURN (0, _("sh_hash_compdata"));
} 


int hash_remove_tree (char * s) 
{
  sh_file_t *  p;
  size_t       len;
  unsigned int i;

  SL_ENTER(_("hash_remove_tree"));

  if (!s || *s == '\0')
    SL_RETURN ((-1), _("hash_remove_tree"));

  len = sl_strlen(s);

  if (IsInit != 1) 
    sh_hash_init();

  SH_MUTEX_LOCK_UNSAFE(mutex_hash);
  for (i = 0; i < TABSIZE; ++i)
    {
      for (p = tab[i]; p; p = p->next)
	{
	  if (p->fullpath && 0 == strncmp(s, p->fullpath, len))
	    { 
	      SET_SH_FFLAG_ALLIGNORE(p->fflags);
	    }
	}
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_hash);
  SL_RETURN ((0), _("hash_remove_tree"));
} 

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

static int ListFullDetail    = S_FALSE;
static int ListWithDelimiter = S_FALSE;
static char * ListFile       = NULL;

int set_list_file (const char * c)
{
  ListFile = sh_util_strdup(c);
  return 0;
}

int set_full_detail (const char * c)
{
  (void) c;
  ListFullDetail = S_TRUE;
  return 0;
}
 
int set_list_delimited (const char * c)
{
  (void) c;
  ListFullDetail = S_TRUE;
  ListWithDelimiter = S_TRUE;
  return 0;
}

/* Always quote the string, except if it is empty. Quote quotes by
 * doubling them.
 */
char * csv_escape(const char * str)
{
  const  char * p = str;
  const  char * q;

  size_t size       = 0;
  size_t flag_quote = 0;
  int    flag_comma = 0;
  char * new;
  char * pnew;

  if (p)
    {

      while (*p) 
	{
	  if (*p == ',')
	    flag_comma = 1;
	  else if (*p == '"')
	    ++flag_quote;
	  
	  ++size; ++p;
	}

      if (sl_ok_adds(size, flag_quote))
	size += flag_quote;      /* double each quote */
      else
	return NULL;

      if (sl_ok_adds(size, 3))
	size += 3; /* two quotes and terminating null */
      else
	return NULL;
      
      new = SH_ALLOC(size);
      
      if (flag_quote != 0)
	{
	  new[0] = '"';
	  pnew = &new[1];
	  q    = str;
	  while (*q)
	    {
	      *pnew = *q;
	      if (*pnew == '"')
		{
		  ++pnew; *pnew = '"';
		}
	      ++pnew; ++q;
	    }
	  *pnew = '"'; ++pnew;
	  *pnew = '\0';
	}
      else
	{
	  if (size > 3) 
	    {
	      new[0] = '"';
	      sl_strlcpy (&new[1], str, size-1);
	      new[size-2] = '"';
	      new[size-1] = '\0';
	    }
	  else
	    {
	      new[0] = '\0';
	    }
	}

      return new;
    }
  return NULL;
}


 
void sh_hash_list_db_entry_full_detail (sh_file_t * p)
{
  char * tmp;
  char * esc;
  char   str[81];

  if (ListWithDelimiter == S_TRUE)
    {
      printf(_("%7ld, %7ld, %10s, %5d, %12s, %5d, %3d, %-8s, %5d, %-8s, %5d, "),
	     (unsigned long) p->theFile.ino, (unsigned long) p->theFile.dev,
	     p->theFile.c_mode, (int) p->theFile.mode,
	     p->theFile.c_attributes, (int) p->theFile.attributes,
	     (int) p->theFile.hardlinks,
	     p->theFile.c_owner, (int) p->theFile.owner, 
	     p->theFile.c_group, (int) p->theFile.group);
    }
  else
    {
      printf(_("%7ld %7ld %10s %5d %12s %5d %3d %-8s %5d %-8s %5d "),
	     (unsigned long) p->theFile.ino, (unsigned long) p->theFile.dev,
	     p->theFile.c_mode, (int) p->theFile.mode,
	     p->theFile.c_attributes, (int) p->theFile.attributes,
	     (int) p->theFile.hardlinks,
	     p->theFile.c_owner, (int) p->theFile.owner, 
	     p->theFile.c_group, (int) p->theFile.group);
    }

  if ('c' == p->theFile.c_mode[0] || 'b' == p->theFile.c_mode[0])
    sl_snprintf(str, sizeof(str), "%"PRIu64, p->theFile.rdev);
  else
    sl_snprintf(str, sizeof(str), "%"PRIu64, p->theFile.size);

  printf( _(" %8s"), str);
  if (ListWithDelimiter == S_TRUE)
    putchar(',');

  printf( _(" %s"), sh_unix_gmttime (p->theFile.ctime, str, sizeof(str)));
  if (ListWithDelimiter == S_TRUE)
    putchar(',');
  printf( _(" %s"), sh_unix_gmttime (p->theFile.mtime, str, sizeof(str)));
  if (ListWithDelimiter == S_TRUE)
    putchar(',');
  printf( _(" %s"), sh_unix_gmttime (p->theFile.atime, str, sizeof(str)));
  if (ListWithDelimiter == S_TRUE)
    putchar(',');
  printf( _(" %s"), p->theFile.checksum);
  if (ListWithDelimiter == S_TRUE)
    putchar(',');

  tmp = sh_util_safe_name(p->fullpath);
  if (ListWithDelimiter != S_TRUE)
    {
      printf( _(" %s"), tmp);
    }
  else
    {
      esc = csv_escape(tmp);
      printf( _(" %s,"), (esc != NULL) ? esc : _("(null)"));
      if (esc)
	SH_FREE(esc);
    }
  SH_FREE(tmp);

  if ('l' == p->theFile.c_mode[0])
    {
      tmp = sh_util_safe_name(p->linkpath);
      if (ListWithDelimiter != S_TRUE)
	{
	  printf(_(" -> %s"), tmp);
	}
      else
	{
	  esc = csv_escape(tmp);
	  printf( _(" %s,"), (esc != NULL) ? esc : _("(null)"));
	  if (esc)
	    SH_FREE(esc);
	}
      SH_FREE(tmp);
    }

  if (p->attr_string)
    {
      tmp = sh_util_safe_name(p->attr_string);
      if (ListWithDelimiter != S_TRUE) 
	{
	  printf(_(" %s"), tmp);
	}
      else
	{
	  esc = csv_escape(tmp);
	  printf( _(" %s"), (esc != NULL) ? esc : _("(null)"));
	  if (esc)
	    SH_FREE(esc);
	}
      SH_FREE(tmp);
    }
  else
    {
      if (ListWithDelimiter == S_TRUE)
	printf("%s",_(" no_attr"));
    }
  putchar('\n');

  return;
}

void sh_hash_list_db_entry (sh_file_t * p)
{
  char nowtime[128];
  char thetime[128];
  char * tmp;
  time_t now  = time(NULL);
  time_t then = (time_t) p->theFile.mtime;

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GMTIME_R)
  struct tm   * time_ptr;
  struct tm     time_tm;

  time_ptr = gmtime_r(&then, &time_tm);
  strftime(thetime, 127, _("%b %d  %Y"), time_ptr);
  time_ptr = gmtime_r(&now,  &time_tm);
  strftime(nowtime, 127, _("%b %d  %Y"), time_ptr);
  if (0 == strncmp(&nowtime[7], &thetime[7], 4))
    {
      time_ptr = gmtime_r(&then, &time_tm);
      strftime(thetime, 127, _("%b %d %H:%M"), time_ptr);
    }
#else
  strftime(thetime, 127, _("%b %d  %Y"), gmtime(&then));
  strftime(nowtime, 127, _("%b %d  %Y"), gmtime(&now));
  if (0 == strncmp(&nowtime[7], &thetime[7], 4))
    strftime(thetime, 127, _("%b %d %H:%M"), gmtime(&then));
#endif

  tmp = sh_util_safe_name(p->fullpath);
  if ('c' == p->theFile.c_mode[0] || 'b' == p->theFile.c_mode[0])
    printf(_("%10s %3d %-8s %-8s %3d,%4d %s %s"),
	   p->theFile.c_mode, (int) p->theFile.hardlinks,
	   p->theFile.c_owner, p->theFile.c_group, 
	   (int) major((dev_t)p->theFile.rdev), 
	   (int) minor((dev_t)p->theFile.rdev),
	   thetime, 
	   tmp);
  else
    printf(_("%10s %3d %-8s %-8s %8ld %s %s"),
	   p->theFile.c_mode, (int) p->theFile.hardlinks,
	   p->theFile.c_owner, p->theFile.c_group, (long) p->theFile.size,
	   thetime, 
	   tmp);
  SH_FREE(tmp);

  if ('l' == p->theFile.c_mode[0])
    {
      tmp = sh_util_safe_name(p->linkpath);
      printf(_(" -> %s\n"), tmp);
      SH_FREE(tmp);
    }
  else
    printf("\n");
	  
  return;
}

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif    

int sh_hash_printcontent(char * linkpath)
{
#ifdef HAVE_LIBZ
  unsigned char * decoded;
  unsigned char * decompressed = NULL;
  size_t dlen;
  unsigned long clen;
  unsigned long clen_o;
  int    res;

  if (linkpath && *linkpath != '-')
    {
      dlen = sh_util_base64_dec_alloc (&decoded, 
				       (unsigned char *)linkpath, 
				       strlen(linkpath));

      clen = dlen * 2 + 1;

      do {
	if (decompressed)
	  SH_FREE(decompressed);
	clen += dlen; clen_o = clen;
	decompressed = SH_ALLOC(clen);
	res = uncompress(decompressed, &clen, decoded, dlen);
	if (res == Z_MEM_ERROR)
	  { fprintf(stderr, "%s",_("Error: Not enough memory\n")); return -1; }
	if (res == Z_DATA_ERROR)
	  { fprintf(stderr, "%s",_("Error: Data corrupt or incomplete\n")); return -1; }
      } while (res == Z_BUF_ERROR || clen == clen_o);

      decompressed[clen] = '\0';
      fputs( (char*) decompressed, stdout);
      SH_FREE(decompressed);
      return 0;
    }
#else
  (void) linkpath;
#endif
  fprintf(stderr, "%s",_("Error: No data available\n")); 
  return -1;
}

int sh_hash_list_db (const char * db_file)
{
  sh_file_t * p;
  SL_TICKET fd;
  char * line;
  int  flag = 0;

  if (!db_file)
    {
      _exit(EXIT_FAILURE);
      return -1; 
    }
  if (sl_is_suid())
    {
      fprintf(stderr, "%s",_("ERROR: insufficient privilege\n"));
      _exit (EXIT_FAILURE);
      return -1; /* for Mac OSX compiler */
    }
  if (0 == strcmp(db_file, _("default")))
    db_file = file_path('D', 'W');
  if (!db_file)
    {
      _exit(EXIT_FAILURE);
      return -1; 
    }

  line = SH_ALLOC(MAX_PATH_STORE+2);

  if ( SL_ISERROR(fd = sl_open_read(FIL__, __LINE__, db_file, SL_YESPRIV))) 
    {
      fprintf(stderr, _("ERROR: can't open %s for read (errnum = %ld)\n"), 
	      db_file, fd);
      _exit(EXIT_FAILURE);
      return -1; 
    }

  /* fast forward to start of data
   */
  sh_hash_setdataent(fd, line, MAX_PATH_STORE+1, db_file);

  while (1) 
    {
      p = sh_hash_getdataent (fd, line, MAX_PATH_STORE+1);
      if ((p != NULL) && (p->fullpath[0] == '/'))
	{
	  if (!ListFile)
	    {
	      flag = 1;
	      if (ListFullDetail == S_FALSE)
		sh_hash_list_db_entry (p); 
	      else
		sh_hash_list_db_entry_full_detail (p);
	    }
	  else
	    {
	      if (0 != sl_strcmp(ListFile, p->fullpath))
		{
		  continue;
		}
	      flag = 1;
	      if ('l' != p->theFile.c_mode[0])
		{
		  if (sh_hash_printcontent(p->linkpath) < 0)
		    {
		      _exit(EXIT_FAILURE);
		      return -1;
		    }
		}
	      else
		{
		  fprintf(stderr, "%s",_("File is a link\n"));
		  _exit(EXIT_FAILURE);
		  return -1;
		}
	      break;
	    }
	}
      else if (p == NULL)
	{
	  break;
	}
    }

  if (line != NULL)
    SH_FREE(line);
  sl_close (fd);

  fflush(NULL);

  if (flag == 0)
    {
      fprintf(stderr, "%s",_("File not found\n"));
      _exit(EXIT_FAILURE);
    }
  _exit(EXIT_SUCCESS);
  return 0; 
}

/* if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE) */
#endif
