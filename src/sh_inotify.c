/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2009 Rainer Wichmann                                      */
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

#if defined(HAVE_SYS_INOTIFY_H)

#undef  FIL__
#define FIL__  _("sh_inotify.c")

/* printf */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_calls.h"
#include "sh_inotify.h"
#include "sh_mem.h"
#include "slib.h"

/**************************************************
 *
 * Make the inotify fd thread-specific by 
 * encapsulating it in get/set functions:
 * sh_get_inotify_fd() / sh_set_inotify_fd()
 *
 **************************************************/

#if defined(HAVE_PTHREAD)
static pthread_key_t  inotify_key;
static pthread_once_t inotify_key_once = PTHREAD_ONCE_INIT;

static void make_inotify_key()
{
    (void) pthread_key_create(&inotify_key, free);
}

static int sh_get_inotify_fd()
{
  void * ptr;
  int  * fp;

  (void) pthread_once(&inotify_key_once, make_inotify_key);
 
  if ((ptr = pthread_getspecific(inotify_key)) == NULL) 
    {
      ptr = malloc(sizeof(int));
      if (ptr)
	{
	  fp  = (int*) ptr;
	  *fp = -1;
	  (void) pthread_setspecific(inotify_key, ptr);
	}
      else
	{
	  return -1;
	}
    }
  else 
    {
      fp  = (int*) ptr;
    }
  return *fp;
}

static void sh_set_inotify_fd(int fd)
{
  int  * fp;

  fp = (int*) pthread_getspecific(inotify_key);
  if (fp)
    *fp = fd;
  return;
}

/* !defined(HAVE_PTHREAD) */
#else

static int sh_inotify_fd = -1;

static inline int sh_get_inotify_fd()
{
  return sh_inotify_fd;
}

static inline void sh_set_inotify_fd(int fd)
{
  sh_inotify_fd = fd;
}

#endif

/*--- nothing thread-related below this point --- */


/**************************************************
 *
 * Get inotify fd, initialize inotify if necessary
 *
 **************************************************/
#define SH_INOTIFY_FAILED -2

static int sh_inotify_getfd()
{
  int ifd = sh_get_inotify_fd();

  if (ifd >= 0)
    {
      return ifd;
    }

  else if (ifd == SH_INOTIFY_FAILED)
    {
      return -1;
    }

  else /* if (ifd == -1) */
    {
#if defined(HAVE_INOTIFY_INIT1)
      ifd = inotify_init1(IN_CLOEXEC);
#else
      ifd = inotify_init();
      if (ifd >= 0)
	{
	  long sflags;

	  sflags = retry_fcntl(FIL__, __LINE__, ifd, F_GETFD, 0);
	  retry_fcntl(FIL__, __LINE__, ifd, F_SETFD, sflags|FD_CLOEXEC);
	}
#endif

      if (ifd < 0)
	{
	  sh_set_inotify_fd(SH_INOTIFY_FAILED);
	  return -1;
	}

      sh_set_inotify_fd(ifd);
      return ifd;
    }
}

/**************************************************
 *
 * Public function:
 *  int sh_inotify_wait_for_change(char * filename,
 *                                 int watch,
 *                                 int * errnum,
 *                                 int   waitsec);
 * Returns: watch, if nonnegative
 *          -1 on error or reopen required
 *             (check errnum != 0)
 *
 * Caller needs to keep track of watch descriptor
 *
 **************************************************/

#define SH_INOTIFY_REOPEN 0
#define SH_INOTIFY_MODIFY 1

void sh_inotify_remove(sh_watches * watches)
{
  int     i;
  int     ifd = sh_inotify_getfd();

  for (i = 0; i < watches->count; ++i)
    {
      if (watches->file[i])
	{
	  SH_FREE (watches->file[i]);
	  watches->file[i] = 0;
	}
      watches->watch[i] = 0;
      watches->flag[i] = 0;
    }
  watches->count = 0;
  if (ifd >= 0)
    close(ifd);
  sh_set_inotify_fd(-1);

  return;
}

static int index_watched_file(char * filename, sh_watches * watches)
{
  int i;

  for (i = 0; i < watches->count; ++i)
    {
      if (0 == strcmp(filename, watches->file[i]))
	return i;
    }
  return -1;
}

/* This function is idempotent; it will add the watch only once 
 */
int sh_inotify_add_watch(char * filename, sh_watches * watches, int  * errnum)
{
  size_t len;
  *errnum = 0;

  if (filename)
    {
      int nwatch;
      int index = index_watched_file(filename, watches);
      
      if (index < 0)
	{
	  int     ifd = sh_inotify_getfd();

	  if (watches->count == SH_INOTIFY_MAX)
	    {
#ifdef EMFILE
	      *errnum = EMFILE;
#else
	      *errnum = 24;
#endif
	      return -1;
	    }

	  nwatch = inotify_add_watch (ifd, filename, 
				      IN_MODIFY|IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT);
	  if (nwatch < 0)
	    {
	      *errnum = errno;
	      return -1;
	    }
	  
	  watches->watch[watches->count] = nwatch;
	  watches->flag[watches->count]  = 0;

	  len = strlen(filename) + 1;
	  watches->file[watches->count] = SH_ALLOC(len);
	  sl_strlcpy(watches->file[watches->count], filename, len);

	  ++(watches->count);
	}
    }
  return 0;
}

int sh_inotify_wait_for_change(char * filename, sh_watches * watches, 
			       int  * errnum, int waitsec)
{
  int     ifd = sh_inotify_getfd();
  
  *errnum = 0;

 start_it:

  if (ifd >= 0)
    {
      ssize_t len = -1;
      ssize_t  i  = 0;
      int  flag = 0;
      char buffer[1024];

      /* -- Add watch if required 
       */
      if (filename)
	{
	  if (sh_inotify_add_watch(filename, watches, errnum) < 0)
	    {
	      retry_msleep(waitsec, 0);
	      return -1;
	    }
	}

      for (i = 0; i < watches->count; ++i)
	{
	  if (watches->watch[i] == -1)
	    watches->watch[i] = inotify_add_watch (ifd, watches->file[i], 
					 IN_MODIFY|IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT);
	}


      /* -- Blocking read on inotify file descriptor
       */
      do {
	len = read (ifd, &buffer, sizeof(buffer));
      } while (len < 0 || errno == EINTR);

      if (len > 0)
	{
	  int j;
	  struct inotify_event *event;

	  i = 0;
	  
	  while (i < len) {

	    event = (struct inotify_event *) &buffer[i];

	    for (j = 0; j < watches->count; ++j)
	      {
		if (watches->watch[j] == event->wd)
		  {
		    if (event->mask & IN_MODIFY)
		      {
			watches->flag[j] |= SH_INOTIFY_MODIFY;
			flag |= SH_INOTIFY_MODIFY;
		      }
		    else if (event->mask & IN_DELETE_SELF || 
			event->mask & IN_UNMOUNT     || 
			event->mask & IN_MOVE_SELF   )
		      {
			watches->flag[j] |= SH_INOTIFY_REOPEN;
			(void) inotify_rm_watch(ifd, watches->watch[j]);
			watches->watch[j] = -1;
			flag |= SH_INOTIFY_REOPEN;
		      }
		  }
	      }
	    i += sizeof (struct inotify_event) + event->len;
	  }
	}
      else if (len == -1)
	{
	  *errnum = errno;
	  retry_msleep(waitsec, 0);

	  return -1;
	}

      if (flag & SH_INOTIFY_REOPEN)
	{
	  if (flag & SH_INOTIFY_MODIFY)
	    return 0;
	  else
	    goto start_it;
	}

      return 0;
    }

  /* Inotify not working, sleep
   */
  retry_msleep(waitsec, 0);

  *errnum = 0;
  return -1;
}

/* !defined(HAVE_SYS_INOTIFY_H) */
#else

#include "sh_calls.h"
#include "sh_inotify.h"

void sh_inotify_remove(sh_watches * watches)
{
  (void) watches;
  return;
}

int sh_inotify_wait_for_change(char * filename, sh_watches * watches,
			       int *  errnum, int waitsec)
{
  (void) filename;
  (void) watches;

  /* Inotify not working, sleep for waitsec seconds
   */
  retry_msleep(waitsec, 0);

  *errnum = 0;
  return -1;
}

int sh_inotify_add_watch(char * filename, sh_watches * watches, int  * errnum)
{
  (void) filename;
  (void) watches;
  *errnum = 0;
  return 0;
}

#endif
