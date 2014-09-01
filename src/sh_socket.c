/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2003,2005 Rainer Wichmann                                 */
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

/* define if you want debug info
 * #define SH_DEBUG_SOCKET
 */

#if defined(SH_WITH_SERVER) && defined(__linux__)
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "samhain.h"
#include "sh_socket.h"
#include "sh_error.h"
#include "sh_unix.h"
#include "sh_calls.h"

#undef  FIL__
#define FIL__  _("sh_socket.c")

#if defined (SH_WITH_CLIENT)

#include <signal.h>

void sh_socket_server_cmd(const char * srvcmd)
{
  SL_ENTER(_("sh_tools_server_cmd"));

  if ((srvcmd == NULL) || (srvcmd[0] == '\0') || (sl_strlen(srvcmd) < 4))
    {
      SL_RET0(_("sh_socket_server_cmd"));
    }
  if ((srvcmd[0] == 'S') && (srvcmd[1] == 'T') && 
      (srvcmd[2] == 'O') && (srvcmd[3] == 'P'))
    {
      TPT((0, FIL__, __LINE__, _("msg=<stop command from server>\n")));
#ifdef SIGQUIT
      raise(SIGQUIT);
#else
      sig_terminate       = 1;
      ++sig_raised;
#endif
    } 
  else if ((srvcmd[0] == 'R') && (srvcmd[1] == 'E') &&
	   (srvcmd[2] == 'L') && (srvcmd[3] == 'O') &&
	   (srvcmd[4] == 'A') && (srvcmd[5] == 'D'))
    {
      TPT((0, FIL__, __LINE__, _("msg=<reload command from server>\n")));
#ifdef SIGHUP
      raise(SIGHUP);
#else
      sig_config_read_again = 1;
      ++sig_raised;
#endif
    }
  else if ((srvcmd[0] == 'S') && (srvcmd[1] == 'C') &&
	   (srvcmd[2] == 'A') && (srvcmd[3] == 'N'))
    {
      TPT((0, FIL__, __LINE__, _("msg=<scan command from server>\n")));
      if (sh.flag.isdaemon == ON) 
	{ 
#ifdef SIGTTOU
	  raise(SIGTTOU);
#else
	  sig_force_check = 1;
	  ++sig_raised;
#endif
	} 
      else 
	{
	  sig_force_check = 1;
	  ++sig_raised;
	}
    }
  else
    {
      sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      srvcmd, 
		      _("sh_socket_server_cmd"));
    }
  SL_RET0(_("sh_socket_server_cmd"));
}
/* #if defined (SH_WITH_CLIENT)
 */
#endif

#if defined(SH_WITH_SERVER)
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>

#include <time.h>

#include <sys/socket.h>
#include <sys/un.h>


#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#if !defined(HAVE_GETPEEREID) && !defined(SO_PEERCRED)
#if defined(HAVE_STRUCT_CMSGCRED) || defined(HAVE_STRUCT_FCRED) || defined(HAVE_STRUCT_SOCKCRED)
#include <sys/param.h>
#include <sys/ucred.h>
#endif
#endif


int    pf_unix_fd  = -1;
static char * sh_sockname = NULL;
static char   sh_sockpass_real[SOCKPASS_MAX+1];

struct socket_cmd {
  char cmd[SH_MAXMSGLEN];
  char clt[SH_MAXMSGLEN];
  char cti[81];
  struct socket_cmd * next;
};

#if !defined(O_NONBLOCK)
#if defined(O_NDELAY)
#define O_NONBLOCK  O_NDELAY
#else
#define O_NONBLOCK  0
#endif
#endif

#if !defined(AF_FILE)
#define AF_FILE AF_UNIX
#endif

static struct socket_cmd * cmdlist    = NULL;
static struct socket_cmd * runlist    = NULL;

static int    sh_socket_flaguse = S_FALSE;
static int    sh_socket_flaguid = 0;

#include "sh_utils.h"

/* The reload list stores information about
 * reloads confirmed by clients (startup and/or
 * runtime cinfiguration reloaded).
 */
struct reload_cmd {
  char          clt[SH_MAXMSGLEN];
  time_t        cti;
  struct reload_cmd * next;
};
static struct reload_cmd * reloadlist = NULL;

void sh_socket_add2reload (const char * clt)
{
  struct reload_cmd  * new = reloadlist;

  while (new)
    {
      if (0 == sl_strcmp(new->clt, clt))
	{
#ifdef SH_DEBUG_SOCKET
	  fprintf(stderr, "add2reload: time reset for %s\n", clt);
#endif
	  sl_strlcpy (new->clt, clt, SH_MAXMSGLEN);
	  new->cti = time(NULL);
	  return;
	}
      new = new->next;
    }

  new = SH_ALLOC(sizeof(struct reload_cmd));
#ifdef SH_DEBUG_SOCKET
  fprintf(stderr, "add2reload: time set for %s\n", clt);
#endif
  sl_strlcpy (new->clt, clt, SH_MAXMSGLEN);
  new->cti = time(NULL);

  new->next    = reloadlist;
  reloadlist   = new;

  return;
}

#include "zAVLTree.h"
#include "sh_html.h"
#include "sh_tools.h"
static void sh_socket_add2list (struct socket_cmd * in);

static void sh_socket_probe4reload (void)
{
  struct reload_cmd  * new;
  struct socket_cmd    cmd;

  zAVLCursor avlcursor;
  client_t * item;
  extern zAVLTree * all_clients;

  char     * file;
  unsigned long dummy;
  struct stat buf;

#ifdef SH_DEBUG_SOCKET
  fprintf(stderr, "PROBE\n");
#endif

  for (item = (client_t *) zAVLFirst(&avlcursor, all_clients); item;
       item = (client_t *) zAVLNext(&avlcursor))
    {
#ifdef SH_DEBUG_SOCKET
      fprintf(stderr, "%s %d\n", item->hostname, (int)item->status_now);
#endif

      if (item->status_now != CLT_INACTIVE)
	{
	  int flag = 0;

	  file = get_client_conf_file (item->hostname, &dummy);

#ifdef SH_DEBUG_SOCKET
	  fprintf(stderr, "%s\n", file);
#endif
	  if (0 == stat (file, &buf))
	    {
	      new = reloadlist;
	      while (new)
		{
#ifdef SH_DEBUG_SOCKET
		  fprintf(stderr, "%s <> %s\n", new->clt, item->hostname);
#endif
		  if (0 == sl_strcmp(new->clt, item->hostname))
		    {
		      flag = 1; /* Client is in list already */

#ifdef SH_DEBUG_SOCKET
		      fprintf(stderr, "%lu <> %lu\n", 
			      (unsigned long) buf.st_mtime, 
			      (unsigned long)new->cti);
#endif
		      if (buf.st_mtime > new->cti)
			{
			  /* reload */
			  sl_strlcpy(cmd.cmd, _("RELOAD"),    SH_MAXMSGLEN);
			  sl_strlcpy(cmd.clt, item->hostname, SH_MAXMSGLEN);
			  sh_socket_add2list (&cmd);
			}
		      break;
		    }
		  new = new->next;
		}

	      if (flag == 0)
		{
		  /* client is active, but start message has been missed; reload 
		   */
		  sl_strlcpy(cmd.cmd, _("RELOAD"),    SH_MAXMSGLEN);
		  sl_strlcpy(cmd.clt, item->hostname, SH_MAXMSGLEN);
		  sh_socket_add2list (&cmd);

		  /* Add the client to the reload list and set
		   * time to 0, since we don't know the startup time.
		   */
		  sh_socket_add2reload (item->hostname);
		  new = reloadlist;
		  while (new)
		    {
		      if (0 == sl_strcmp(new->clt, item->hostname))
			{
			  new->cti = 0;
			  break;
			}
		      new = new->next;
		    }
		}
	    } /* if stat(file).. */
	} /* if !CLT_INACTIVE */
    } /* loop over clients */
  return;
}

char * sh_get_sockpass (void)
{
  size_t j = 0;

  while (skey->sh_sockpass[2*j] != '\0' && j < sizeof(sh_sockpass_real))
    {
      sh_sockpass_real[j] = skey->sh_sockpass[2*j];
      ++j;
    }
  sh_sockpass_real[j] = '\0';

  return sh_sockpass_real;
}

void sh_set_sockpass (void)
{
  int j;
  for (j = 0; j < 15; ++j)
    {
      sh_sockpass_real[j] = '\0';
    }
}

int sh_socket_use (const char * c)
{
  return sh_util_flagval(c, &sh_socket_flaguse);
}

int sh_socket_remove ()
{
  int retval = 0;
#ifdef S_ISSOCK
  struct stat sbuf;
#endif

  SL_ENTER(_("sh_socket_remove"));

  if (NULL == sh_sockname)
    {
      SL_RETURN((retval),_("sh_socket_remove"));
    }

  if (0 != tf_trust_check (DEFAULT_PIDDIR, SL_YESPRIV))
    {
      SL_RETURN((-1),_("sh_socket_remove"));
    }

  if ( (retry_lstat(FIL__, __LINE__, sh_sockname, &sbuf) == 0) && 
       (sbuf.st_uid == getuid()))
    {
#ifdef S_ISSOCK
      if (S_ISSOCK (sbuf.st_mode))
	{
	  retval = retry_aud_unlink (FIL__, __LINE__, sh_sockname);
	}
#else
      retval = retry_aud_unlink (FIL__, __LINE__, sh_sockname);
#endif
    }
  SL_RETURN((retval),_("sh_socket_remove"));
}

#if !defined(HAVE_GETPEEREID) && !defined(SO_PEERCRED) && !defined(HAVE_STRUCT_CMSGCRED) && !defined(HAVE_STRUCT_FCRED) && !(defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))

#define NEED_PASSWORD_AUTH

#endif

int sh_socket_uid (const char * c)
{
  uid_t val = (uid_t) strtol (c, (char **)NULL, 10);
  sh_socket_flaguid = val;
#if defined(NEED_PASSWORD_AUTH)
  sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, errno, MSG_E_SUBGEN,
		  _("Config option SetSocketAllowUID not supported, use SetSocketPassword"), 
		  _("sh_socket_uid"));
#endif
  return 0;
}

int sh_socket_password (const char * c)
{
#if defined(NEED_PASSWORD_AUTH)
  int j, i;
  
#define LCG(n) ((69069 * n) & 0xffffffffUL)

  i = sl_strlen(c);
  if (i > SOCKPASS_MAX) {
    return -1;
  }
  for (j = 0; j < (2*SOCKPASS_MAX+1); ++j)
    {
      skey->sh_sockpass[j] = '\0';
    }
  for (j = 0; j < i; ++j)
    {
      skey->sh_sockpass[2*j]     = c[j];
      skey->sh_sockpass[(2*j)+1] = (LCG(c[j]) % 256);
    }
  return 0;
#else
  sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, errno, MSG_E_SUBGEN,
		  _("Config option SetSocketPassword not supported, use SetSocketAllowUID"), 
		  _("sh_socket_password"));
  (void) c;
  return 0;
#endif
}


int sh_socket_open_int ()
{
  struct sockaddr_un name;
  size_t size;
  int    flags;
#if defined(SO_PASSCRED) 
  socklen_t    optval = 1;
#endif
  struct stat buf;
  char errbuf[SH_ERRBUF_SIZE];
  
  SL_ENTER(_("sh_socket_open_int"));

  if (sh_socket_flaguse == S_FALSE)
    {
      SL_RETURN(0, _("sh_socket_open_int"));
    }

  if (sh_sockname == NULL)
    {
      size = sl_strlen(DEFAULT_PIDDIR) + 1 + sl_strlen(SH_INSTALL_NAME) + 6;
      sh_sockname = SH_ALLOC(size); /* compile-time constant */
      sl_strlcpy(sh_sockname, DEFAULT_PIDDIR, size);
      sl_strlcat(sh_sockname, "/", size);
      sl_strlcat(sh_sockname, SH_INSTALL_NAME, size);
      sl_strlcat(sh_sockname, _(".sock"), size);
    }

  if (0 != sh_unix_check_piddir (sh_sockname))
    {
      SH_FREE(sh_sockname);
      SL_RETURN((-1),_("sh_socket_open_int"));
    }

  pf_unix_fd = socket (PF_UNIX, SOCK_STREAM, 0);
  if ((pf_unix_fd) < 0)
    {
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: socket"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

  if (sizeof(name.sun_path) < (1 + sl_strlen(sh_sockname)))
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		       _("PID dir path too long"), 
		       _("sh_socket_open_int"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

  name.sun_family = AF_FILE;
  sl_strlcpy (name.sun_path, sh_sockname, sizeof(name.sun_path));

  size = (offsetof (struct sockaddr_un, sun_path)
          + strlen (name.sun_path) + 1);

  flags = retry_lstat (FIL__, __LINE__, sh_sockname, &buf);

  if (flags == 0)
    {
      sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, -1, MSG_E_SUBGEN,
		      _("Socket exists, trying to unlink it"), 
		      _("sh_socket_open_int"));
      if (sh_socket_remove() < 0) 
	{
	  sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
	  sh_error_handle ((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			   _("Unlink of socket failed, maybe path not trusted"), 
			   _("sh_socket_open_int"));
	  SL_RETURN( (-1), _("sh_socket_open_int"));
	}
    }

  if (bind ((pf_unix_fd), (struct sockaddr *) &name, size) < 0)
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: bind"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

#ifdef SO_PASSCRED
  if (0 != setsockopt(pf_unix_fd, SOL_SOCKET, SO_PASSCRED, 
		      &optval, sizeof(optval)))
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: setsockopt"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }
#endif

  flags = fcntl((pf_unix_fd), F_GETFL);
  if (flags < 0)
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: fcntl1"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

  flags = fcntl((pf_unix_fd), F_SETFL, flags|O_NONBLOCK);
  if (flags < 0)
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_open_int: fcntl2"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

  if (0 != listen(pf_unix_fd, 5))
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: listen"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }
  SL_RETURN( (0), _("sh_socket_open_int"));
}
/* #if !defined(HAVE_CMSGCRED) || !defined(SO_PEERCRED) */
/* #endif */

/*
#if !defined(HAVE_GETPEEREID) && !defined(SO_PEERCRED) && !defined(HAVE_STRUCT_CMSGCRED) && !defined(HAVE_STRUCT_FCRED) && !(defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))
static 
int sh_socket_read (struct socket_cmd * srvcmd)
{
  srvcmd->cmd[0] = '\0';
  srvcmd->clt[0] = '\0';
  return 0;
}
#else
*/

/*
 * Parts of the socket authentication code is copied from PostgreSQL:
 *
 * PostgreSQL Database Management System
 * (formerly known as Postgres, then as Postgres95)
 *
 * Portions Copyright (c) 1996-2001, The PostgreSQL Global Development Group
 *
 * Portions Copyright (c) 1994, The Regents of the University of California
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without a written agreement
 * is hereby granted, provided that the above copyright notice and this
 * paragraph and the following two paragraphs appear in all copies.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */
static 
int sh_socket_read (struct socket_cmd * srvcmd)
{
  struct socket_cmd * list_cmd;
  char message[SH_MAXMSG];
  struct sockaddr_un name;
  ACCEPT_TYPE_ARG3 size = sizeof(name);

  int nbytes;
  int talkfd;
  int retry = 0;

  char * cmd = NULL;
  char * clt = NULL;

  int  client_uid = -1;
  char errbuf[SH_ERRBUF_SIZE];


  struct msghdr msg;
  struct iovec iov;

#if defined(NEED_PASSWORD_AUTH)
  char * eopw = NULL;
  char * goodpassword = NULL;
#endif

#if defined(HAVE_GETPEEREID)
  uid_t peer_uid;
  gid_t peer_gid;
#elif defined(SO_PEERCRED) 
  struct ucred cr;
#ifdef HAVE_SOCKLEN_T
  socklen_t cl = sizeof(cr);
#else
  int       cl = sizeof(cr);
#endif 

#elif defined(HAVE_STRUCT_CMSGCRED) || defined(HAVE_STRUCT_FCRED) || (defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))

#ifdef HAVE_STRUCT_CMSGCRED
  typedef struct cmsgcred Cred;
#define CRED_UID cmcred_uid 

#elif HAVE_STRUCT_FCRED
  typedef struct fcred Cred;
#define CRED_UID fc_uid 

#elif HAVE_STRUCT_SOCKCRED
  typedef struct sockcred Cred;
#define CRED_UID sc_uid 

#endif
  Cred       *cred;

  /* Compute size without padding */
  char   cmsgmem[ALIGN(sizeof(struct cmsghdr)) + ALIGN(sizeof(Cred))];   
  /* for NetBSD */

  /* Point to start of first structure */
  struct cmsghdr *cmsg = (struct cmsghdr *) cmsgmem;
#endif

  if (pf_unix_fd  < 0)
    {
      return 0;
    }

  iov.iov_base = (char *) &message;
  iov.iov_len  = sizeof(message);

  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

#if !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID)
#if defined(HAVE_STRUCT_CMSGCRED) || defined(HAVE_STRUCT_FCRED) || (defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))
  msg.msg_control = (char *) cmsg;
  msg.msg_controllen = sizeof (cmsgmem);
  memset (cmsg, 0, sizeof (cmsgmem));
#endif
#endif

  /* the socket is non-blocking 
   * 'name' is the address of the sender socket
   */
  do {
    talkfd = accept(pf_unix_fd, (struct sockaddr *) &name, &size);
  } while (talkfd < 0 && errno == EINTR);

  if ((talkfd < 0) && (errno == EAGAIN))
    {
      return 0;
    }
  else if (talkfd < 0)
    {
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_read: accept"));
      return -1;
    }


#if defined(LOCAL_CREDS) && !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID)
  /* Set the socket to receive credentials on the next message 
   */
  {
    int on = 1;
    if (setsockopt (talkfd, 0, LOCAL_CREDS, &on, sizeof (on)) < 0)
      {
	sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			sh_error_message (errno, errbuf, sizeof(errbuf)), 
			_("sh_socket_read: setsockopt"));
	sl_close_fd(FIL__, __LINE__, talkfd);
	return -1;
      }
  }
#endif

  do {
    nbytes = recvmsg (talkfd, &msg, 0);
    if ((nbytes < 0) && (errno != EAGAIN))
      {
	sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			sh_error_message (errno, errbuf, sizeof(errbuf)),
			_("sh_socket_read: recvmsg"));
	sl_close_fd(FIL__, __LINE__, talkfd);	
	return -1;
      }
    else if (nbytes < 0)
      {
	++retry;
	retry_msleep(0, 10);
      }
  } while ((nbytes < 0) && (retry < 3));

#ifdef SH_DEBUG_SOCKET
  fprintf(stderr, "%d bytes received\n", nbytes);
#endif

  /* msg.msg_iov.iov_base, filled by recvmsg
   */
  message[sizeof(message)-1] = '\0';

  if (nbytes < 0)
    {
      if (errno == EAGAIN)
	{
	  /* no data */
	  sl_close_fd(FIL__, __LINE__, talkfd);
	  return 0;
	}
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_read: recvfrom"));
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }

#if defined(HAVE_GETPEEREID)
  if (0 != getpeereid(talkfd, &peer_uid, &peer_gid))
    {
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_read: getpeereid"));
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }
  client_uid = peer_uid;
  cmd = message;
#elif defined(SO_PEERCRED)
  if (0 != getsockopt(talkfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl))
    {
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_read: getsockopt"));
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }
  client_uid = cr.uid;
  cmd = message;
#elif defined(HAVE_STRUCT_CMSGCRED) || defined(HAVE_STRUCT_FCRED) || (defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))
  if (cmsg->cmsg_len < sizeof (cmsgmem) || cmsg->cmsg_type != SCM_CREDS)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("Message from recvmsg() was not SCM_CREDS"), 
		      _("sh_socket_read"));

      /* Check for file descriptors sent using SCM_RIGHTS, and
       * close them. If MSG_CTRUNC is set, the buffer was too small,
       * and no fds are duped.
       */
      if (msg.msg_controllen >= sizeof(struct cmsghdr) &&
	  (msg.msg_flags & MSG_CTRUNC) == 0)
	{
	  unsigned int     data_size;
	  unsigned int     data_i;
	  int              fdcount, fdmax;
	  struct cmsghdr * cmptr;
	  int              fdsbuf[1 + (sizeof(cmsgmem)/sizeof(int))];

	  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr != NULL;
	       cmptr = CMSG_NXTHDR(&msg, cmptr)) 
	    {
	      if (cmptr->cmsg_len > sizeof (cmsgmem) || 
		  cmptr->cmsg_level != SOL_SOCKET ||
		  cmptr->cmsg_type  != SCM_RIGHTS)
		continue;

	      /* Crappy way of finding the data length.
	       * cmptr->cmsg_len includes both header and padding,
	       * how are you supposed to find the data length?
	       * cmptr->cmsg_len - ALIGN(sizeof(struct cmsghdr)) ?
	       */
	      data_size = 0;

	      for (data_i = 0; data_i < cmptr->cmsg_len; ++data_i)
		{
		  if (CMSG_LEN(data_i) == cmptr->cmsg_len)
		    {
		      data_size = data_i;
		      break;
		    }
		}
	      memcpy(fdsbuf, CMSG_DATA(cmptr), data_size);
	      fdmax = data_size / sizeof(int);
	      for (fdcount = 0; fdcount < fdmax; ++fdcount)
		(void) sl_close_fd(FIL__, __LINE__, fdsbuf[fdcount]);
	    }
	}
      
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }
  cred = (Cred *) CMSG_DATA (cmsg);
  client_uid = cred->CRED_UID;
  cmd = message;
#elif defined(NEED_PASSWORD_AUTH)
  goodpassword = sh_get_sockpass();
  eopw = strchr(message, '@');
  if (eopw) 
    *eopw = '\0';
  /*
   * message is null-terminated and >> goodpassword
   */
  if (0 == strcmp(goodpassword, message) &&
      strlen(goodpassword) < (sizeof(message)/2))
    {
      client_uid = sh_socket_flaguid;
      cmd = &message[strlen(goodpassword)+1];
      sh_set_sockpass();
    }
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("Bad password"), 
		      _("sh_socket_read"));
      sh_set_sockpass();
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }
#else
  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		  _("Socket credentials not supported on this OS"), 
		  _("sh_socket_read"));
  sl_close_fd(FIL__, __LINE__, talkfd);
  return -1;
#endif

#ifdef SH_DEBUG_SOCKET
  fprintf(stderr, "Peer uid=%d, required=%d\n",
	  client_uid, sh_socket_flaguid);
#endif

  if (client_uid != sh_socket_flaguid)
    {
      sh_error_handle((-1), FIL__, __LINE__, client_uid, MSG_E_SUBGEN,
		      _("client does not have required uid"), 
		      _("sh_socket_read: getsockopt"));
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }


  /* Give a diagnostic message. 
   */
#ifdef SH_DEBUG_SOCKET
  fprintf (stderr, "Server: got message: %s\n", cmd);
#endif

  clt = strchr(cmd, ':');
  if (clt != NULL) 
    {
      *clt = '\0'; ++clt;
      if (sl_strlen(cmd) >= SH_MAXMSGLEN)
	{
#ifdef SH_DEBUG_SOCKET
	  fprintf (stderr, "Server: command too long: %s\n", cmd);
#endif
	  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			  _("Bad message format: command too long"), 
			  _("sh_socket_read"));
	  sl_close_fd(FIL__, __LINE__, talkfd);
	  return -1;
	}
      else if (sl_strlen(clt) >= SH_MAXMSGLEN)
	{
#ifdef SH_DEBUG_SOCKET
	  fprintf (stderr, "Server: hostname too long: %s\n", clt);
#endif
	  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			  _("Bad message format: hostname too long"), 
			  _("sh_socket_read"));
	  sl_close_fd(FIL__, __LINE__, talkfd);
	  return -1;
	}
      if (cmd[0] == 'L' && cmd[1] == 'I' &&
	  cmd[2] == 'S' && cmd[3] == 'T')
	{
#ifdef SH_DEBUG_SOCKET
	  fprintf (stderr, "Server: list %s\n", clt);
#endif
	  goto list_all;
	}
      else if (cmd[0] == 'P' && cmd[1] == 'R' &&
	  cmd[2] == 'O' && cmd[3] == 'B' && cmd[4] == 'E')
	{
#ifdef SH_DEBUG_SOCKET
	  fprintf (stderr, "Server: probe start %s\n", clt);
#endif
	  sh_socket_probe4reload();
#ifdef SH_DEBUG_SOCKET
	  fprintf (stderr, "Server: probe done  %s\n", clt);
#endif
	  cmd[0] = 'L'; cmd[1] = 'I'; cmd[2] = 'S'; cmd[3] = 'T';cmd[4] = '\0';
	  goto list_all;
	}
      sl_strlcpy (srvcmd->cmd, cmd, SH_MAXMSGLEN);
      sl_strlcpy (srvcmd->clt, clt, SH_MAXMSGLEN);
      --clt; *clt = ':';
    }
  else
    {
#ifdef SH_DEBUG_SOCKET
      fprintf (stderr, "Server: bad message\n");
#endif
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      _("Bad message format"), 
		      _("sh_socket_read"));
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }

  /* Bounce the message back to the sender. 
   * 'name' is the receiver address; it has been been filled
   *        with the sender address in the recvfrom call 
   */
#ifdef SH_DEBUG_SOCKET
  fprintf (stderr, "Server: send message: %s to %s\n", 
	   cmd, name.sun_path);
#endif
  /*
  nbytes = sendto (pf_unix_fd, message, nbytes, 0,
                       (struct sockaddr *) & name, size);
  */
  nbytes = send (talkfd, cmd, strlen(cmd) + 1, 0);
  sl_close_fd(FIL__, __LINE__, talkfd);
  if (nbytes < 0)
    {
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_read: send"));
      return -1;
    }
#ifdef SH_DEBUG_SOCKET
  fprintf (stderr, "Server: message is out\n");
#endif
  return nbytes;

 list_all:
#ifdef SH_DEBUG_SOCKET
  fprintf (stderr, "Server: list all\n");
#endif
  if (cmd[4] == 'A' && cmd[5] == 'L' && cmd[6] == 'L')
    {
      list_cmd = runlist;
      while (list_cmd)
	{
	  sl_snprintf(message, sizeof(message), _("SENT  %8s  %32s  %s"),
		      list_cmd->cmd, list_cmd->clt, list_cmd->cti);
	  /*
	  sl_strlcpy(message,     _("DONE"), SH_MAXMSG);
	  sl_strlcat(message,          "  ", SH_MAXMSG);
	  sl_strlcat(message, list_cmd->cmd, SH_MAXMSG);
	  sl_strlcat(message,          "  ", SH_MAXMSG);
	  sl_strlcat(message, list_cmd->clt, SH_MAXMSG);
	  sl_strlcat(message,          "  ", SH_MAXMSG);
	  sl_strlcat(message, list_cmd->cti, SH_MAXMSG);
	  */
	  nbytes = send (talkfd, message, sl_strlen(message) + 1, 0);
	  if (nbytes < 0)
	    {
	      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			      sh_error_message (errno, errbuf, sizeof(errbuf)), 
			      _("sh_socket_read: sendto"));
	      sl_close_fd(FIL__, __LINE__, talkfd);
	      return -1;
	    }
	  list_cmd = list_cmd->next;
	}
    }

  list_cmd = cmdlist;
  while (list_cmd)
    {
      sl_snprintf(message, sizeof(message), _(">>>>  %8s  %32s  %s"),
		  list_cmd->cmd, list_cmd->clt, list_cmd->cti);
      /*
      sl_strlcpy(message,     _(">>>>"), SH_MAXMSG);
      sl_strlcat(message,          "  ", SH_MAXMSG);
      sl_strlcat(message, list_cmd->cmd, SH_MAXMSG);
      sl_strlcat(message,          "  ", SH_MAXMSG);
      sl_strlcat(message, list_cmd->clt, SH_MAXMSG);
      sl_strlcat(message,          "  ", SH_MAXMSG);
      sl_strlcat(message, list_cmd->cti, SH_MAXMSG);
      */
      /*
      nbytes = sendto (pf_unix_fd, message, sl_strlen(message) + 1, 0,
                       (struct sockaddr *) & name, size);
      */
      nbytes = send (talkfd, message, sl_strlen(message) + 1, 0);
      if (nbytes < 0)
	{
	  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			  sh_error_message (errno, errbuf, sizeof(errbuf)), 
			  _("sh_socket_read: sendto"));
	  sl_close_fd(FIL__, __LINE__, talkfd);
	  return -1;
	}
      list_cmd = list_cmd->next;
    }

  /*
  nbytes = sendto (pf_unix_fd, _("END"), 4, 0,
		   (struct sockaddr *) & name, size);
  */
  /* nbytes = *//* never read */ send (talkfd, _("END"), 4, 0);
  sl_close_fd(FIL__, __LINE__, talkfd);
  return 0;
}
/* #if !defined(HAVE_CMSGCRED) || !defined(SO_PEERCRED) */
/* #endif */

static void sh_socket_add2list (struct socket_cmd * in)
{
  struct socket_cmd  * new;

  new = SH_ALLOC(sizeof(struct socket_cmd));
  sl_strlcpy (new->cmd, in->cmd, sizeof(new->cmd));
  sl_strlcpy (new->clt, in->clt, sizeof(new->clt));
#ifdef SH_DEBUG_SOCKET
  fprintf(stderr, "add2list: time set for %s\n", new->clt);
#endif
  (void) sh_unix_time(0, new->cti, sizeof(new->cti));
  new->next = cmdlist;
  cmdlist   = new;

  return;
}

static void sh_socket_add2run (struct socket_cmd * in)
{
  struct socket_cmd  * new = runlist;
  char * client_name       = in->clt;

  while (new)
    {
      if (0 == sl_strcmp(new->clt, client_name))
	{
	  sl_strlcpy (new->cmd, in->cmd, sizeof(new->cmd));
	  sl_strlcpy (new->clt, in->clt, sizeof(new->clt));
#ifdef SH_DEBUG_SOCKET
	  fprintf(stderr, "add2run: time reset for %s\n", new->clt);
#endif
	  (void) sh_unix_time(0, new->cti, sizeof(new->cti));
	  return;
	}
      new = new->next;
    }

  new = SH_ALLOC(sizeof(struct socket_cmd));
  sl_strlcpy (new->cmd, in->cmd, sizeof(new->cmd));
  sl_strlcpy (new->clt, in->clt, sizeof(new->clt));
#ifdef SH_DEBUG_SOCKET
  fprintf(stderr, "add2run: time set for %s\n", new->clt);
#endif
  (void) sh_unix_time(0, new->cti, sizeof(new->cti));
  new->next = runlist;
  runlist   = new;

  return;
}



static void sh_socket_rm2list (const char * client_name)
{
  struct socket_cmd * old = cmdlist;
  struct socket_cmd * new = cmdlist;
  
  while (new)
    {
      if (0 == sl_strcmp(new->clt, client_name))
	{
	  if ((new == cmdlist) && (new->next == NULL))
	    {
	      cmdlist = NULL;
	      SH_FREE(new);
	      return;
	    }
	  else if (new == cmdlist)
	    {
	      cmdlist = new->next;
	      SH_FREE(new);
	      return;
	    }
	  else
	    {
	      old->next = new->next;
	      SH_FREE(new);
	      return;
	    }
	}
      old = new;
      new = new->next;
    }
  return;
}

/* poll the socket to gather input
 */
int sh_socket_poll()
{
  struct socket_cmd   cmd;
  char   cancel_cmd[SH_MAXMSGLEN];
 
  /* struct pollfd sh_poll = { pf_unix_fd, POLLIN, 0 }; */

  if (pf_unix_fd  < 0)
    {
      return 0;
    }

  sl_strlcpy(cancel_cmd, _("CANCEL"), sizeof(cancel_cmd)); 

  while (sh_socket_read (&cmd) > 0)
    {
      if (0 == sl_strcmp(cmd.cmd, cancel_cmd))
	{
	  sh_socket_rm2list  (cmd.clt);
	}
      else
	{
	  sh_socket_rm2list  (cmd.clt);
	  sh_socket_add2list (&cmd);
	}
    }
  return 0;
}

/* return the command associated with client_name
   and remove the corresponding entry
 */
char * sh_socket_check(const char * client_name)
{
  struct socket_cmd * new = cmdlist;
  static char         out[SH_MAXMSGLEN];

  while (new)
    {
      if (0 == sl_strcmp(new->clt, client_name))
	{
	  sl_strlcpy(out, new->cmd, sizeof(out));
	  sh_socket_add2run (new);
	  sh_socket_rm2list  (client_name);
	  return out;
	}
      new = new->next;
    }
  return NULL;
}

/* #if defined (SH_WITH_SERVER)
 */
#endif

