/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2003 Rainer Wichmann                                      */
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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <signal.h>
#include <pwd.h>

#if !defined(AF_FILE)
#define AF_FILE AF_UNIX
#endif

#define SH_MAXMSG 209

static int    sock     = -1;
static char * sockname = NULL;

static char   password[15] = "";

static int    verbose = 0;

#ifdef SH_STEALTH
char * globber(const char * string);
#define _(string) globber(string) 
#define N_(string) string
#else
#define _(string)  string 
#define N_(string) string
#endif

#ifdef SH_STEALTH
#ifndef SH_MAX_GLOBS
#define SH_MAX_GLOBS 32
#endif
char * globber(const char * str)
{
  register int i, j;
  static int  count = -1;
  static char glob[SH_MAX_GLOBS][128];

  ++count; if (count > (SH_MAX_GLOBS-1) ) count = 0;
  j = strlen(str);
  if (j > 127) j = 127;

  for (i = 0; i < j; ++i)
    {
      if (str[i] != '\n' && str[i] != '\t') 
	glob[count][i] = str[i] ^ XOR_CODE;
      else
	glob[count][i] = str[i];
    }
  glob[count][j] = '\0';
  return glob[count];
}
#endif

#define CLIENT _("yulectl")


int 
make_named_socket (char * sockname)
{
  int sock;

#if 0
  struct sockaddr_un name;
  size_t size;
#else
  (void) sockname;
#endif

  /* Create the socket. */
  
  sock = socket (PF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror (_("ERROR: socket"));
      return -1;
    }

#if 0
  /* Bind a name to the socket. */
  name.sun_family = AF_FILE;
  strcpy (name.sun_path, sockname);

  /* The size of the address is
     the offset of the start of the filename,
     plus its length,
     plus one for the terminating null byte. */
  size = (offsetof (struct sockaddr_un, sun_path)
          + strlen (name.sun_path) + 1);

  if (bind (sock, (struct sockaddr *) &name, size) < 0)
    {
      perror (_("ERROR: bind"));
      return -1;
    }
#endif

  return sock;
}

void
termination_handler (int signum)
{
  /* Clean up. */
  if (signum != 0)
    {
      if (verbose)
	fprintf(stdout, _("# Terminated on signal %d\n"), signum);
    }
#if 0
  if (sockname != NULL) unlink (sockname);
#endif
  if (sock   >= 0 ) close  (sock);

  return;
}


int send_to_server (char * serversock, char * message)
{
  struct sockaddr_un name;
  /* size_t size; */
  int size;
  int nbytes;

  /* Initialize the server socket address. 
   */
  name.sun_family = AF_UNIX;
  strncpy (name.sun_path, serversock, sizeof(name.sun_path) - 1);
  size = (offsetof (struct sockaddr_un, sun_path)
          + strlen (name.sun_path) + 1);

  nbytes = connect(sock, (struct sockaddr *) & name, size);
  if (nbytes < 0)
    {
      perror (_("ERROR: connect"));
      return -1;
    }

  /* Send the datagram. 
  nbytes = sendto (sock, message, strlen (message) + 1, 0,
                   (struct sockaddr *) & name, size);
   */
  nbytes = send (sock, message, strlen (message) + 1, 0);

  if (nbytes < 0)
    {
      perror (_("ERROR: send"));
      return -1;
    }
  return 0;
}

static int getline_from_server (int sock, char * buf, int size)
{
  int nbytes = 0;
  int status = 0;
  char * p   = buf;

  do {
    status = read (sock, p, 1);
    if (status <= 0)
      {
	buf[nbytes] = '\0';
	return ((status == 0) ? nbytes : status);
      }
    else if (*p == '\0')
      {
	return nbytes;
      }
    ++nbytes; ++p;
  } while (nbytes < size);
  buf[size-1] = '\0';
  return 0;
}

int recv_from_server (char * message)
{
  int nbytes = 0;
  char recvmsg[SH_MAXMSG];
  int  num = 0;
  int  good = -1;
  int  islist = 0;
  char * p;

  if (password[0] == '\0')
    {
      if (message[0] == 'L' && message[1] == 'I' &&
	  message[2] == 'S' && message[3] == 'T')
	{
	  islist = 1;
	}
      if (message[0] == 'P' && message[1] == 'R' &&
	  message[2] == 'O' && message[3] == 'B' && message[4] == 'E' )
	{
	  islist = 1;
	}
    }
  else
    {
      p = &message[strlen(password)+1];
      if (p[0] == 'L' && p[1] == 'I' &&
	  p[2] == 'S' && p[3] == 'T')
	{
	  islist = 1;
	}
      if (p[0] == 'P' && p[1] == 'R' &&
	  p[2] == 'O' && p[3] == 'B' && p[4] == 'E' )
	{
	  islist = 1;
	}
    }

  if (islist == 1)
    {
      do {
	/*
	nbytes = recvfrom (sock, recvmsg, SH_MAXMSG, 0, NULL, 0);
	*/
	nbytes = getline_from_server (sock, recvmsg, SH_MAXMSG);
	if (nbytes < 0)
	  {
	    if (errno == EAGAIN)
	      {
		return 0;
	      }
	    else
	      {
		perror (_("ERROR: recv"));
		return -1;
	      }
	  }
	else if (nbytes == 0)
	  {
	    return 0;
	  }
	if (recvmsg[0] == 'E' && recvmsg[1] == 'N' && recvmsg[2] == 'D')
	  {
	    if (verbose && (num == 0))
	      fprintf (stdout, "%s", _("# There are no pending commands.\n"));
	    return 0;
	  }
	++num;
	fprintf (stdout, _("%03d: %s\n"), num, recvmsg);
      } while (nbytes >= 0);
    }
  else
    {
      /*
      nbytes = recvfrom (sock, recvmsg, SH_MAXMSG, 0, NULL, 0);
      */
      nbytes = recv (sock, recvmsg, SH_MAXMSG, 0);
      if (nbytes < 0)
	{
	  perror (_("ERROR: recv"));
	  return -1;
	}
    }

  /* Print a diagnostic message. */
  if (password[0] == '\0')
    {
      good = strcmp (message, recvmsg);
    }
  else
    {
      good = strcmp (&message[strlen(password)+1], recvmsg);
    }

  if (0 != good)
    {
      fprintf (stderr, "%s", _("ERROR: Bounced message != original message (possible reason: superfluous password).\n"));
      return -1;
    }
  else
    {
      if (verbose)
	fprintf (stdout, "%s", _("# Message received by server.\n"));
    }

  return 0;
}

void usage(char * name)
{
  printf(_("\nUsage : %s [-v][-s server_socket] -c command <client_hostname>\n\n"), 
	 name);

  printf("%s", _("Purpose : send commands to the server via a socket,\n"));
  printf("%s", _("          in particular commands that the server would\n"));
  printf("%s", _("          transfer to the client <client_hostname> when\n"));
  printf("%s", _("          this client connects to deliver a message.\n\n"));
  printf("%s", _("          If password is required, it is read from\n"));
  printf("%s", _("          $HOME/.yulectl_cred or taken from the environment\n"));
  printf("%s", _("          variable YULECTL_PASSWORD (not recommended).\n\n"));

  printf("%s", _("Commands: RELOAD    <reload configuration>\n"));
  printf("%s", _("          STOP      <terminate>\n"));
  printf("%s", _("          SCAN      <initiate file system check\n"));
  printf("%s", _("          CANCEL    <cancel previous command>\n"));
  printf("%s", _("          LIST      <list queued commands>\n"));
  printf("%s", _("          LISTALL   <list queued and last sent commands>\n"));
  printf("%s", _("          PROBE     <probe all clients for necessity of reload>\n"));
  return;
}

char * rtrim(char * str)
{
  size_t len;

  if (!str)
    return str;

  len = strlen(str);
  while (len > 0)
    {
      --len;
      if (str[len] == '\n' || str[len] == '\r')
	str[len] = '\0';
      else
	break;
    }
    
  return str;
}

void fixup_message (char * message)
{
  char message2[SH_MAXMSG];
  char home[4096];
  FILE * fp;
  struct passwd * pwent;
  char * pw;

  pw = getenv(_("YULECTL_PASSWORD"));
  if (pw && strlen(pw) < 15)
    {
      strcpy(password, pw);
      strcpy(message2, password);
      goto do_msg;
    }
  
  pwent = getpwuid(geteuid());
  if ((pwent == 0) || (pwent->pw_dir == NULL))
    {
      if (verbose)
	fprintf (stderr, _("WARNING: no home directory for euid %ld\n"), 
		 (long) geteuid()); 
      if (NULL != getenv(_("HOME")))
	{
	  strncpy(home, getenv(_("HOME")), 4096);
	  home[4095] = '\0';
	}
      else
	{
	  fprintf (stderr, _("ERROR: no home directory for euid %ld (tried $HOME and password database).\n"), (long) geteuid());
	  exit(EXIT_FAILURE);
	}
    }
  else
    {
      strncpy(home, pwent->pw_dir, 4096);
      home[4095] = '\0';
    }

  if ( (strlen(home) + strlen(_("/.yulectl_cred")) + 1) > 4096)
    {
      fprintf (stderr, "%s", _("ERROR: path for $HOME is too long.\n"));
      exit(EXIT_FAILURE);
    }
  strcat(home, _("/.yulectl_cred"));
  fp = fopen(home, "r");

#if !defined(HAVE_GETPEEREID) && !defined(SO_PEERCRED) && !defined(HAVE_STRUCT_CMSGCRED) && !defined(HAVE_STRUCT_FCRED) && !(defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))
  if (fp == NULL)
    {
      if (errno == ENOENT) {
	fprintf (stderr, 
		 _("ERROR No password file (%s) exists\n"),
		 home);
      }
      else {
	fprintf (stderr, 
		 _("ERROR: Password file (%s) not accessible for euid %ld uid %ld\n"),
		 home, (long)geteuid(), (long)getuid());
      }
      exit(EXIT_FAILURE);
    }
#else
  if (fp == NULL)
    return;
#endif

  if (NULL == fgets(message2, sizeof(message2), fp))
    {
      fprintf (stderr,
	       _("ERROR: empty or unreadable password file (%s).\n"),
	       home);
      exit(EXIT_FAILURE);
    }

  (void) rtrim(message2);

  if (strlen(message2) > 14)
    {
      fprintf (stderr, "%s", 
	       _("ERROR: Password too long (max. 14 characters).\n"));
      exit(EXIT_FAILURE);
    }

  strcpy(password, message2);
  fclose(fp);

 do_msg:
  strcat(message2, "@");

  strncat(message2, message, SH_MAXMSG - strlen(message2) -1);
  message2[SH_MAXMSG-1] = '\0';
  strcpy(message, message2);
  return;
}


int
main (int argc, char * argv[])
{

  char   message[SH_MAXMSG] = "";
  char   clientcd[1024];
  char   serversock[256];
  int    status, size;
  int    num = 1;
  int    flag = 0;
  
#ifdef HAVE_VSNPRINTF
  status = snprintf(serversock, 256, _("%s/%s.sock"), 
		    DEFAULT_PIDDIR, SH_INSTALL_NAME);
#else
  if ((strlen(DEFAULT_PIDDIR) + strlen(SH_INSTALL_NAME) + 1 + 6) > 256)
    {
      status = -1;
    }
  else
    {
      status = sprintf (serversock, _("%s/%s.sock"), 
			DEFAULT_PIDDIR, SH_INSTALL_NAME);
    }
#endif

  if ((status < 0) || (status > 255))
    {
      fprintf(stderr, _("ERROR: Path too long (maximum 255): %s/%s.sock\n"), 
	      DEFAULT_PIDDIR, SH_INSTALL_NAME);
      return (EXIT_FAILURE);
    }

  while (argc > 1 && argv[num][0] == '-')
    {
      switch (argv[num][1]) 
	{
	  case 'h':
	    usage(argv[0]);
	    return (EXIT_SUCCESS);

	  case 'v':
	    ++verbose;
	    break;

	  case 's':
	    --argc; ++num;
	    if (argv[num] == NULL || argv[num][0] == '\0') {
	      usage(argv[0]);
	      fprintf(stderr, "%s", _("ERROR: -s: argument missing\n"));
	      return (EXIT_FAILURE);
	    } else {
	      if (strlen(argv[num]) > 255) 
		{
		  fprintf(stderr, _("ERROR: Path too long: %s\n"), argv[num]);
		  return (EXIT_FAILURE);
		}
	      strncpy (serversock, argv[num], 256);
	      serversock[255] = '\0';
	    }
	    break;

	  case 'c':
	    --argc; ++num;
	    if (argv[num] == NULL || argv[num][0] == '\0') {
	      usage(argv[0]);
	      fprintf(stderr, "%s", _("ERROR: -c: argument missing\n"));
	      return (EXIT_FAILURE);
	    } else {
	      if (strlen(argv[num]) >= SH_MAXMSG) 
		{
		  fprintf(stderr, _("ERROR: Command too long: %s\n"), 
			  argv[num]);
		  return (EXIT_FAILURE);
		}
	      strncpy (message, argv[num], SH_MAXMSG);
	      message[SH_MAXMSG-1] = '\0';
	      strncat(message, ":", SH_MAXMSG-strlen(message)-1);
	      message[SH_MAXMSG-1] = '\0';
	      flag = 1;
	    }
	    break;

	  default:
	    usage(argv[0]);
	    fprintf(stderr, _("ERROR: unknown option -%c\n"), argv[num][1]);
	    return (EXIT_FAILURE);
	}
      --argc; ++num;
    }

  if (flag == 0) /* no command given */
    {
      usage(argv[0]);
      return (EXIT_FAILURE);
    }

  if (argc > 1)
    {
      if (strlen(argv[num]) > (SH_MAXMSG - strlen(message) -1)) 
	{
	  fprintf(stderr, _("ERROR: Hostname too long: %s\n"), argv[num]);
	  return (EXIT_FAILURE);
	}
      strncat (message, argv[num], SH_MAXMSG -strlen(message) - 1);
      message[SH_MAXMSG-1] = '\0';
    }
  else
    {
      if (message[0] == 'P' && message[1] == 'R' &&
	  message[2] == 'O' && message[3] == 'B' && message[4] == 'E' )
	{
	  strncat (message, _("dummy"), SH_MAXMSG -strlen(message) - 1);
	  message[SH_MAXMSG-1] = '\0';
	}
      else if (message[0] == 'L' && message[1] == 'I' &&
	       message[2] == 'S' && message[3] == 'T')
	{
	  strncat (message, _("dummy"), SH_MAXMSG -strlen(message) - 1);
	  message[SH_MAXMSG-1] = '\0';
	}
      else
	{
	  fprintf(stderr, "%s", _("ERROR: this command requires a hostname\n"));
	  usage(argv[0]);
	  return (EXIT_FAILURE);
	}
    }

  fixup_message(message);

  /* OpenBSD wants >= 1024
   */
  if (NULL == getcwd(clientcd, 1024))
    {
      perror(_("ERROR: getcwd"));
      return (EXIT_FAILURE);
    }
  size = strlen(clientcd) + 1 + strlen(CLIENT) + 6;
  sockname = malloc (size);
  if (!sockname)
    {
      perror(_("ERROR: main: malloc"));
      return (EXIT_FAILURE);
    }
#ifdef HAVE_VSNPRINTF
  snprintf(sockname, size, _("%s/%s.sock"), clientcd, CLIENT);
#else
  sprintf(sockname, _("%s/%s.sock"), clientcd, CLIENT);
#endif

  /* Make the socket.
   */
  sock = make_named_socket (sockname);
  if (sock < 0)
    {
      return (EXIT_FAILURE);
    }

  /* Set up termination handler.
   */
  signal (SIGINT,  termination_handler);
  signal (SIGHUP,  termination_handler);
  signal (SIGTERM, termination_handler);
  signal (SIGQUIT, termination_handler);

  /* Send the datagram. 
   */
  status = send_to_server (serversock, message);
  if (status < 0)
    {
      fprintf(stderr, "%s", _("ERROR: sending command to server failed\n"));
      (void) termination_handler(0);
      return (EXIT_FAILURE);
    }

  /* Wait for a reply. 
   */
  if (message[0] == 'L' && message[1] == 'I' &&
      message[2] == 'S' && message[3] == 'T')
    {
      if (verbose)
	fprintf(stdout, "%s", _("# Waiting for listing.\n"));
    }
  else
    {
      if (verbose)
	fprintf(stdout, "%s", _("# Waiting for confirmation.\n"));
    }
  status = recv_from_server (message);

  if (status < 0)
    {
      fprintf(stderr, "%s", _("ERROR: receiving data from server failed.\n"));
      (void) termination_handler(0);
      return (EXIT_FAILURE);
    }

  /* Clean up. */
  (void) termination_handler(0);
  return (EXIT_SUCCESS);
}

