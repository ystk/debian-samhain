/*****************************************************************************
* 
* Nagios check_samhain plugin
* 
* License: GPL
* Copyright (c) 2012 Rainer Wichmann
*
* Based on the Nagios check_load plugin:
*   License: GPL
*   Copyright (c) 1999-2007 Nagios Plugins Development Team
* 
* Description:
* 
* This file contains the check_samhain plugin
* 
* This plugin tests whether samhain has reported policy violations.
* 
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* 
* 
*****************************************************************************/

#include <stdio.h>
/* malloc, free */
#include <stdlib.h>
/* getpid, open */
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

const char *progname = "check_samhain";
const char *copyright = "2012";
const char *email = "support@la-samhna.de";

#define _(a) a

/*
#include "common.h"
#include "utils.h"
#include "popen.h"
*/
enum {
        STATE_OK,
        STATE_WARNING,
        STATE_CRITICAL,
        STATE_UNKNOWN,
        STATE_DEPENDENT
};



static int process_arguments (int argc, char **argv);
static int validate_arguments (void);
void print_help (void);
void print_usage (void);

#define SH_STATNUM 6
char          * sh_status_file = NULL;
unsigned long   sh_timeout     = 0;
unsigned long   sh_status[SH_STATNUM] = { 0 };

char *status_line;
int take_into_account_cpus = 0;

static void
get_threshold(char *arg, double *th)
{
	size_t i, n;
	int valid = 0;
	char *str = arg, *p;

	n = strlen(arg);
	for(i = 0; i < 3; i++) {
		th[i] = strtod(str, &p);
		if(p == str) break;

		valid = 1;
		str = p + 1;
		if(n <= (size_t)(str - arg)) break;
	}

	/* empty argument or non-floatish, so warn about it and die */
	if(!i && !valid) usage (_("Warning threshold must be float or float triplet!\n"));

	if(i != 2) {
		/* one or more numbers were given, so fill array with last
		 * we got (most likely to NOT produce the least expected result) */
		for(n = i; n < 3; n++) th[n] = th[i];
	}
}


int
main (int argc, char **argv)
{
	int result;
	int i;
	long numcpus;

	double la[3] = { 0.0, 0.0, 0.0 };	/* NetBSD complains about unitialized arrays */
#ifndef HAVE_GETLOADAVG
	char input_buffer[MAX_INPUT_BUFFER];
# ifdef HAVE_PROC_LOADAVG
	FILE *fp;
	char *str, *next;
# endif
#endif

#if 0
	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);
	setlocale(LC_NUMERIC, "POSIX");
#endif

	/* Parse extra opts if any */
	argv = np_extra_opts (&argc, argv, progname);

	if (process_arguments (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

#ifdef HAVE_GETLOADAVG
	result = getloadavg (la, 3);
	if (result != 3)
		return STATE_UNKNOWN;
#else
# ifdef HAVE_PROC_LOADAVG
	fp = fopen (PROC_LOADAVG, "r");
	if (fp == NULL) {
		printf (_("Error opening %s\n"), PROC_LOADAVG);
		return STATE_UNKNOWN;
	}

	while (fgets (input_buffer, MAX_INPUT_BUFFER - 1, fp)) {
		str = (char *)input_buffer;
		for(i = 0; i < 3; i++) {
			la[i] = strtod(str, &next);
			str = next;
		}
	}

	fclose (fp);
# else
	child_process = spopen (PATH_TO_UPTIME);
	if (child_process == NULL) {
		printf (_("Error opening %s\n"), PATH_TO_UPTIME);
		return STATE_UNKNOWN;
	}
	child_stderr = fdopen (child_stderr_array[fileno (child_process)], "r");
	if (child_stderr == NULL) {
		printf (_("Could not open stderr for %s\n"), PATH_TO_UPTIME);
	}
	fgets (input_buffer, MAX_INPUT_BUFFER - 1, child_process);
	sscanf (input_buffer, "%*[^l]load average: %lf, %lf, %lf", &la1, &la5, &la15);

	result = spclose (child_process);
	if (result) {
		printf (_("Error code %d returned in %s\n"), result, PATH_TO_UPTIME);
		return STATE_UNKNOWN;
	}
# endif
#endif

	if (take_into_account_cpus == 1) {
		if ((numcpus = GET_NUMBER_OF_CPUS()) > 0) {
			la[0] = la[0] / numcpus;
			la[1] = la[1] / numcpus;
			la[2] = la[2] / numcpus;
		}
	}
	if ((la[0] < 0.0) || (la[1] < 0.0) || (la[2] < 0.0)) {
#ifdef HAVE_GETLOADAVG
		printf (_("Error in getloadavg()\n"));
#else
# ifdef HAVE_PROC_LOADAVG
		printf (_("Error processing %s\n"), PROC_LOADAVG);
# else
		printf (_("Error processing %s\n"), PATH_TO_UPTIME);
# endif
#endif
		return STATE_UNKNOWN;
	}

	/* we got this far, so assume OK until we've measured */
	result = STATE_OK;

	asprintf(&status_line, _("load average: %.2f, %.2f, %.2f"), la1, la5, la15);

	for(i = 0; i < 3; i++) {
		if(la[i] > cload[i]) {
			result = STATE_CRITICAL;
			break;
		}
		else if(la[i] > wload[i]) result = STATE_WARNING;
	}

	printf("%s - %s|", state_text(result), status_line);
	for(i = 0; i < 3; i++)
		printf("load%d=%.3f;%.3f;%.3f;0; ", nums[i], la[i], wload[i], cload[i]);

	putchar('\n');
	return result;
}


/* process command-line arguments */
static int
process_arguments (int argc, char **argv)
{
	int c = 0;

	int option = 0;
	static struct option longopts[] = {
		{"warning",  required_argument, 0, 'w'},
		{"critical", required_argument, 0, 'c'},
		{"path",     required_argument, 0, 'r'},
		{"timeout",  required_argument, 0, 't'},
		{"version",  no_argument,       0, 'V'},
		{"help",     no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	if (argc < 2)
		return ERROR;

	while (1) {
		c = getopt_long (argc, argv, "Vht:p:c:w:", longopts, &option);

		if (c == -1 || c == EOF)
			break;

		switch (c) {
		case 'w': /* warning time threshold */
			get_threshold(optarg, wload);
			break;
		case 'c': /* critical time threshold */
			get_threshold(optarg, cload);
			break;
		case 'p':
		        sh_status_file = strdup(optarg);
			break;
		case 't':
		        sh_timeout = strtoul(optarg, (char **) NULL, 10);
			break;
		case 'V':									/* version */
			print_revision (progname, NP_VERSION);
			exit (STATE_OK);
		case 'h':									/* help */
			print_help ();
			exit (STATE_OK);
		case '?':									/* help */
			usage5 ();
		}
	}

	c = optind;
	if (c == argc)
		return validate_arguments ();

	/* handle the case if both arguments are missing,
	 * but not if only one is given without -c or -w flag */
	if(c - argc == 2) {
		get_threshold(argv[c++], wload);
		get_threshold(argv[c++], cload);
	}
	else if(c - argc == 1) {
		get_threshold(argv[c++], cload);
	}

	return validate_arguments ();
}



static int
validate_arguments (void)
{
	int i = 0;

	/* match cload first, as it will give the most friendly error message
	 * if user hasn't given the -c switch properly */
	for(i = 0; i < 3; i++) {
		if(cload[i] < 0)
			die (STATE_UNKNOWN, _("Critical threshold for %d-minute load average is not specified\n"), nums[i]);
		if(wload[i] < 0)
			die (STATE_UNKNOWN, _("Warning threshold for %d-minute load average is not specified\n"), nums[i]);
		if(wload[i] > cload[i])
			die (STATE_UNKNOWN, _("Parameter inconsistency: %d-minute \"warning load\" is greater than \"critical load\"\n"), nums[i]);
		if(timeout < 0)
		        die (STATE_UNKNOWN, _("Parameter inconsistency: %ld-second \"timeout\" is lower than zero\n"), timeout);
	}

	return OK;
}



void
print_help (void)
{
	print_revision (progname, NP_VERSION);

	printf ("Copyright (c) 2012 Rainer Wichmann\n");
	printf (COPYRIGHT, copyright, email);

	printf (_("This plugin tests whether samhain has reported policy violations."));

	printf ("\n\n");

	print_usage ();

	printf (UT_HELP_VRSN);
	printf (UT_EXTRA_OPTS);

	printf (" %s\n", "-w, --warning=NWARN");
	printf ("    %s\n", _("Exit with WARNING status if number of policy violations exceed NWARN"));
	printf (" %s\n", "-c, --critical=NCRIT");
	printf ("    %s\n", _("Exit with CRITICAL status if number of policy violations exceed NCRIT"));
	printf (" %s\n", "-p, --path=PATH");
	printf ("    %s\n", _("Specify the path to the status report file"));
	printf (" %s\n", "-t, --timeout=NSEC");
	printf ("    %s\n", _("Exit with UNKNOWN status if no reports found for last NSEC seconds"));


	printf (UT_SUPPORT);
}

void
print_usage (void)
{
  printf ("%s\n", _("Usage:"));
	printf ("%s [-r] -w WLOAD1,WLOAD5,WLOAD15 -c CLOAD1,CLOAD5,CLOAD15\n", progname);
}


/* >>>>>>>>>>>>>>>>>>>>>>>> read status file <<<<<<<<<<<<<<<<<<<<<< */

/* overflow check */
int sl_ok_adds (size_t a, size_t b) /* a+b */
{
  if (a <= (SIZE_MAX - b))
    return 1; /* no overflow */
  else
    return 0;
}

/* write lock for filename
 */
static void sh_efile_lock (const char * filename, int flag)
{
  size_t len;
  int    res = -1;
  char myPid[64];
  char * lockfile;
  int    status;

  sprintf (myPid, "%ld\n", (long) getpid());             /* known to fit  */

  if (filename == NULL)
    {
      printf (_("Error: path to status file not specified\n"));
      exit(STATE_UNKNOWN);
    }

  len = strlen(filename);
  if (sl_ok_adds(len, 6))
    len += 6;
  lockfile = malloc(len);
  strcpy(lockfile, filename,   len);
  strcat(lockfile, ".lock", len);

  if (flag == 0)
    {
      /* --- Delete the lock file. --- 
       */
      res = unlink (lockfile);
      if (res < ) {
	printf (_("Error unlinking lockfile %s\n"), lockfile);
	exit(STATE_UNKNOWN);
      }
    }
  else
    {
      int fd;
      unsigned int count = 0;

      /* fails if file exists 
       */
      do {
	fd = open (lockfile, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (fd < 0)
	  {
	    sleep(1);
	    ++count;
	  }
	
      } while (fd < 0 && count < 3);
      
      if (fd < 0)
	{
	  printf (_("Error unlinking lockfile %s\n"), lockfile);
	  exit(STATE_UNKNOWN);
	}
	  
      res = write (fd, myPid, strlen(myPid));
      if (res < 0)
	{
	  printf (_("Error writing to lockfile %s\n"), lockfile);
	  exit(STATE_UNKNOWN);
	}

      res = close (fd);
      if (res < 0)
	{
	  printf (_("Error closing lockfile %s\n"), lockfile);
	  exit(STATE_UNKNOWN);
	}
    }

  free (lockfile);
  return;
}

static int sh_efile_read()
{
  FILE * fp;
  int    fd;
  char   input_buffer[1024];

  int    i;

  char * dummy;
  long   timestamp;
  long   s[

  sh_efile_lock(sh_status_file, 1);

  for (i = 0; i < SH_STATNUM; ++i) sh_status[i] = 0;

  fp = fopen(sh_status_file, "rw");
  if (!fp)
    {
      printf (_("Error opening status file %s\n"), sh_status_file);
      sh_efile_lock(sh_status_file, 0);
      exit(STATE_UNKNOWN);
    }

  while (fgets(input_buffer, sizeof(input_buffer), fp) != NULL)
    {
      if (sscanf(input_buffer, " %s %ld %ld %ld %ld %ld %ld %ld ",
		 dummy, &timestamp, &(s[0]), &(s[1]), &(s[2]), &(s[3]), &(s[4]), &(s[5])) != 8)
	{
	  printf (_("Error: currupt line (%s) in status file %s\n"), input_buffer, sh_status_file);
	  sh_efile_lock(sh_status_file, 0);
	  exit(STATE_UNKNOWN);
	}

      for (i = 0; i < SH_STATNUM; ++i) sh_status[i] += s[i];
    }

  fd = fileno(fp);
  if (fileno < 0)
    {
      printf (_("Error truncating status file %s\n"), sh_status_file);
      sh_efile_lock(sh_status_file, 0);
      exit(STATE_UNKNOWN);
    }
  
  if (ftruncate(fd, 0) < 0)
    {
      printf (_("Error truncating status file %s\n"), sh_status_file);
      sh_efile_lock(sh_status_file, 0);
      exit(STATE_UNKNOWN);
    }
  
  sh_efile_lock(sh_status_file, 0);
}
