/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2001 Rainer Wichmann                                      */
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

#define SH_SYSCALL_CODE


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/mman.h>


#ifdef SH_USE_KERN

#undef  FIL__
#define FIL__  _("sh_kern.c")

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 

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


#include "samhain.h"
#include "sh_pthread.h"
#include "sh_utils.h"
#include "sh_error.h"
#include "sh_modules.h"
#include "sh_kern.h"
#include "sh_ks_xor.h"

#include "sh_unix.h"
#include "sh_hash.h"



sh_rconf sh_kern_table[] = {
  {
    N_("severitykernel"),
    sh_kern_set_severity
  },
  {
    N_("kernelcheckactive"),
    sh_kern_set_activate
  },
  {
    N_("kernelcheckinterval"),
    sh_kern_set_timer
  },
  {
    N_("kernelcheckidt"),
    sh_kern_set_idt
  },
  {
    N_("kernelcheckpci"),
    sh_kern_set_pci
  },
  {
    N_("kernelsystemcall"),
    sh_kern_set_sc_addr
  },
  {
    N_("kernelsyscalltable"),
    sh_kern_set_sct_addr
  },
  {
    N_("kernelprocrootlookup"),
    sh_kern_set_proc_root_lookup
  },
 {
    N_("kernelprocrootiops"),
    sh_kern_set_proc_root_iops
  },
  {
    N_("kernelprocroot"),
    sh_kern_set_proc_root
  },
  {
    NULL,
    NULL
  },
};


static time_t  lastcheck;
static int     ShKernActive   = S_TRUE;
static int     ShKernInterval = 300;
static int     ShKernSeverity = SH_ERR_SEVERE;
static int     ShKernDelay    = 100; /* milliseconds */
static int     ShKernIDT      = S_TRUE;
static int     ShKernPCI      = S_TRUE;

/* The address of system_call
 */
#ifdef SH_SYS_CALL_ADDR
static unsigned long system_call_addr = SH_SYS_CALL_ADDR;
#else
static unsigned long system_call_addr = 0;
#endif

/* The address of the sys_call_table
 */
#ifdef SH_SYS_CALL_TABLE
static unsigned int  kaddr = SH_SYS_CALL_TABLE;
#else
static unsigned int  kaddr = 0;
#endif

#ifdef PROC_ROOT_LOC
static unsigned long proc_root = PROC_ROOT_LOC;
#else
static unsigned long proc_root = 0;
#endif
#ifdef PROC_ROOT_IOPS_LOC
static unsigned long proc_root_iops = PROC_ROOT_IOPS_LOC;
#else
static unsigned long proc_root_iops = 0;
#endif
#ifdef PROC_ROOT_LOOKUP_LOC
static unsigned long proc_root_lookup = PROC_ROOT_LOOKUP_LOC;
#else
static unsigned long proc_root_lookup = 0;
#endif

/* This is the module 'reconfigure' function, which is a no-op.
 */
int sh_kern_null()
{
  return 0;
}

#define SH_KERN_DBPUSH 0
#define SH_KERN_DBPOP  1

char * sh_kern_db_syscall (int num, char * prefix,
		   void * in_name, unsigned long * addr,
			   unsigned int * code1, unsigned int * code2,
			   int * size, int direction)
{
  char            path[128];
  char          * p = NULL;
  unsigned long   x1 = 0, x2 = 0;
  unsigned char * name = (unsigned char *) in_name;

  sl_snprintf(path, 128, "K_%s_%04d", prefix, num);

  if (direction == SH_KERN_DBPUSH) 
    {
      x1 = *code1;
      x2 = *code2;

      sh_hash_push2db (path, *addr, x1, x2,
		       name, (name == NULL) ? 0 : (*size));
    }
  else
    {
      p = sh_hash_db2pop (path, addr,  &x1, &x2, size);
      *code1 = (unsigned int) x1;
      *code2 = (unsigned int) x2;
    }
  return p;
}

static char * sh_kern_pathmsg (char * msg, size_t msg_len,
			       int num, char * prefix,
			       unsigned char * old, size_t old_len,
			       unsigned char * new, size_t new_len)
{
  size_t k;
  char   tmp[128];
  char  *p;
  char  *linkpath_old;
  char  *linkpath_new;
  char   i2h[2];

#ifdef SH_USE_XML
  sl_snprintf(tmp, sizeof(tmp), _("path=\"K_%s_%04d\" "), 
	      prefix, num);
#else
  sl_snprintf(tmp, sizeof(tmp), _("path=<K_%s_%04d> "), 
	      prefix, num);
#endif
  sl_strlcpy(msg, tmp, msg_len);

  if (SL_TRUE == sl_ok_muls(old_len, 2) &&
      SL_TRUE == sl_ok_adds(old_len * 2, 1))
    linkpath_old = SH_ALLOC(old_len * 2 + 1);
  else
    return msg;

  if (SL_TRUE == sl_ok_muls(new_len, 2) &&
      SL_TRUE == sl_ok_adds(new_len * 2, 1))
    linkpath_new = SH_ALLOC(new_len * 2 + 1);
  else
    return msg;

  for (k = 0; k < old_len; ++k)
    {
      p = sh_util_charhex (old[k], i2h);
      linkpath_old[2*k]   = p[0];
      linkpath_old[2*k+1] = p[1];
      linkpath_old[2*k+2] = '\0';
    }

  for (k = 0; k < new_len; ++k)
    {
      p = sh_util_charhex (new[k], i2h);
      linkpath_new[2*k]   = p[0];
      linkpath_new[2*k+1] = p[1];
      linkpath_new[2*k+2] = '\0';
    
}
#ifdef SH_USE_XML
  sl_strlcat(msg, _("link_old=\""),    msg_len);
  sl_strlcat(msg, linkpath_old,        msg_len);
  sl_strlcat(msg, _("\" link_new=\""), msg_len);
  sl_strlcat(msg, linkpath_new,        msg_len);
  sl_strlcat(msg, _("\""),             msg_len);
#else
  sl_strlcat(msg, _("link_old=<"),     msg_len);
  sl_strlcat(msg, linkpath_old,        msg_len);
  sl_strlcat(msg, _(">, link_new=<"),  msg_len);
  sl_strlcat(msg, linkpath_new,        msg_len);
  sl_strlcat(msg, _(">"),              msg_len);
#endif

  SH_FREE(linkpath_old);
  SH_FREE(linkpath_new);

  return msg;
}
 
#ifdef HOST_IS_LINUX

/*
 * Interrupt Descriptor Table
 */
#ifdef HAVE_ASM_SEGMENT_H
#include <asm/segment.h>
#endif

#define SH_MAXIDT   256

static unsigned char sh_idt_table[SH_MAXIDT * 8];

static char * sh_strseg(unsigned short segment)
{
  switch (segment) {
#ifdef __KERNEL_CS
  case __KERNEL_CS:
    return _("KERNEL_CS");
#endif
#ifdef __KERNEL_DS
  case __KERNEL_DS:
    return _("KERNEL_DS");
#endif
#ifdef __USER_CS
  case __USER_CS:
    return _("USER_CS");
#endif
#ifdef __USER_DS
  case __USER_DS:
    return _("USER_DS");
#endif
  default:
    return _("unknown");
  }
}


static int sh_kern_data_init ()
{
  unsigned long store0 = 0;
  unsigned int  store1 = 0, store2 = 0;
  int           datasize, i, j;
  char        * databuf;

  /* system_call code
   */
  databuf = sh_kern_db_syscall (0, _("system_call"), 
				NULL, &store0, &store1, &store2,
				&datasize, SH_KERN_DBPOP);
  if (datasize == sizeof(system_call_code))
    {
      memcpy (system_call_code, databuf, sizeof(system_call_code));
      SH_FREE(databuf);
    }
  else
    {
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("system_call_code not found in database"), 
		      _("sh_kern_data_init"));
      return -1;
    }

  /* syscall address and code
   */ 
  for (i = 0; i < SH_MAXCALLS; ++i) 
    {
      databuf = sh_kern_db_syscall (i, _("syscall"), 
				    NULL, &store0, &store1, &store2,
				    &datasize, SH_KERN_DBPOP);
      sh_syscalls[i].addr = store0;
      if (store0 == 0) {
	sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, i, MSG_E_SUBGEN,
			_("syscall address not found in database"), 
			_("sh_kern_data_init"));
	return -1;
      }

      sh_syscalls[i].code[0] = (unsigned int) store1; 
      sh_syscalls[i].code[1] = (unsigned int) store2;
      if ((store1 == 0) || (store2 == 0)) {
	sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, i, MSG_E_SUBGEN,
			_("syscall code not found in database"), 
			_("sh_kern_data_init"));
      }

      if (databuf != NULL) {
	SH_FREE(databuf);
      }
      
    }

  if (ShKernIDT == S_TRUE)
    {
      for (j = 0; j < SH_MAXIDT; ++j) 
	{
	  databuf = sh_kern_db_syscall (j, _("idt_table"), 
					NULL, 
					&store0, &store1, &store2,
					&datasize, SH_KERN_DBPOP);
	  if (datasize == 8) {
	    memcpy(&idt_table[j*8], databuf, 8);
	    SH_FREE(databuf);
	  } else {
	    sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, j, MSG_E_SUBGEN,
			    _("idt table not found in database"), 
			    _("sh_kern_data_init"));
	    return -1;
	  }
	}
    }

  return 0;
}


/*
 * Defined in include/linux/fs.h
 */

/* Here. we are only interested in 'lookup'. I.e. the struct
 * must be <= the real one, and 'lookup' must be at the 
 * correct position.
 */
struct inode_operations {
  int (*create) (int *,int *,int);
  int * (*lookup) (int *,int *);
  int (*link) (int *,int *,int *);
  int (*unlink) (int *,int *);
  int (*symlink) (int *,int *,const char *);
  int (*mkdir) (int *,int *,int);
  int (*rmdir) (int *,int *);
  int (*mknod) (int *,int *,int,int);
  int (*rename) (int *, int *,
                 int *, int *);
  /* flawfinder: ignore */
  int (*readlink) (int *, char *,int);
  int (*follow_link) (int *, int *);
  void (*truncate) (int *);
  int (*permission) (int *, int);
  int (*revalidate) (int *);
  /*
    int (*setattr) (int *, int *);
    int (*getattr) (int *, int *);
    int (*setxattr) (int *, const char *, void *, size_t, int);
    ssize_t (*getxattr) (int *, const char *, void *, size_t);
    ssize_t (*listxattr) (int *, char *, size_t);
    int (*removexattr) (int *, const char *);
  */
};

/* 
 * this one is just for dummy purposes
 */
struct file_operations {
  int (*create) (int *,int *,int);
};

/* Defined in include/linux/proc_fs.h
 * Here we are interested in the 'proc_iops' member.
 */
struct proc_dir_entry {
  unsigned short low_ino;
  unsigned short namelen;
  const char * name;
  mode_t mode;
  nlink_t nlink;
  uid_t uid;
  gid_t gid;
#if defined  TWO_SIX_SEVENTEEN_PLUS
  /* size is loff_t in 2.6.17+ kernels */
  unsigned long dummy; 
#endif
  unsigned long size;
  struct inode_operations * proc_iops;
  struct file_operations * proc_fops;
  /*
  get_info_t *get_info;
  struct module *owner;
  struct proc_dir_entry *next, *parent, *subdir;
  void *data;
  read_proc_t *read_proc;
  write_proc_t *write_proc;
  atomic_t count;         
  int deleted;  
  */          
};


static int sh_kern_kmem_read (int fd, unsigned long addr, 
			      unsigned char * buf, int len)
{
  if (lseek(fd, addr, SEEK_SET) == (off_t) (-1))
    {
      return -1;
    }
  if (read(fd, buf, len) < 0)
    {
      return -1;
    }
  return 0;
}

static int sh_kern_read_data (int fd, unsigned long addr, 
			      unsigned char * buf, size_t len)
{
  size_t    moff, roff;
  size_t    sz;
  char    * kmap;

  /* first, try read()
   */
  if (0 == sh_kern_kmem_read (fd, addr, buf, len))
    return 0;

  /* next, try mmap()
   */
  sz = getpagesize(); /* unistd.h */

  moff = ((size_t)(addr/sz)) * sz;                 /* lower page boundary */
  roff = addr - moff;    /* off relative to lower address of mmapped area */

  kmap = mmap(0, len+sz, PROT_READ, MAP_PRIVATE, fd, moff);/* sys/mman.h */

  if (kmap == MAP_FAILED)
    {
      memset(buf, '\0', len);
      return -1;
    }
  memcpy (buf, &kmap[roff], len);
  return munmap(kmap, len+sz);
}


static int check_init (int * init_retval)
{
  static int is_init = 0;

  SL_ENTER(_("check_init"));

  if (is_init == 0)
    {
      if (sh.flag.checkSum != SH_CHECK_INIT && sh.flag.update != S_TRUE)
	{
	  if (0 == sh_kern_data_init()) {
	    is_init = 1;
	  } else {
	    sh_error_handle (ShKernSeverity, FIL__, __LINE__, 1, 
			     MSG_E_SUBGEN,
			     _("could not initialize kernel check - switching off"),
			     _("check_init") );
	    ShKernActive = S_FALSE;
	    *init_retval = is_init;
	    SL_RETURN( (-1), _("check_init"));
	  }
	}
      else if ((sh.flag.checkSum == SH_CHECK_INIT || 
		sh.flag.checkSum == SH_CHECK_CHECK) && 
	       (sh.flag.update == S_TRUE))
	{
	  if (0 == sh_kern_data_init()) {
	    is_init = 1;
	  } else {
	    sh_error_handle (SH_ERR_WARN, FIL__, __LINE__, 0, 
			     MSG_E_SUBGEN,
			     _("no or incomplete data in baseline database for kernel check"),
			     _("check_init") );
	  }
	}
    }
  *init_retval = is_init;
  SL_RETURN( (0), _("check_init"));
}

#define SH_KERN_SIZ 512
#define SH_KERN_SCC 256

static void run_child(int kd, int mpipe[2])
{
  int j;

  unsigned long kmem_call_table[SH_KERN_SIZ];
  unsigned int  kmem_code_table[SH_KERN_SIZ][2];

  unsigned char  buf[6];
  unsigned short idt_size;
  unsigned long  idt_addr;

  unsigned char new_system_call_code[SH_KERN_SCC];

  struct inode_operations proc_root_inode;
  struct proc_dir_entry   proc_root_dir;

  int status = sl_close_fd(FIL__, __LINE__, mpipe[0]);

  setpgid(0, 0);
	  
  /* Seek to the system call table (at kaddr) and read it into
   * the kmem_call_table array
   */
  if(status == 0)
    {
      retry_msleep (0, ShKernDelay); /* milliseconds */
      
      if (sh_kern_read_data (kd, kaddr, 
			     (unsigned char *) &kmem_call_table, 
			     sizeof(kmem_call_table)))
	{
	  status = -2;
	}
    }

  /* 
   * Seek to the system call address (at sh_syscalls[j].addr) and 
   * read first 8 bytes into the array kmem_code_table[j][] (2 * unsigned int)
   */
  if(status == 0)
    {
      memset(kmem_code_table, 0, sizeof(kmem_code_table));
      for (j = 0; j < SH_MAXCALLS; ++j) 
	{
	  if (sh_syscalls[j].addr == 0UL) {
	    sh_syscalls[j].addr = kmem_call_table[j];
	  }

	  if (sh_syscalls[j].name == NULL || 
	      sh_syscalls[j].addr == 0UL)
	    break;

	  if ((sh.flag.checkSum == SH_CHECK_INIT || 
	       sh.flag.checkSum == SH_CHECK_CHECK) && 
	      (sh.flag.update == S_TRUE))
	    {
	      if (sh_kern_read_data (kd, kmem_call_table[j], 
				     (unsigned char *) &(kmem_code_table[j][0]),
				     2 * sizeof(unsigned int)))
		status = -3;
	    }
	  else
	    {
	      if (sh_kern_read_data (kd, sh_syscalls[j].addr, 
				     (unsigned char *) &(kmem_code_table[j][0]),
				     2 * sizeof(unsigned int)))
		status = -4;
	    }
	}
    }

  if(status == 0)
    {
      /* 
       * Get the address and size of Interrupt Descriptor Table,
       * and read the content into the global array sh_idt_table[]
       */
      __asm__ volatile ("sidt %0": "=m" (buf));
      idt_size = *((unsigned short *) &buf[0]);
      idt_addr = *((unsigned long *)  &buf[2]);
      idt_size = (idt_size + 1)/8;
      
      if (idt_size > SH_MAXIDT)
	idt_size = SH_MAXIDT;
      
      memset(sh_idt_table, '\0', SH_MAXIDT*8);
      if (sh_kern_read_data (kd, idt_addr, 
			     (unsigned char *) sh_idt_table, idt_size*8))
	status = -5;
    }

  /* 
   * Seek to the system_call address (at system_call_addr) and 
   * read first 256 bytes into new_system_call_code[]
   *
   * system_call_addr is defined in the include file.
   */
  if(status == 0)
    {
      if (sh_kern_read_data (kd, system_call_addr, 
			     (unsigned char *) new_system_call_code, 
			     SH_KERN_SCC))
	status = -6;
    }
  
  /* 
   * Seek to proc_root and read the structure.
   * Seek to proc_root_inode_operations and get the structure.
   */
  if(status == 0)
    {
      if (sh_kern_read_data (kd, proc_root, 
			     (unsigned char *) &proc_root_dir, 
			     sizeof(proc_root_dir)))
	status = -7;
      if (sh_kern_read_data (kd, proc_root_iops, 
			     (unsigned char *) &proc_root_inode, 
			     sizeof(proc_root_inode)))
	status = -8;
    }
  
  /*
   * Write out data to the pipe
   */
  status = write(mpipe[1], &status, sizeof(int));

  if (status > 0)
    status = write(mpipe[1], &kmem_call_table, sizeof(kmem_call_table));
  
  if(status > 0)
    status = write(mpipe[1], &kmem_code_table, sizeof(kmem_code_table));
  
  if(status > 0)
    status = write(mpipe[1], &sh_idt_table, sizeof(sh_idt_table));
  
  if(status > 0)
    status = write(mpipe[1], new_system_call_code, SH_KERN_SCC);
  
  if(status > 0)
    status = write(mpipe[1], &proc_root_dir, sizeof(proc_root_dir));
  
  if(status > 0)
    status = write(mpipe[1], &proc_root_inode, sizeof(proc_root_inode));

  _exit( (status >= 0) ? 0 : status);
}

struct sh_kernel_info {
  unsigned long kmem_call_table[SH_KERN_SIZ];
  unsigned int  kmem_code_table[SH_KERN_SIZ][2];

  unsigned char new_system_call_code[SH_KERN_SCC];

  struct inode_operations proc_root_inode;
  struct proc_dir_entry   proc_root_dir;
};

static int read_from_child(pid_t mpid, int * mpipe, 
			   struct sh_kernel_info * kinfo)
{
  int  res;
  int  status;
  long size;
  int  errcode;

  /* Close reading side of pipe, and wait some milliseconds
   */
  sl_close_fd (FIL__, __LINE__, mpipe[1]);
  retry_msleep (0, ShKernDelay); /* milliseconds */

  if (sizeof(int) != read(mpipe[0], &errcode, sizeof(int)))
    status = -3;
  else
    status = 0;

  if (errcode)
    status = errcode - 100;

  if(status == 0)
    {
      size = SH_KERN_SIZ * sizeof(unsigned long);

      if (size != read(mpipe[0], &(kinfo->kmem_call_table), size))
	status = -4;
      else
	status = 0;
    }

  if(status == 0)
    {
      size = sizeof(unsigned int) * 2 * SH_KERN_SIZ;

      if (size != read(mpipe[0], &(kinfo->kmem_code_table), size))
	status = -5;
      else
	status = 0;
    }

  if(status == 0)
    {
      memset(sh_idt_table, '\0', SH_MAXIDT*8);
      if (sizeof(sh_idt_table) != 
	  read(mpipe[0], &sh_idt_table, sizeof(sh_idt_table)))
	status = -5;
      else
	status = 0;
    }

  if(status == 0)
    {
      size = SH_KERN_SCC;

      if (size != read(mpipe[0], &(kinfo->new_system_call_code), size))
	status = -6;
      else
	status = 0;
    }
  
  if(status == 0)
    {
      size = sizeof (struct proc_dir_entry);

      if (size != read(mpipe[0], &(kinfo->proc_root_dir), size))
	status = -7;
      else
	status = 0;
    }

  if(status == 0)
    {
      size = sizeof (struct inode_operations);

      if (size != read(mpipe[0], &(kinfo->proc_root_inode), size))
	status = -8;
      else
	status = 0;
    }

  if (status < 0)
    res = waitpid(mpid, NULL,    WNOHANG|WUNTRACED);
  else 
    {
      res = waitpid(mpid, &status, WNOHANG|WUNTRACED);
      if (res == 0 && 0 != WIFEXITED(status))
	status = WEXITSTATUS(status);
    }
  sl_close_fd (FIL__, __LINE__, mpipe[0]);
  if (res <= 0)
    {
      aud_kill(FIL__, __LINE__, mpid, 9);
      waitpid(mpid, NULL, 0);
    }
  return status;
}


static void check_idt_table(int is_init)
{
  int            i, j;

  unsigned short idt_offset_lo, idt_offset_hi, idt_selector;
  unsigned char  idt_reserved, idt_flag;
  unsigned short sh_idt_offset_lo, sh_idt_offset_hi, sh_idt_selector;
  unsigned char  sh_idt_reserved, sh_idt_flag;
  int            dpl;
  unsigned long  idt_iaddr;
  int            sh_dpl;
  unsigned long  sh_idt_iaddr;
  char           idt_type, sh_idt_type;

  unsigned long store0;
  unsigned int  store1, store2;
  int           datasize;
  char          msg[2*SH_BUFSIZE];

  if (ShKernIDT == S_TRUE)
    {
      if (sh.flag.checkSum == SH_CHECK_INIT || sh.flag.update == S_TRUE)
	{
	  datasize = 8;
	  for (j = 0; j < SH_MAXIDT; ++j) 
	    {
	      sh_kern_db_syscall (j, _("idt_table"), 
				  &sh_idt_table[j*8], 
				  &store0, &store1, &store2,
				  &datasize, SH_KERN_DBPUSH);
	    }
	}

      if ((sh.flag.checkSum != SH_CHECK_INIT) || 
	  (sh.flag.update == S_TRUE && is_init == 1))
	{
	  /* Check the Interrupt Descriptor Table
	   *
	   * Stored(old) is idt_table[]
	   */
	  for (j = 0; j < SH_MAXIDT; ++j)
	    {
	      i = j * 8;
	  
	      sh_idt_offset_lo = *((unsigned short *) &sh_idt_table[i]);
	      sh_idt_selector  = *((unsigned short *) &sh_idt_table[i+2]);
	      sh_idt_reserved  = (unsigned char) sh_idt_table[i+4];
	      sh_idt_flag      = (unsigned char) sh_idt_table[i+5];
	      sh_idt_offset_hi = *((unsigned short *) &sh_idt_table[i+6]);
	      sh_idt_iaddr = (unsigned long)(sh_idt_offset_hi << 16) 
		+ sh_idt_offset_lo;
	      
	      if (sh_idt_iaddr == 0)
		{
		  sh_idt_table[i+2] = '\0';
		  sh_idt_table[i+3] = '\0';
		  sh_idt_table[i+5] = '\0';

		  idt_offset_lo = *((unsigned short *) &idt_table[i]);
		  idt_offset_hi = *((unsigned short *) &idt_table[i+6]);
		  idt_iaddr = (unsigned long)(idt_offset_hi << 16) 
		    + idt_offset_lo;
		  if (idt_iaddr == 0)
		    {
		      idt_table[i+2] = '\0';
		      idt_table[i+3] = '\0';
		      idt_table[i+5] = '\0';
		    }
		  
		}
	  
	      if (memcmp(&sh_idt_table[i], &idt_table[i], 8) != 0)
		{
		  
		  idt_offset_lo = *((unsigned short *) &idt_table[i]);
		  idt_selector  = *((unsigned short *) &idt_table[i+2]);
		  idt_reserved  = (unsigned char) idt_table[i+4];
		  idt_flag      = (unsigned char) idt_table[i+5];
		  idt_offset_hi = *((unsigned short *) &idt_table[i+6]);
		  idt_iaddr = (unsigned long)(idt_offset_hi << 16) 
		    + idt_offset_lo;
	      
		  if (idt_iaddr != 0)
		    {
		      if (idt_flag & 64) { dpl = 3; }
		      else               { dpl = 0; }
		      if (idt_flag & 1)  { 
			if (dpl == 3) idt_type = 'S'; 
			else idt_type = 'T'; }
		      else               { idt_type = 'I'; }
		    }
		  else { dpl = -1; idt_type = 'U'; }
		  
		  if (sh_idt_iaddr != 0)
		    {
		      if (sh_idt_flag & 64) { sh_dpl = 3; }
		      else               { sh_dpl = 0; }
		      if (sh_idt_flag & 1)  { 
			if (sh_dpl == 3) sh_idt_type = 'S'; 
			else sh_idt_type = 'T'; }
		      else               { sh_idt_type = 'I'; }
		    }
		  else { sh_dpl = -1; sh_idt_type = 'U'; }
		  
		  sh_kern_pathmsg (msg, SH_BUFSIZE,
				   j, _("idt_table"),
				   &idt_table[i], 8,
				   &sh_idt_table[i], 8);

		  sh_error_handle (ShKernSeverity, FIL__, __LINE__, 
				   0, MSG_KERN_IDT,
				   j, 
				   sh_idt_iaddr, sh_strseg(sh_idt_selector), 
				   (int) sh_dpl, sh_idt_type, 
				   idt_iaddr, sh_strseg(idt_selector),
				   (int) dpl, idt_type, msg);
		  
		  memcpy(&idt_table[i], &sh_idt_table[i], 8);
		}
	    }
	}
    }
}


#define SYS_BUS_PCI _("/sys/bus/pci/devices")
#include <dirent.h>

static void check_rom (char * pcipath, char * name)
{
  file_type       theFile;
  char            fileHash[2*(KEY_LEN + 1)];
  int             status;
  char          * tmp;
  extern unsigned long sh_files_maskof (int class);

  (void) sl_strlcpy (theFile.fullpath, pcipath, PATH_MAX);
  theFile.check_mask  = sh_files_maskof(SH_LEVEL_READONLY);
  theFile.check_mask &= ~(MODI_MTM|MODI_CTM|MODI_INO);
  CLEAR_SH_FFLAG_REPORTED(theFile.file_reported);
  theFile.attr_string = NULL;
  theFile.link_path   = NULL;
  
  status = sh_unix_getinfo (ShDFLevel[SH_ERR_T_RO], 
			    name, &theFile, fileHash, 0);

  if (status != 0)
    {
      tmp = sh_util_safe_name(pcipath);
      sh_error_handle (ShKernSeverity, FIL__, __LINE__, 
		       0, MSG_E_SUBGPATH,
		       _("Could not check PCI ROM"),
		       _("check_rom"),
		       tmp);
      SH_FREE(tmp);
      goto out;
    }

  if ( sh.flag.checkSum == SH_CHECK_INIT ) 
    {
      sh_hash_pushdata (&theFile, fileHash);
    }
  else if (sh.flag.checkSum == SH_CHECK_CHECK ) 
    {
      sh_hash_compdata (SH_LEVEL_READONLY, &theFile, fileHash, NULL, -1);
    }

 out:
  if (theFile.attr_string) SH_FREE(theFile.attr_string);
  if (theFile.link_path)   SH_FREE(theFile.link_path);
  return;
}

static void check_pci_rom (char * pcipath, char * name)
{
  struct stat buf;
  int         fd;
  int         status;

  if (0 == stat(pcipath, &buf))
    {
      /* Need to write "1" to the file to enable the ROM. Afterwards,
       * write "0" to disable it.
       */
      fd = open ( pcipath, O_RDWR );
      if (fd)
	{
	  do {
	    status = write( fd, "1", 1 );
	  } while (status < 0 && errno == EINTR);
	  sl_close_fd (FIL__, __LINE__,  fd );

	  if (status > 0)
	    {
	      check_rom(pcipath, name);
	      
	      fd = open ( pcipath, O_RDWR );
	      if (fd)
		{
		  do {
		    status = write( fd, "0", 1 );
		  } while (status < 0 && errno == EINTR);
		  sl_close_fd (FIL__, __LINE__,  fd );
		}
	    }
	}
    }
  return;
}

static void check_pci()
{
  char pci_dir[256];
  char * pcipath;
  DIR * df;
  struct dirent * entry;

  if (ShKernPCI != S_TRUE)
    return;

  sl_strlcpy(pci_dir, SYS_BUS_PCI, sizeof(pci_dir));

  df = opendir(pci_dir);
  if (df)
    {
      while (1)
	{
	  SH_MUTEX_LOCK(mutex_readdir);
	  entry = readdir(df);
	  SH_MUTEX_UNLOCK(mutex_readdir);

	  if (entry == NULL)
	    break;

	  if (0 == strcmp(entry->d_name, ".") && 
	      0 == strcmp(entry->d_name, ".."))
	    continue;

	  pcipath = sh_util_strconcat(pci_dir, "/", 
				      entry->d_name, "/rom", NULL);
	  check_pci_rom(pcipath, entry->d_name);
	  SH_FREE(pcipath);
	}

      closedir(df);
    }
  return;
}

/* -- Check the proc_root inode.
 *
 * This will detect adore-ng.
 */
static void check_proc_root (struct sh_kernel_info * kinfo)
{
  struct proc_dir_entry   proc_root_dir;

/* 2.6.21 (((2) << 16) + ((6) << 8) + (21)) */
#if SH_KERNEL_NUMBER < 132629
  struct inode_operations proc_root_inode;

  memcpy (&proc_root_inode, &(kinfo->proc_root_inode), sizeof(struct inode_operations));

  /* Seems that the info does not relate anymore to proc_root_lookup(?)
   */
  if ( (unsigned int) *proc_root_inode.lookup != proc_root_lookup)
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_KERN_PROC,
		       _("proc_root_inode_operations.lookup != proc_root_lookup"));
    }
#endif

  memcpy (&proc_root_dir,   &(kinfo->proc_root_dir),   sizeof(struct proc_dir_entry));
  if (    (((unsigned int) * &proc_root_dir.proc_iops) != proc_root_iops)
	    && (proc_root_dir.size != proc_root_iops)
	    && (((unsigned int) * &proc_root_dir.proc_fops) != proc_root_iops)
	    )
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_KERN_PROC,
		       _("proc_root.proc_iops != proc_root_inode_operations"));
    }

  return;
}

/* -- Check the system_call syscall gate.
 *
 * Stored(old) is system_call_code[]
 */
static void check_syscall_gate(int is_init, struct sh_kernel_info * kinfo)
{
  int           i, j;
  unsigned long store0;
  unsigned int  store1, store2;
  int           datasize;
  int           max_system_call = (SYS_CALL_LOC < 128) ? 128 : SYS_CALL_LOC;
  char          msg[2*SH_BUFSIZE];
  
  if (sh.flag.checkSum == SH_CHECK_INIT || sh.flag.update == S_TRUE)
    {
      store0 = 0; store1 = 0; store2 = 0;
      datasize = SH_KERN_SCC;
      sh_kern_db_syscall (0, _("system_call"), 
			  &(kinfo->new_system_call_code), &store0, &store1, &store2,
			  &datasize, SH_KERN_DBPUSH);
    }

  if ((sh.flag.checkSum != SH_CHECK_INIT) || 
      (sh.flag.update == S_TRUE && is_init == 1))
    {
      for (i = 0; i < (max_system_call + 4); ++i) 
	{
	  if (system_call_code[i] != kinfo->new_system_call_code[i])
	    {

	      sh_kern_pathmsg (msg, sizeof(msg),
			       0, _("system_call"),
			       system_call_code, SH_KERN_SCC,
			       kinfo->new_system_call_code, SH_KERN_SCC);

	      sh_error_handle (ShKernSeverity, FIL__, __LINE__, 
			       0, MSG_KERN_GATE,
			       kinfo->new_system_call_code[i], 0,
			       system_call_code[i], 0,
			       0, _("system_call (interrupt handler)"),
			       msg);
	      
	      for (j = 0; j < (max_system_call + 4); ++j)
		system_call_code[j] = kinfo->new_system_call_code[j];
	      break;
	    }
	}
    }
  return;
}

static void check_system_calls (int is_init, struct sh_kernel_info * kinfo)
{
  int           i;

#ifdef SH_USE_LKM
  static int check_getdents      = 0;
  /* #ifdef __NR_getdents64 */
  static int check_getdents64    = 0;
  /* #endif */
  static int copy_if_next        = -1;
  static int copy_if_next_64     = -1;
#endif

  unsigned long store0;
  unsigned int  store1, store2;
  int           mod_syscall_addr = 0;
  int           mod_syscall_code = 0;
  UINT64        size_old  = 0, size_new = 0;
  UINT64        mtime_old = 0, mtime_new = 0;
  UINT64        ctime_old = 0, ctime_new = 0;
  char          tmp[128];
  char          msg[2*SH_BUFSIZE];
  char timstr_o[32];
  char timstr_n[32];

  if (sh.flag.checkSum == SH_CHECK_INIT || sh.flag.update == S_TRUE)
    {
      for (i = 0; i < SH_MAXCALLS; ++i) 
	{
	  store0 = kinfo->kmem_call_table[i]; 
	  store1 = kinfo->kmem_code_table[i][0]; store2 = kinfo->kmem_code_table[i][1];
	  sh_kern_db_syscall (i, _("syscall"), 
			      NULL, &store0, &store1, &store2,
			      0, SH_KERN_DBPUSH);
	}
    }

  if ((sh.flag.checkSum != SH_CHECK_INIT) || 
      (sh.flag.update == S_TRUE && is_init == 1))
    {
      for (i = 0; i < SH_MAXCALLS; ++i) 
	{
	  if (sh_syscalls[i].name == NULL /* || sh_syscalls[i].addr == 0UL */)
	    break;

#ifdef SH_USE_LKM
	  if (sh_syscalls[i].addr != kinfo->kmem_call_table[i])
	    {
	      if (check_getdents == 0 && 
		  0 == strcmp(_(sh_syscalls[i].name), _("sys_getdents")))
		{
		  check_getdents = 1;
		  sh_error_handle (SH_ERR_WARN, FIL__, __LINE__, 
				   0, MSG_E_SUBGEN,
				   _("Modified kernel syscall (expected)."),
				   _(sh_syscalls[i].name) );
		  copy_if_next = i;
		  sh_syscalls[i].addr = kinfo->kmem_call_table[i];
		  continue;
		}
	      /* #ifdef __NR_getdents64 */
	      else if  (check_getdents64 == 0 && 
			0 == strcmp(_(sh_syscalls[i].name), 
				    _("sys_getdents64")))
		{
		  check_getdents64 = 1;
		  sh_error_handle (SH_ERR_WARN, FIL__, __LINE__, 
				   0, MSG_E_SUBGEN,
				   _("Modified kernel syscall (expected)."),
				   _(sh_syscalls[i].name) );
		  copy_if_next_64 = i;
		  sh_syscalls[i].addr = kinfo->kmem_call_table[i];
		  continue;
		}
	      /* #endif */
	      else
		{
		  size_old = sh_syscalls[i].addr;
		  size_new = kinfo->kmem_call_table[i];
		  mod_syscall_addr = 1;
		}
	      sh_syscalls[i].addr = kinfo->kmem_call_table[i];
	    }
#else
	  if (sh_syscalls[i].addr != kinfo->kmem_call_table[i])
	    {
	      size_old = sh_syscalls[i].addr;
	      size_new = kinfo->kmem_call_table[i];
	      mod_syscall_addr = 1;
	      sh_syscalls[i].addr = kinfo->kmem_call_table[i];
	    }
#endif


	  /* -- Check the code at syscall address
	   *
	   * Stored(old) is sh_syscalls[]
	   */
	  if ( (mod_syscall_addr == 0) && 
	       ((sh_syscalls[i].code[0] != kinfo->kmem_code_table[i][0]) || 
		(sh_syscalls[i].code[1] != kinfo->kmem_code_table[i][1]))
	       )
	    {
	      mtime_old = sh_syscalls[i].code[0];
	      mtime_new = kinfo->kmem_code_table[i][0];
	      ctime_old = sh_syscalls[i].code[1];
	      ctime_new = kinfo->kmem_code_table[i][1];
	      mod_syscall_code = 1;

#ifdef SH_USE_LKM
	      if (i == copy_if_next)
		{
		  mod_syscall_code =  0;
		  copy_if_next     = -1;
		}
	      if (i == copy_if_next_64)
		{
		  mod_syscall_code =  0;
		  copy_if_next_64  = -1;
		}
#endif

	      sh_syscalls[i].code[0] = kinfo->kmem_code_table[i][0];
	      sh_syscalls[i].code[1] = kinfo->kmem_code_table[i][1];
	    }

	  /* Build the error message, if something has been
	   * detected.
	   */
	  if ((mod_syscall_addr != 0) || (mod_syscall_code != 0))
	    {
#ifdef SH_USE_XML
	      sl_snprintf(tmp, 128, "path=\"K_%s_%04d\" ", 
			  _("syscall"), i);
#else
	      sl_snprintf(tmp, 128, "path=<K_%s_%04d>, ", 
			  _("syscall"), i);
#endif
	      sl_strlcpy(msg, tmp, SH_BUFSIZE);

	      if (mod_syscall_addr != 0)
		{
		  sl_snprintf(tmp, 128, sh_hash_size_format(),
			      size_old, size_new);
		  sl_strlcat(msg, tmp, SH_BUFSIZE); 
		}
	      if (mod_syscall_code != 0)
		{
		  (void) sh_unix_gmttime (ctime_old, timstr_o, sizeof(timstr_o));
		  (void) sh_unix_gmttime (ctime_new, timstr_n, sizeof(timstr_n));
#ifdef SH_USE_XML
		  sl_snprintf(tmp, 128, 
			      _("ctime_old=\"%s\" ctime_new=\"%s\" "), 
			      timstr_o, timstr_n);
#else
		  sl_snprintf(tmp, 128, 
			      _("ctime_old=<%s>, ctime_new=<%s>, "), 
			      timstr_o, timstr_n);
#endif
		  sl_strlcat(msg, tmp, SH_BUFSIZE); 
		  (void) sh_unix_gmttime (mtime_old, timstr_o, sizeof(timstr_o));
		  (void) sh_unix_gmttime (mtime_new, timstr_n, sizeof(timstr_n));
#ifdef SH_USE_XML
		  sl_snprintf(tmp, 128, 
			      _("mtime_old=\"%s\" mtime_new=\"%s\" "), 
			      timstr_o, timstr_n);
#else
		  sl_snprintf(tmp, 128, 
			      _("mtime_old=<%s>, mtime_new=<%s> "), 
			      timstr_o, timstr_n);
#endif
		  sl_strlcat(msg, tmp, SH_BUFSIZE); 
		}
	      sh_error_handle (ShKernSeverity, FIL__, __LINE__, 
			       0, MSG_KERN_SYSCALL,
			       i, _(sh_syscalls[i].name), msg);
	      mod_syscall_addr = 0;
	      mod_syscall_code = 0;
	    }
	}
    }
  return;
}
 
int sh_kern_check_internal ()
{
  int kd;
  int is_init;
  pid_t mpid;
  int mpipe[2];
  int status = 0;

  struct sh_kernel_info kinfo;


  SL_ENTER(_("sh_kern_check_internal"));

  /* -- Check whether initialisation is required; if yes, initialize.
   */

  if (0 != check_init(&is_init))
    {
      SL_RETURN( (-1), _("sh_kern_check_internal"));
    }


  /* -- Open /dev/kmem and fork subprocess to read from it.
   */
   
  if (kaddr == (unsigned int) -1) /* kaddr = address of the sys_call_table */
    {
      sh_error_handle (ShKernSeverity, FIL__, __LINE__, status, MSG_E_SUBGEN,
		       _("no address for sys_call_table - switching off"),
		       _("kern_check_internal") );
      ShKernActive = S_FALSE;
      SL_RETURN( (-1), _("sh_kern_check_internal"));
    }
  
  kd = aud_open(FIL__, __LINE__, SL_YESPRIV, _("/dev/kmem"), O_RDONLY, 0);
  
  if (kd < 0)
    {
      status = errno;
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
		       _("error opening /dev/kmem"),
		       _("kern_check_internal") );
      SL_RETURN( (-1), _("sh_kern_check_internal"));
    }

  status = aud_pipe(FIL__, __LINE__, mpipe);

  if (status == 0)
    {
      mpid = aud_fork(FIL__, __LINE__);

      switch (mpid) 
	{
	case -1:
	  status = -1;
	  break;
	case 0: 

	  /* -- Child process reads /dev/kmem and writes to pipe
	   */
	  run_child(kd, mpipe);
	  break;
	  
	  /* -- Parent process reads from child via pipe
	   */
	default:
	  sl_close_fd(FIL__, __LINE__, kd);
	  status = read_from_child(mpid, mpipe, &kinfo);
	  break;
	}
    }

  if ( status < 0)
    {
      char errmsg[SH_ERRBUF_SIZE];
      sl_snprintf(errmsg, SH_ERRBUF_SIZE, 
		  _("error reading from /dev/kmem: %d"), status);
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
		       errmsg,
		       _("kern_check_internal") );
      SL_RETURN( (-1), _("sh_kern_check_internal"));
    }

  /* -- Check the proc_root inode.
   *
   * This will detect adore-ng.
   */
  check_proc_root( &kinfo );


  /* -- Check the system_call syscall gate.
   *
   * Stored(old) is system_call_code[]
   */
  check_syscall_gate( is_init, &kinfo );

  /* -- Check the individual syscalls
   *
   * Stored(old) is sh_syscalls[] array.
   */
  check_system_calls ( is_init, &kinfo );

  /* -- Check the Interrupt Descriptor Table
   */
  check_idt_table(is_init);

  /* -- Check PCI ROM
   */
  check_pci();

  SL_RETURN( (0), _("sh_kern_check_internal"));
}
/* ifdef HOST_IS_LINUX */
#else

/********************************************************
 *
 *  --- BSD ---
 *
 ********************************************************/

#include <err.h>
#include <kvm.h>
#include <nlist.h>

/* not OpenBSD */
#if defined(HOST_IS_FREEBSD)
#include <sys/sysent.h>
#endif

#include <sys/syscall.h>
#ifndef  SYS_MAXSYSCALL
#define  SYS_MAXSYSCALL	512
#endif

#ifdef __OpenBSD__
struct proc;
struct sysent {
	short sy_narg;
	short sy_argsize;
	int   (*sy_call)(struct proc *, void *, register_t *);
};
#endif

int sh_kern_data_init ()
{
  unsigned long store0 = 0;
  unsigned int  store1 = 0, store2 = 0;
  int           datasize, i;
  char        * databuf = NULL;

  /* syscall address and code
   */ 
  for (i = 0; i < SH_MAXCALLS; ++i) 
    {
      databuf = sh_kern_db_syscall (i, _("syscall"), 
				    NULL, &store0, &store1, &store2,
				    &datasize, SH_KERN_DBPOP);
      sh_syscalls[i].addr = store0;
      if (databuf != NULL) { SH_FREE(databuf); }
      if (store0 == 0) {
	sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			_("syscall address not found in database"), 
			_("sh_kern_data_init"));
	return -1;
      }

      sh_syscalls[i].code[0] = (unsigned int) store1; 
      sh_syscalls[i].code[1] = (unsigned int) store2;
      if ((store1 == 0) || (store2 == 0)) {
	sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			_("syscall code not found in database"), 
			_("sh_kern_data_init"));
	return -1;
      }

    }

  return 0;
}

int sh_kern_check_internal ()
{
  struct sysent  sy;
  kvm_t * kd;
  int     i;
  int     status = -1;
  char    errbuf[_POSIX2_LINE_MAX+1];
  struct  nlist * sys_list;
  struct  nlist list[2];

  unsigned long offset = 0L;
  unsigned int  syscall_code[2];  /* 8 bytes */
  unsigned long syscall_addr;

  unsigned long store0 = 0;
  unsigned int  store1 = 0, store2 = 0;

  UINT64        size_old  = 0, size_new = 0;
  UINT64        mtime_old = 0, mtime_new = 0;
  UINT64        ctime_old = 0, ctime_new = 0;
  char          tmp[128];
  char          msg[2*SH_BUFSIZE];
  char timstr_o[32];
  char timstr_n[32];

  static int is_init = 0;

  SL_ENTER(_("sh_kern_check_internal"));

  if (is_init == 0)
    { 
      if (sh.flag.checkSum != SH_CHECK_INIT && sh.flag.update != S_TRUE)
	{
	  if (0 == sh_kern_data_init()) {
	    is_init = 1;
	  } else {
	    sh_error_handle (ShKernSeverity, FIL__, __LINE__, status, 
			     MSG_E_SUBGEN,
			     _("could not initialize - switching off"),
			     _("kern_check_internal") );
	    ShKernActive = S_FALSE;
	    SL_RETURN( (-1), _("sh_kern_check_internal"));
	  }
	}
      else if ((sh.flag.checkSum == SH_CHECK_INIT ||
		sh.flag.checkSum == SH_CHECK_CHECK) && 
	       (sh.flag.update == S_TRUE))
	{	
	  if (0 == sh_kern_data_init()) {
	    is_init = 1;
	  } else {
	    sh_error_handle (ShKernSeverity, FIL__, __LINE__, status, 
			     MSG_E_SUBGEN,
			     _("no or incomplete data in baseline database"),
			     _("kern_check_internal") );
	  }
	}
    }

  /* defined, but not used
   */
  ShKernDelay    = 0;
   
  list[0].n_name = "_sysent";
  list[1].n_name = NULL;

  kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);
  if (!kd)
    {
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
		       errbuf,
		       _("kvm_openfiles") );
      SL_RETURN( (-1), _("sh_kern_check_internal"));
    }

  i = kvm_nlist(kd, list);
  if (i == -1)
    {
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
		       kvm_geterr(kd),
		       _("kvm_nlist (_sysent)") );
      kvm_close(kd);
      SL_RETURN( (-1), _("sh_kern_check_internal"));
    }

  sys_list = SH_ALLOC((SYS_MAXSYSCALL+1) * sizeof(struct nlist));

  for (i = 0; i < SH_MAXCALLS; ++i)
    sys_list[i].n_name = sh_syscalls[i].name;
  sys_list[SH_MAXCALLS].n_name = NULL;

  i = kvm_nlist(kd, sys_list);
  if (i == -1)
    {
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
		       kvm_geterr(kd),
		       _("kvm_nlist (syscalls)") );
      kvm_close(kd);
      SH_FREE(sys_list);
      SL_RETURN( (-1), _("sh_kern_check_internal"));
    }
  else if (i > 0)
    {
      sl_snprintf(tmp, 128,
                  _("%d invalid syscalls"), i);
      /*
      for (i = 0; i < SH_MAXCALLS; ++i) {
        if (sys_list[i].n_type == 0 && sys_list[i].n_value == 0)
          fprintf(stderr, "invalid: [%3d] %s\n", i, sh_syscalls[i].name);
      }
      */
      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, status, MSG_E_SUBGEN,
                       tmp,
                       _("kvm_nlist (syscalls)") );
    }

  /* Check the individual syscalls
   *
   * Stored(old) is sh_syscalls[] array.
   */
  if (sh.flag.checkSum == SH_CHECK_INIT || sh.flag.update == S_TRUE)
    {
      for (i = 0; i < SH_MAXCALLS; ++i) 
	{
	  if (sh_syscalls[i].name == NULL)
	    {
	      sl_snprintf(tmp, 128, 
			  _("too few entries in sh_syscalls[]: have %d, expect %d"), 
			  i, SH_MAXCALLS);

	      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
			       tmp,
			       _("sh_kern_check_internal") );
	      break;
	    }

	  /* read address of syscall from sysent table
	   */
	  offset = list[0].n_value + (i*sizeof(struct sysent));
	  if (kvm_read(kd, offset, &sy, sizeof(struct sysent)) < 0)
	    {
	      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
			       kvm_geterr(kd),
			       _("kvm_read (syscall table)") );
	      kvm_close(kd);
	      SH_FREE(sys_list);
	      SL_RETURN( (-1), _("sh_kern_check_internal"));
	    }
	  syscall_addr = (unsigned long) sy.sy_call;
	  store0 = syscall_addr;
	  
	  /* read the syscall code
	   */
	  if(kvm_read(kd, (unsigned int) sy.sy_call, &(syscall_code[0]), 
		      2 * sizeof(unsigned int)) < 0)
	    {
	      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
			       kvm_geterr(kd),
			       _("kvm_read (syscall code)") );
	      kvm_close(kd);
	      SH_FREE(sys_list);
	      SL_RETURN( (-1), _("sh_kern_check_internal"));
	    }
	  store1 = syscall_code[0]; store2 = syscall_code[1];
	  
	  sh_kern_db_syscall (i, _("syscall"), 
			      NULL, &store0, &store1, &store2,
			      0, SH_KERN_DBPUSH);
	}
    }

  if ((sh.flag.checkSum != SH_CHECK_INIT) || 
      (sh.flag.update == S_TRUE && is_init == 1))
    {
      for (i = 0; i < SH_MAXCALLS; ++i)
	{
	  if (sh_syscalls[i].name == NULL)
	    {
	      sl_snprintf(tmp, 128, 
			  _("too few entries in sh_syscalls[]: have %d, expect %d"), 
			  i, SH_MAXCALLS);

	      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
			       tmp,
			       _("sh_kern_check_internal") );
	      break;
	    }
	  
	  /* read address of syscall from sysent table
	   */
	  offset = list[0].n_value + (i*sizeof(struct sysent));
	  if (kvm_read(kd, offset, &sy, sizeof(struct sysent)) < 0)
	    {
	      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
			       kvm_geterr(kd),
			       _("kvm_read (syscall table)") );
	      kvm_close(kd);
	      SH_FREE(sys_list);
	      SL_RETURN( (-1), _("sh_kern_check_internal"));
	    }
	  syscall_addr = (unsigned long) sy.sy_call;
	  
	  if (sh_syscalls[i].addr != syscall_addr)
	    {
#ifdef SH_USE_XML
	      sl_snprintf(tmp, 128, "path=\"K_%s_%04d\" ", 
			  _("syscall"), i);
#else
	      sl_snprintf(tmp, 128, "path=<K_%s_%04d>, ", 
			  _("syscall"), i);
#endif
	      sl_strlcpy(msg, tmp, SH_BUFSIZE);

	      size_old = sh_syscalls[i].addr; 
	      size_new = syscall_addr;
	      sl_snprintf(tmp, 128, sh_hash_size_format(),
			  size_old, size_new);
	      sl_strlcat(msg, tmp, SH_BUFSIZE);
 
	      sh_error_handle (ShKernSeverity, FIL__, __LINE__, 
			       status, MSG_KERN_SYSCALL,
			       i, _(sh_syscalls[i].name),
			       msg);
	      sh_syscalls[i].addr = syscall_addr;
	    }
	  else
	    {    
	      /* read the syscall code
	       */
	      if(kvm_read(kd, (unsigned int) sy.sy_call, &(syscall_code[0]), 
			  2 * sizeof(unsigned int)) < 0)
		{
		  sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
				   kvm_geterr(kd),
				   _("kvm_read (syscall code)") );
		  kvm_close(kd);
		  SH_FREE(sys_list);
		  SL_RETURN( (-1), _("sh_kern_check_internal"));
		}
	      
	      if (sh_syscalls[i].code[0] != syscall_code[0] || 
		  sh_syscalls[i].code[1] != syscall_code[1])
		{
		  mtime_old = sh_syscalls[i].code[0];
		  mtime_new = syscall_code[0];
		  ctime_old = sh_syscalls[i].code[1];
		  ctime_new = syscall_code[1];

#ifdef SH_USE_XML
		  sl_snprintf(tmp, 128, "path=\"K_%s_%04d\" ", 
			      _("syscall"), i);
#else
		  sl_snprintf(tmp, 128, "path=<K_%s_%04d>, ", 
			      _("syscall"), i);
#endif
		  sl_strlcpy(msg, tmp, SH_BUFSIZE);

		  (void) sh_unix_gmttime (ctime_old, timstr_o, sizeof(timstr_o));
		  (void) sh_unix_gmttime (ctime_new, timstr_n, sizeof(timstr_n));
#ifdef SH_USE_XML
		  sl_snprintf(tmp, 128, 
			      _("ctime_old=\"%s\" ctime_new=\"%s\" "), 
			      timstr_o, timstr_n);
#else
		  sl_snprintf(tmp, 128, 
			      _("ctime_old=<%s>, ctime_new=<%s>, "), 
			      timstr_o, timstr_n);
#endif
		  sl_strlcat(msg, tmp, SH_BUFSIZE); 
		  (void) sh_unix_gmttime (mtime_old, timstr_o, sizeof(timstr_o));
		  (void) sh_unix_gmttime (mtime_new, timstr_n, sizeof(timstr_n));
#ifdef SH_USE_XML
		  sl_snprintf(tmp, 128, 
			      _("mtime_old=\"%s\" mtime_new=\"%s\" "), 
			      timstr_o, timstr_n);
#else
		  sl_snprintf(tmp, 128, 
			      _("mtime_old=<%s>, mtime_new=<%s> "), 
			      timstr_o, timstr_n);
#endif
		  sl_strlcat(msg, tmp, SH_BUFSIZE); 

		  sh_error_handle (ShKernSeverity, FIL__, __LINE__, 
				   status, MSG_KERN_SYSCALL,
				   i, _(sh_syscalls[i].name),
				   msg);
		  sh_syscalls[i].code[0] = syscall_code[0];
		  sh_syscalls[i].code[1] = syscall_code[1];
		}
	    }
	}
    }
  SH_FREE(sys_list);
  if(kvm_close(kd) < 0)
    {
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
                       kvm_geterr(kd),
                       _("kvm_close") );
      exit(EXIT_FAILURE);
    }

  SL_RETURN( (0), _("sh_kern_check_internal"));
}

#endif

/*************
 *
 * module init
 *
 *************/
#if defined(HOST_IS_LINUX)
#include <sys/utsname.h>
#endif

static int AddressReconf = 0;

int sh_kern_init (struct mod_type * arg)
{
#if defined(HOST_IS_LINUX)
  struct utsname buf;
  char         * str;
#endif
  (void) arg;

  SL_ENTER(_("sh_kern_init"));
  if (ShKernActive == S_FALSE)
    SL_RETURN( (-1), _("sh_kern_init"));

#if defined(HOST_IS_LINUX)
  uname(&buf);

  if ((AddressReconf < 5) && (0 != strcmp(SH_KERNEL_VERSION, buf.release)))
    {
      str = SH_ALLOC(256);
      sl_snprintf(str, 256, 
		  "Compiled for kernel %s, but current kernel is %s, and kernel addresses have not been re-configured",
		  SH_KERNEL_VERSION, buf.release);
      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, EINVAL, MSG_E_SUBGEN,
		       str,
		       _("kern_check") );
      SH_FREE(str);
      ShKernActive = S_FALSE;
      SL_RETURN( (-1), _("sh_kern_init"));
    }
#endif

  lastcheck  = time (NULL);
  if (sh.flag.checkSum != SH_CHECK_INIT)
    {
      sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       _("Checking kernel syscalls"),
		       _("kern_check") );
    }
  sh_kern_check_internal ();
  SL_RETURN( (0), _("sh_kern_init"));
}

/*************
 *
 * module cleanup
 *
 *************/
int sh_kern_end ()
{
  return (0);
}


/*************
 *
 * module timer
 *
 *************/
int sh_kern_timer (time_t tcurrent)
{
  if (ShKernActive == S_FALSE)
    return 0;

  if ((int) (tcurrent - lastcheck) >= ShKernInterval)
    {
      lastcheck  = tcurrent;
      return (-1);
    }
  return 0;
}

/*************
 *
 * module check
 *
 *************/
int sh_kern_check ()
{
  sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, EINVAL, MSG_E_SUBGEN,
		   _("Checking kernel syscalls"),
		   _("kern_check") );
  return (sh_kern_check_internal ());
}

/*************
 *
 * module setup
 *
 *************/

int sh_kern_set_severity  (const char * c)
{
  char tmp[32];
  tmp[0] = '='; tmp[1] = '\0';
  sl_strlcat (tmp, c, 32);
  sh_error_set_level (tmp, &ShKernSeverity);
  return 0;
}

int sh_kern_set_timer (const char * c)
{
  long val;

  SL_ENTER(_("sh_kern_set_timer"));

  val = strtol (c, (char **)NULL, 10);
  if (val <= 0)
    sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
                      _("kern timer"), c);

  val = (val <= 0 ? 60 : val);

  ShKernInterval = (time_t) val;
  SL_RETURN( 0, _("sh_kern_set_timer"));
}

int sh_kern_set_activate (const char * c)
{
  int i;
  SL_ENTER(_("sh_kern_set_activate"));
  i = sh_util_flagval(c, &ShKernActive);
  SL_RETURN(i, _("sh_kern_set_activate"));
}

int sh_kern_set_idt (const char * c)
{
  int i;
  SL_ENTER(_("sh_kern_set_idt"));
  i = sh_util_flagval(c, &ShKernIDT);
  SL_RETURN(i, _("sh_kern_set_idt"));
}

int sh_kern_set_pci (const char * c)
{
  int i;
  SL_ENTER(_("sh_kern_set_pci"));
  i = sh_util_flagval(c, &ShKernPCI);
  SL_RETURN(i, _("sh_kern_set_pci"));
}

int sh_kern_set_sc_addr (const char * c)
{
  char * endptr;
  unsigned long value;

  SL_ENTER(_("sh_kern_set_sc_addr"));
  errno = 0;
  value = strtoul(c, &endptr, 16);
  if ((ULONG_MAX == value) && (errno == ERANGE))
    {
      SL_RETURN((-1), _("sh_kern_set_sc_addr"));
    }
  if ((*c == '\0') || (*endptr != '\0'))
    {
      SL_RETURN((-1), _("sh_kern_set_sc_addr"));
    }
  system_call_addr = value;
  ++AddressReconf;
  SL_RETURN((0), _("sh_kern_set_sc_addr"));
}

int sh_kern_set_sct_addr (const char * c)
{
  char * endptr;
  unsigned long value;

  SL_ENTER(_("sh_kern_set_sct_addr"));
  errno = 0;
  value = strtoul(c, &endptr, 16);
  if ((ULONG_MAX == value) && (errno == ERANGE))
    {
      SL_RETURN((-1), _("sh_kern_set_sct_addr"));
    }
  if ((*c == '\0') || (*endptr != '\0'))
    {
      SL_RETURN((-1), _("sh_kern_set_sct_addr"));
    }
  kaddr = (unsigned int) value;
  ++AddressReconf;
  SL_RETURN((0), _("sh_kern_set_sct_addr"));
}

int sh_kern_set_proc_root (const char * c)
{
  char * endptr;
  unsigned long value;

  SL_ENTER(_("sh_kern_set_proc_root"));
  errno = 0;
  value = strtoul(c, &endptr, 16);
  if ((ULONG_MAX == value) && (errno == ERANGE))
    {
      SL_RETURN((-1), _("sh_kern_set_proc_root"));
    }
  if ((*c == '\0') || (*endptr != '\0'))
    {
      SL_RETURN((-1), _("sh_kern_set_proc_root"));
    }
  
  proc_root = value;
  ++AddressReconf;
  SL_RETURN((0), _("sh_kern_set_proc_root"));
}

int sh_kern_set_proc_root_iops (const char * c)
{
  char * endptr;
  unsigned long value;

  SL_ENTER(_("sh_kern_set_proc_root_iops"));
  errno = 0;
  value = strtoul(c, &endptr, 16);
  if ((ULONG_MAX == value) && (errno == ERANGE))
    {
      SL_RETURN((-1), _("sh_kern_set_proc_root_iops"));
    }
  if ((*c == '\0') || (*endptr != '\0'))
    {
      SL_RETURN((-1), _("sh_kern_set_proc_root_iops"));
    }
  
  proc_root_iops = value;
  ++AddressReconf;
  SL_RETURN((0), _("sh_kern_set_proc_root_iops"));
}

int sh_kern_set_proc_root_lookup (const char * c)
{
  char * endptr;
  unsigned long value;

  SL_ENTER(_("sh_kern_set_proc_root_lookup"));
  errno = 0;
  value = strtoul(c, &endptr, 16);
  if ((ULONG_MAX == value) && (errno == ERANGE))
    {
      SL_RETURN((-1), _("sh_kern_set_proc_root_lookup"));
    }
  if ((*c == '\0') || (*endptr != '\0'))
    {
      SL_RETURN((-1), _("sh_kern_set_proc_root_lookup"));
    }
  proc_root_lookup = value;
  ++AddressReconf;
  SL_RETURN((0), _("sh_kern_set_proc_root_lookup"));
}

#endif

/* #ifdef SH_USE_KERN */
#endif
