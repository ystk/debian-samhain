/***************************************************************************
 *
 * Purpose:
 * -------
 *   (1) Hide files with the string MAGIC_HIDE in filename,
 *       where MAGIC_HIDE is defined below. 
 *       By default,  MAGIC_HIDE is defined as "samhain".
 *
 *   (2) Hide all processes, if the executable has the string MAGIC_HIDE 
 *       in its name.
 *
 *
 * Configuration:
 * -------------
 *   If not building within the samhain system, you may remove the 
 *   line '#include "config.h"' and in the line
 *   '#define MAGIC_HIDE SH_MAGIC_HIDE', replace SH_MAGIC_HIDE with
 *   "someString" (in quotes !).
 */

/* #define _(string) string */
#include "config.h" 

#undef _
#define _(string) string

/* define if this is a 2.6 kernel                 */
/* #define LINUX26                                */

#define MAGIC_HIDE SH_MAGIC_HIDE

/*  #define MAGIC_HIDE "someString"               */

/* define this if you have a modversioned kernel  */
/*  #define MODVERSIONS                           */

/* the address of the sys_call_table (not exported in 2.5 kernels) */
#define MAGIC_ADDRESS SH_SYSCALLTABLE

/*
 * Install:
 * -------
 *   gcc -Wall -O2 -c samhain_hide.c
 *   mv samhain_hide.o  /lib/modules/KERNEL_VERSION/misc/
 *   
 *   (Replace KERNEL_VERSION with your kernel's version.)
 *
 * Usage:
 * -----
 *   To load the module:
 *    insmod samhain_hide (for improved safety: 'sync && insmod samhain_hide')
 *
 *   Self-hiding can be switched off by passing the option
 *   'removeme=0' to the module: 
 *    insmod ./samhain_hide.ko removeme=0
 *
 *   To unload the module (only possible if not hidden):
 *    rmmod samhain_hide  (for improved safety: 'sync && rmmod samhain_hide')
 * 
 *
 * Details:
 * -------
 *   The following kernel syscalls are replaced:
 *     sys_getdents     [hide files/directories/processes (/proc/PID)]
 * 
 * Tested on:
 * ---------
 *   Linux 2.2, 2.4, 2.6
 *
 * Copyright:
 * ---------
 *   Copyright (C) 2001, 2002 Rainer Wichmann (http://la-samhna.de)
 *
 * License: 
 * -------
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *                                                                         
 *   This program is distributed in the hope that it will be useful,        
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          
 *   GNU General Public License for more details.                           
 *                                                                         
 *   You should have received a copy of the GNU General Public License      
 *   along with this program; if not, write to the Free Software            
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.              
 *
 ***************************************************************************/



/*****************************************************
 *
 *  The defines:
 *
 *****************************************************/

/* This is a Linux Loadable Kernel Module.
 */

#ifndef LINUX26
#define __KERNEL__
#define MODULE
#endif
#define LINUX

/* Define for debugging.   
 */
/* #define HIDE_DEBUG  */   /* query_module */
/* #define FILE_DEBUG  */   /* getdents     */
/* #define READ_DEBUG  */   /* read         */
/* #define PROC_DEBUG  */   /* procfs       */

/*****************************************************
 *
 *  The include files:
 *
 *****************************************************/


/* The configure options (#defines) for the Kernel
 */
/* 2.6.19 (((2) << 16) + ((6) << 8) + (19)) */
#define SH_KERNEL_MIN 132627 

#if SH_KERNEL_NUMERIC >= SH_KERNEL_MIN
#include <linux/autoconf.h>
#else
#include <linux/config.h>
#endif

#ifndef LINUX26
#ifdef CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif
#endif


#ifdef LINUX26
#include <linux/init.h>
#endif

#include <linux/module.h>

/* File tables structures. If directory caching is used,
 * <linux/dcache.h> will be included here, and __LINUX_DCACHE_H
 * will thus be defined.
 */
#include <linux/fs.h>
#include <linux/proc_fs.h>

/* Include the SYS_syscall defines.
 */
#ifndef LINUX26
#include <sys/syscall.h>
#else
#define SYS_getdents 141
#define SYS_getdents64 220
#endif


/* Includes for 'getdents' per the manpage.
 */
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>

/* To access userspace memory.
 */
#include <asm/uaccess.h>

/* Include for lock_kernel().
 */
#include <linux/smp_lock.h>

#if SH_KERNEL_NUMERIC >= SH_KERNEL_MIN
#include <linux/mutex.h>
#endif

/* Include for fget().
 */
#include <linux/file.h>

/*****************************************************
 *
 *  The global variables:
 *
 *****************************************************/

/* The kernel syscall table. Not exported anymore in 2.5 ff., and also
 * not in the RedHat 2.4 kernel.
 */

#if 0
extern void * sys_call_table[];
#define sh_sys_call_table sys_call_table
#endif

unsigned long * sh_sys_call_table = (unsigned long *) MAGIC_ADDRESS;

/* The old address of the sys_getdents syscall.
 */
int (*old_getdents)(unsigned int, struct dirent *, unsigned int);
#ifdef __NR_getdents64
#if SH_KERNEL_NUMERIC >= 132628
/*
 * 'asmlinkage' is __required__ to get this to work.
 */
asmlinkage long (*old_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);
#else
long (*old_getdents64)(unsigned int, struct dirent64 *, unsigned int);
#endif
#endif

char hidden[] = MAGIC_HIDE;
 

/*****************************************************
 *
 *  The functions:
 *
 *****************************************************/


MODULE_AUTHOR("Rainer Wichmann");
MODULE_DESCRIPTION("Hide files/processes/modules with MAGIC_HIDE in name.");
#if defined(MODULE_LICENSE) || defined(LINUX26)
MODULE_LICENSE("GPL");  
#endif

#ifdef LINUX26
/* Default is to hide ourselves.
 */
static int removeme = 1;

#ifdef MODULE_PARM 
MODULE_PARM (removeme, "i");
#else
module_param(removeme, int, 0444);
#endif

#ifdef MODULE_PARM_DESC
MODULE_PARM_DESC(removeme, "Choose zero for not hiding.");
#endif

/* LINUX26 */
#endif


/* 
 *  struct task_struct is defined in linux/sched.h
 *
 *  as of 2.4.20, the vanilla kernel holds (among others):
 *        struct task_struct *next_task, *prev_task;
 *
 *  Redhat kernel seems to have a different scheduler.
 *  use:
 *        struct task_struct * find_task_by_pid (int pid);
 */

#if defined(SH_VANILLA_KERNEL) && !defined(LINUX26)
/*
 * Fetch the task struct for a given PID.
 */
struct task_struct * fetch_task_struct (int pid)
{
  struct task_struct * task_ptr;

#ifdef PROC_DEBUG
  printk("FETCH TASK %d\n", pid);
#endif

  task_ptr = current;

  do 
    {
      if (task_ptr->pid == (pid_t) pid )
	return (task_ptr);
      task_ptr = task_ptr->next_task;
    } 
  while (task_ptr != current);

#ifdef PROC_DEBUG
  printk("FETCH TASK: NOT FOUND !!!\n");
#endif

  return (NULL);
}

#else
/*
 *  RedHat 2.4.20 kernel
 */
struct task_struct * fetch_task_struct (int pid)
{
  struct task_struct * task_ptr = NULL;
  task_ptr = find_task_by_pid (pid);
  return (task_ptr);
}
#endif

/* Convert a string to an int. 
 * Does not recognize integers with a sign (+/-) in front.
 */
int my_atoi(char * in_str)
{
  int i      = 0;
  int retval = 0;
  int conv   = 0;

  if (in_str == NULL)
    return (-1);

  while(in_str[i] != '\0')
    {
      /* Break if not numeric.
       */
      if (in_str[i] < '0' || in_str[i] > '9')
	break;

      ++conv;
      
      /* Leading zeroes (should not happen in /proc)
       */
      if (retval == 0 && in_str[i] == '0')
	retval = retval;
      else
	retval = retval * 10;

      retval = retval + (in_str[i] - '0');

      i++;
    }
      
  if (conv == 0)
    return (-1);
  else
    return (retval); 
}

/* Purpose:
 * 
 *   Hide all files/dirs that include the string MAGIC_HIDE in their
 *   name. 
 */
int new_getdents (unsigned int fd, struct dirent *dirp, unsigned int count)
{
  int                  status = 0;    /* Return value from original getdents */
  struct inode       * dir_inode;
  struct file        * fd_file;
  int                  dir_is_proc = 0;

  struct dirent      * dirp_prev;
  struct dirent      * dirp_new;
  struct dirent      * dirp_current;

  int                  dir_table_bytes;
  int                  forward_bytes;
  struct task_struct * task_ptr;
  int                  hide_it = 0;
  long                 dirp_offset;

  unsigned long        dummy;

  lock_kernel();

  status = (*old_getdents)(fd, dirp, count);

#ifdef FILE_DEBUG
  printk("STATUS %d\n", status);
#endif
  
  /*  0: end of directory.
   * -1: some error
   */
  if (status <= 0)
    {
      unlock_kernel();
      return (status);
    }
  
  /* Handle directory caching. dir_inode is the inode of the directory.
   */
#if defined(files_fdtable)
  {
    struct fdtable *fdt = files_fdtable(current->files);
    fd_file = rcu_dereference(fdt->fd[fd]);
  }
#else
  {
    fd_file = current->files->fd[fd];
  }
#endif
  
#if defined(__LINUX_DCACHE_H)
  dir_inode  = fd_file->f_dentry->d_inode;
#else
  dir_inode  = fd_file->f_inode;
#endif

  /* Check for the /proc directory
   */
  if (dir_inode->i_ino == PROC_ROOT_INO 
#ifndef LINUX26
      && !MAJOR(dir_inode->i_dev) && 
      MINOR(dir_inode->i_dev) == 1
#endif
      )
    dir_is_proc = 1;

  /* Allocate space for new dirent table. Can't use GFP_KERNEL 
   * (kernel oops)
   */
  dirp_new = (struct dirent *) kmalloc (status, GFP_ATOMIC);

  if (dirp_new == NULL)
    {
      unlock_kernel();
      return (status);
    }

  /* Copy the dirp table to kernel space.
   */
  dummy = (unsigned long) copy_from_user(dirp_new, dirp, status);

#ifdef FILE_DEBUG
  printk("COPY to kernel: %ld\n", dummy);
#endif

  /* Loop over the dirp table to find entries to hide.
   */
  dir_table_bytes = status;
  dirp_current    = dirp_new;
  dirp_prev       = NULL;

  while (dir_table_bytes > 0)
    {
      hide_it = 0;

      if (dirp_current->d_reclen == 0)
	break;

      dirp_offset = dirp_current->d_off;
      
#ifdef FILE_DEBUG
      printk("DIRENT %d  %d  %ld\n", 
	     dir_table_bytes,
	     dirp_current->d_reclen,
	     dirp_current->d_off);
#endif

      dir_table_bytes -= dirp_current->d_reclen;
      forward_bytes    = dirp_current->d_reclen;

#ifdef FILE_DEBUG
      printk("ENTRY %s\n", dirp_current->d_name);
#endif

      /* If /proc is scanned (e.g. by 'ps'), hide the entry for
       * any process where the executable has MAGIC_HIDE in its name.
       */
      if (dir_is_proc == 1)
	{
	  task_ptr = fetch_task_struct(my_atoi(dirp_current->d_name));
	  if (task_ptr != NULL)
	    {
	      if (strstr(task_ptr->comm, hidden) != NULL)
		hide_it = 1;
	    }
	}
      /* If it is a regular directory, hide any entry with
       * MAGIC_HIDE in its name.
       */
      else
	{
	  if (strstr (dirp_current->d_name, hidden) != NULL)
	    hide_it = 1;
	}

      if (hide_it == 1)
	{
#ifdef FILE_DEBUG
	  printk("  -->HIDDEN %s\n", dirp_current->d_name);
#endif
	  if (dir_table_bytes > 0)
	    {
	      status -= dirp_current->d_reclen;
	      memmove (dirp_current, 
		       (char *) dirp_current + dirp_current->d_reclen, 
		       dir_table_bytes);

	      /* Set forward_bytes to 0, because now dirp_current is the
	       * (previously) next entry in the dirp table.
	       */
	      forward_bytes    = 0;
	      dirp_prev        = dirp_current;
	    }
	  else
	    {
	      status -= dirp_current->d_reclen;
	      if (dirp_prev != NULL)
		dirp_prev->d_off = dirp_offset;
	    }
	  
	}
      else
	{
	  dirp_prev        = dirp_current;
	  if (dir_table_bytes == 0 && dirp_prev != NULL)
	    dirp_prev->d_off = dirp_offset;
	}

      /* Next entry in dirp table.
       */
      if (dir_table_bytes > 0)
	dirp_current = (struct dirent *) ( (char *) dirp_current + 
					   forward_bytes);
    }

  /* Copy our modified dirp table back to user space.
   */
  dummy = (unsigned long) copy_to_user(dirp, dirp_new, status);
#ifdef FILE_DEBUG
  printk("COPY to user: %ld\n", dummy);
#endif

  kfree (dirp_new);
#ifdef FILE_DEBUG
  printk("KFREE\n");
#endif

  unlock_kernel();
  return (status);
}

/* For 2.4 kernel
 */
#ifdef __NR_getdents64

#if SH_KERNEL_NUMERIC >= 132628
/*
 * 'asmlinkage' is __required__ to get this to work.
 */
asmlinkage long new_getdents64 (unsigned int fd, struct linux_dirent64 __user *dirp, 
				unsigned int count)
#else
long new_getdents64 (unsigned int fd, struct dirent64 *dirp, unsigned int count)
#endif
{
  long                 status = 0;    /* Return value from original getdents */
  struct inode       * dir_inode;
  struct file        * fd_file;
  int                  dir_is_proc = 0;

  struct dirent64    * dirp_prev;
  struct dirent64    * dirp_new;
  struct dirent64    * dirp_current;

  int                  dir_table_bytes;
  int                  forward_bytes;
  struct task_struct * task_ptr;
  int                  hide_it = 0;
  __s64                dirp_offset;

  unsigned long        dummy;

#ifdef FILE_DEBUG
  printk("FD64 %d\n", fd);
#endif

  lock_kernel();

#ifdef FILE_DEBUG
  if (!access_ok(VERIFY_WRITE, dirp, count))
    printk("ACCESS64_BAD\n");
  else
    printk("ACCESS64_OK\n");
#endif

#if SH_KERNEL_NUMERIC >= 132628
  status = (*old_getdents64)(fd, dirp, count);
  /* status = my_real_getdents64(fd, dirp, count); */
#else
  status = (*old_getdents64)(fd, dirp, count);
#endif

#ifdef FILE_DEBUG
  printk("STATUS64 %ld\n", status);
#endif

  /*  0: end of directory.
   * -1: some error
   */
  if (status <= 0)
    {
      unlock_kernel();
      return (status);
    }

  /* Handle directory caching. dir_inode is the inode of the directory.
   */
#if defined(files_fdtable)
  {
    struct fdtable *fdt = files_fdtable(current->files);
    fd_file = rcu_dereference(fdt->fd[fd]);
  }
#else
  {
    fd_file = current->files->fd[fd];
  }
#endif

#if defined(__LINUX_DCACHE_H)

/* 2.6.20 (((2) << 16) + ((6) << 8) + (20)) */
#if SH_KERNEL_NUMERIC >= 132628
  dir_inode  = fd_file->f_path.dentry->d_inode;
#else
  dir_inode  = fd_file->f_dentry->d_inode;
#endif

#else
  dir_inode  = fd_file->f_inode;
#endif

#ifdef FILE_DEBUG
  printk("INODE64\n");
#endif

  /* Check for the /proc directory
   */
  if (dir_inode->i_ino == PROC_ROOT_INO
#ifndef LINUX26  
      && !MAJOR(dir_inode->i_dev) /*  && 
      MINOR(dir_inode->i_dev) == 1 */
      /* MINOR commented out because of problems with 2.4.17 */
#endif
      )
    {
      dir_is_proc = 1;

#ifdef PROC_DEBUG
      printk("PROC_CHECK64\n");
#endif
    }

  /* Allocate space for new dirent table. Can't use GFP_KERNEL 
   * (kernel oops)
   */
  dirp_new = kmalloc ((size_t)status, GFP_ATOMIC);

#ifdef FILE_DEBUG
  printk("KMALLOC64_0\n");
#endif

  if (dirp_new == NULL)
    {
      unlock_kernel();
      return (status);
    }

#ifdef FILE_DEBUG
  printk("KMALLOC64\n");
#endif

  /* Copy the dirp table to kernel space.
   */
  dummy = (unsigned long) copy_from_user(dirp_new, dirp, status);

#ifdef FILE_DEBUG
  printk("COPY64 to kernel: %ld\n", dummy);
#endif

  /* Loop over the dirp table to find entries to hide.
   */
  dir_table_bytes = status;
  dirp_current    = dirp_new;
  dirp_prev       = NULL;

  while (dir_table_bytes > 0)
    {
      hide_it = 0;

      if (dirp_current->d_reclen == 0)
	break;

      dirp_offset = dirp_current->d_off;
      
#ifdef FILE_DEBUG
      printk("DIRENT %d  %d  %lld\n", 
	     dir_table_bytes,
	     dirp_current->d_reclen,
	     dirp_current->d_off);
#endif

      dir_table_bytes -= dirp_current->d_reclen;
      forward_bytes    = dirp_current->d_reclen;

#ifdef FILE_DEBUG
      printk("ENTRY %s\n", dirp_current->d_name);
#endif

      /* If /proc is scanned (e.g. by 'ps'), hide the entry for
       * any process where the executable has MAGIC_HIDE in its name.
       */
      if (dir_is_proc == 1)
	{
#ifdef PROC_DEBUG
	  printk("PROC %s\n", dirp_current->d_name);
#endif
	  task_ptr = fetch_task_struct(my_atoi(dirp_current->d_name));
	  if (task_ptr != NULL)
	    {
#ifdef PROC_DEBUG
	      printk("PROC %s <> %s\n", task_ptr->comm, hidden);
#endif
	      if (strstr(task_ptr->comm, hidden) != NULL)
		hide_it = 1;
	    }
	}
      /* If it is a regular directory, hide any entry with
       * MAGIC_HIDE in its name.
       */
      else
	{
	  if (strstr (dirp_current->d_name, hidden) != NULL)
	    hide_it = 1;
	}

      if (hide_it == 1)
	{
#ifdef FILE_DEBUG
	  printk("  -->HIDDEN %s\n", dirp_current->d_name);
#endif
	  if (dir_table_bytes > 0)
	    {
	      status -= dirp_current->d_reclen;
	      memmove (dirp_current, 
		       (char *) dirp_current + dirp_current->d_reclen, 
		       dir_table_bytes);

	      /* Set forward_bytes to 0, because now dirp_current is the
	       * (previously) next entry in the dirp table.
	       */
	      forward_bytes    = 0;
	      dirp_prev        = dirp_current;
	    }
	  else
	    {
	      status -= dirp_current->d_reclen;
	      if (dirp_prev != NULL)
		dirp_prev->d_off = dirp_offset;
	    }
	  
	}
      else
	{
	  dirp_prev        = dirp_current;
	  if (dir_table_bytes == 0 && dirp_prev != NULL)
	    dirp_prev->d_off = dirp_offset;
	}

      /* Next entry in dirp table.
       */
      if (dir_table_bytes > 0)
	dirp_current = (struct dirent64 *) ( (char *) dirp_current + 
					     forward_bytes);
    }

  /* Copy our modified dirp table back to user space.
   */
#ifdef FILE_DEBUG
  printk("STATUS64 AT END %ld\n", status);
#endif
  dummy = (unsigned long) copy_to_user(dirp, dirp_new, status);
#ifdef FILE_DEBUG
  printk("COPY64 to user: %ld\n", dummy);
#endif

  kfree (dirp_new);
  unlock_kernel();
  return (status);
}
#endif

#ifdef LINUX26
static struct module *find_module(const char *name)
{
        struct module *mod;
	struct list_head * modules = (struct list_head *) SH_LIST_MODULES;

        list_for_each_entry(mod, modules, list) {
                if (strcmp(mod->name, name) == 0)
                        return mod;
        }
        return NULL;
}
#endif

/* The initialisation function. Automatically called when module is inserted
 * via the 'insmod' command.
 */
#ifdef LINUX26
static int __init samhain_hide_init(void)
#else
int init_module(void)
#endif
{

  lock_kernel();

  /* Unfortunately this does not fully prevent the module from appearing
   * in /proc/ksyms. 
   */
#ifndef LINUX26
  EXPORT_NO_SYMBOLS;
#endif

  /* Replace the 'sys_getdents' syscall with the new version.
   */
  old_getdents                        = (void*) sh_sys_call_table[SYS_getdents];
  sh_sys_call_table[SYS_getdents]     = (unsigned long) new_getdents;
  
#ifdef __NR_getdents64
  old_getdents64                      = (void*) sh_sys_call_table[SYS_getdents64];
  sh_sys_call_table[SYS_getdents64]   = (unsigned long) new_getdents64;
#endif

#ifdef LINUX26
  {
#if defined(SH_MODLIST_LOCK)
    spinlock_t * modlist_lock = (spinlock_t * ) SH_MODLIST_LOCK;
#endif
#if SH_KERNEL_NUMERIC >= SH_KERNEL_MIN
    struct mutex * module_mutex = (struct mutex *) SH_MODLIST_MUTEX;
#endif

    struct module *mod;

#if SH_KERNEL_NUMERIC >= SH_KERNEL_MIN
    mutex_lock(module_mutex);
#endif

    mod = find_module(SH_INSTALL_NAME"_hide");
    if (mod) {
      /* Delete from various lists */
#if defined(SH_MODLIST_LOCK)
      spin_lock_irq(modlist_lock);
#endif
      if (removeme == 1)
	{
	  list_del(&mod->list);
	}
#if defined(SH_MODLIST_LOCK)
      spin_unlock_irq(modlist_lock);
#endif
    }
#if SH_KERNEL_NUMERIC >= SH_KERNEL_MIN
      mutex_unlock(module_mutex);
#endif
  }
#endif

  unlock_kernel();
  return (0);
}

/* The cleanup function. Automatically called when module is removed
 * via the 'rmmod' command.
 */
#ifdef LINUX26
static void __exit samhain_hide_cleanup(void)
#else
void cleanup_module(void)
#endif
{
  lock_kernel();

  /* Restore the new syscalls to the original version.
   */
  sh_sys_call_table[SYS_getdents]     = (unsigned long) old_getdents;
#ifdef __NR_getdents64
  sh_sys_call_table[SYS_getdents64]   = (unsigned long) old_getdents64;
#endif

  unlock_kernel();
}

#ifdef LINUX26
module_init(samhain_hide_init);
module_exit(samhain_hide_cleanup);
#endif


