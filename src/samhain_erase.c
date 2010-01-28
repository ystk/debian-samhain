/***************************************************************************
 *
 * Purpose:
 * -------
 *   Hide loaded kernel modules with names including the string MAGIC_HIDE 

 *
 * Configuration:
 * -------------
 *   If not building within the samhain system, you may remove the 
 *   line '#include "config.h"' and in the line
 *   '#define MAGIC_HIDE SH_MAGIC_HIDE', replace SH_MAGIC_HIDE with
 *   "someString" (in quotes !).
 */


#include "config.h" 

#define MAGIC_HIDE SH_MAGIC_HIDE

/*  #define MAGIC_HIDE "someString"              */

/* define this if you have a modversioned kernel */
/*  #define MODVERSIONS                           */

/*
 * Install:
 * -------
 *   gcc -Wall -O2 -c samhain_erase.c
 *   mv samhain_hide.o  /lib/modules/KERNEL_VERSION/misc/
 *   
 *   (Replace KERNEL_VERSION with your kernel's version.)
 *
 * Usage:
 * -----
 *   To load the module:
 *    insmod samhain_hide (for improved safety: 'sync && insmod samhain_hide')
 *
 *   To unload the module 
 *    rmmod samhain_hide  (for improved safety: 'sync && rmmod samhain_hide')
 * 
 * 
 * Tested on:
 * ---------
 *   Linux 2.2
 *
 * Copyright:
 * ---------
 *   Copyright (C) 2001 Rainer Wichmann (http://la-samhna.de)
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

#define __KERNEL__
#define MODULE

/* The configure options (#defines) for the Kernel
 */
#include <linux/config.h>

#ifdef CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#define N_(string) string
#include "config.h"

#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");  
#endif

#undef  NULL
#define NULL ((void *)0)


int init_module()
{
  struct module * ptr;
  struct module * prev;
  int             found  = 0;

  ptr  = &(__this_module);
  prev = &(__this_module);

  /* skip this module to allow 'rmmod'
   */
  ptr  = ptr->next;

  while (ptr)
    {
      found = 0;

      if (ptr->name && ptr->name[0] != '\0')
	{
	  /* printk("%s <%s>\n", ptr->name, SH_MAGIC_HIDE); */
	  if (NULL != strstr(ptr->name, SH_MAGIC_HIDE))
	    {
	      prev->next = ptr->next;
	      /* printk("-->HIDE\n"); */
	      found = 1;
	    }
	} 

      if (ptr->next)
	{
	  if (found == 0)
	    prev = ptr;
	  ptr = ptr->next;
	}
      else
	break;
    }

  return 0;
}

void cleanup_module()
{
	return;
}


