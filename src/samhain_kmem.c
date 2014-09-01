/* Most of this code is ripped from the Linux kernel:
 *
 *  linux/drivers/char/mem.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Added devfs support. 
 *    Jan-11-1998, C. Scott Ananian <cananian@alumni.princeton.edu>
 *  Shared /dev/zero mmaping support, Feb 2000, Kanoj Sarcar <kanoj@sgi.com>
 */

#include "config.h" 

#undef _
#define _(string) string

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/raw.h>
#include <linux/tty.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/crash_dump.h>
#include <linux/backing-dev.h>
#include <linux/bootmem.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22)
#include <linux/splice.h>
#endif
#include <linux/pfn.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/pgtable.h>

#ifdef CONFIG_IA64
# include <linux/efi.h>
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("samhain_kmem Kernel Module");
MODULE_AUTHOR("Rainer Wichmann");

static int debug = 0;
#ifdef MODULE_PARM 
MODULE_PARM (debug, "i");
#else
module_param(debug, int, 0444);
#endif

#ifdef MODULE_PARM_DESC
MODULE_PARM_DESC(debug, "Set to a non-zero value for debugging.");
#endif

/* struct task_struct
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#define TASK_EUID euid
#else
#define TASK_EUID cred->euid
#endif

static struct proc_dir_entry *proc_entry;

/*
 * Architectures vary in how they handle caching for addresses
 * outside of main memory.
 *
 */
static inline int uncached_access(struct file *file, unsigned long addr)
{
#if defined(__i386__) && !defined(__arch_um__)
  /*
   * On the PPro and successors, the MTRRs are used to set
   * memory types for physical addresses outside main memory,
   * so blindly setting PCD or PWT on those pages is wrong.
   * For Pentiums and earlier, the surround logic should disable
   * caching for the high addresses through the KEN pin, but
   * we maintain the tradition of paranoia in this code.
   */
  if (file->f_flags & O_SYNC)
    return 1;
  return !( test_bit(X86_FEATURE_MTRR, (const void *) boot_cpu_data.x86_capability) ||
	    test_bit(X86_FEATURE_K6_MTRR, (const void *) boot_cpu_data.x86_capability) ||
	    test_bit(X86_FEATURE_CYRIX_ARR, (const void *) boot_cpu_data.x86_capability) ||
	    test_bit(X86_FEATURE_CENTAUR_MCR, (const void *) boot_cpu_data.x86_capability) )
    && addr >= __pa(high_memory);
#elif defined(__x86_64__) && !defined(__arch_um__)
  /* 
   * This is broken because it can generate memory type aliases,
   * which can cause cache corruptions
   * But it is only available for root and we have to be bug-to-bug
   * compatible with i386.
   */
  if (file->f_flags & O_SYNC)
    return 1;
  /* same behaviour as i386. PAT always set to cached and MTRRs control the
     caching behaviour. 
     Hopefully a full PAT implementation will fix that soon. */      
  return 0;
#elif defined(CONFIG_IA64)
  /*
   * On ia64, we ignore O_SYNC because we cannot tolerate 
   * memory attribute aliases.
   */
  return !(efi_mem_attributes(addr) & EFI_MEMORY_WB);
#elif defined(CONFIG_MIPS)
  {
    extern int __uncached_access(struct file *file,
				 unsigned long addr);
    
    return __uncached_access(file, addr);
  }
#else
  /*
   * Accessing memory above the top the kernel knows about 
   * or through a file pointer
   * that was marked O_SYNC will be done non-cached.
   */
  if (file->f_flags & O_SYNC)
    return 1;
  return addr >= __pa(high_memory);
#endif
}

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static inline int valid_phys_addr_range(unsigned long addr, size_t count)
{
  if (addr + count > __pa(high_memory))
    return 0;
  
  return 1;
}

static inline int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
  return 1;
}
#endif


/* #ifndef __HAVE_PHYS_MEM_ACCESS_PROT */
static pgprot_t my_phys_mem_access_prot(struct file *file, unsigned long pfn,
                                     unsigned long size, pgprot_t vma_prot)
{
#ifdef pgprot_noncached
  unsigned long offset = pfn << PAGE_SHIFT;
  
  if (uncached_access(file, offset))
    return pgprot_noncached(vma_prot);
#else
#error pgtable
#endif
  return vma_prot;
}
/* #endif */


#ifndef CONFIG_MMU
static unsigned long get_unmapped_area_mem(struct file *file,
                                           unsigned long addr,
                                           unsigned long len,
                                           unsigned long pgoff,
                                           unsigned long flags)
{
  if (!valid_mmap_phys_addr_range(pgoff, len))
    return (unsigned long) -EINVAL;
  return pgoff << PAGE_SHIFT;
}

/* can't do an in-place private mapping if there's no MMU */
static inline int private_mapping_ok(struct vm_area_struct *vma)
{
  return vma->vm_flags & VM_MAYSHARE;
}
#else
#define get_unmapped_area_mem   NULL

static inline int private_mapping_ok(struct vm_area_struct *vma)
{
  return 1;
}
#endif

static int mmap_mem(struct file * file, struct vm_area_struct * vma)
{
  size_t size = vma->vm_end - vma->vm_start;
  
  if (!valid_mmap_phys_addr_range(vma->vm_pgoff, size))
    return -EINVAL;
  
  if (!private_mapping_ok(vma))
    return -ENOSYS;
  
  vma->vm_page_prot = my_phys_mem_access_prot(file, vma->vm_pgoff,
					      size,
					      vma->vm_page_prot);
  
  /* Remap-pfn-range will mark the range VM_IO and VM_RESERVED */
  if (remap_pfn_range(vma,
		      vma->vm_start,
		      vma->vm_pgoff,
		      size,
		      vma->vm_page_prot))
    return -EAGAIN;
  return 0;
}

static int mmap_kmem(struct file * file, struct vm_area_struct * vma)
{
  unsigned long pfn;
  
  /* Turn a kernel-virtual address into a physical page frame */
  pfn = __pa((u64)vma->vm_pgoff << PAGE_SHIFT) >> PAGE_SHIFT;
  
  /*
   * RED-PEN: on some architectures there is more mapped memory
   * than available in mem_map which pfn_valid checks
   * for. Perhaps should add a new macro here.
   *
   * RED-PEN: vmalloc is not supported right now.
   */
  if (!pfn_valid(pfn))
    return -EIO;
  
  vma->vm_pgoff = pfn;
  return mmap_mem(file, vma);
}

static int my_permission(struct inode *inode, int op)
{
  /* 
   * only root (uid 0) may read from it 
   */
  if (debug)
    {
      printk(KERN_INFO "samhain_kmem: permission op = %d, current->euid = %d\n", 
	     op, (int)current->TASK_EUID );
    }

  if ((op & 4) != 0 && (op & 2) == 0 && current->TASK_EUID == 0)
    {
      if (debug)
	{
	  printk(KERN_INFO "samhain_kmem: access granted\n" );
	}
      return 0;
    }
  
  /* 
   * If it's anything else, access is denied 
   */
  if ((op & 2) != 0)
    {
      printk(KERN_INFO "/proc/kmem: access denied, "
	     "permission op = %d, current->euid = %d\n", 
	     op, (int)current->TASK_EUID );
    }
  else if (debug)
    {
      printk(KERN_INFO "samhain_kmem: access denied\n" );
    }
  return -EACCES;
}

static struct inode_operations Inode_Ops_Kmem = {
  .permission = my_permission,	/* check for permissions */
};

static int open_kmem(struct inode * inode, struct file * filp)
{
  int ret = capable(CAP_SYS_RAWIO) ? 0 : -EPERM;

  if (debug)
    {
      printk(KERN_INFO "samhain_kmem: open_kmem retval = %d\n", ret);
    }

  if (ret == 0)
    try_module_get(THIS_MODULE);

  if (debug)
    {
      printk(KERN_INFO "samhain_kmem: open_kmem return\n");
    }

  return ret;
}

static int close_kmem(struct inode *inode, struct file *file)
{
  if (debug)
    {
      printk(KERN_INFO "samhain_kmem: close_kmem enter\n");
    }

  module_put(THIS_MODULE);

  if (debug)
    {
      printk(KERN_INFO "samhain_kmem: close_kmem return\n");
    }

  return 0;		/* success */
}

/*********************************************************************
 *
 *   >>>  Required info from System.map: vmlist_lock, vmlist  <<<
 */
static rwlock_t * sh_vmlist_lock_ptr = (rwlock_t *) SH_VMLIST_LOCK;

static struct vm_struct * sh_vmlist   = (struct vm_struct *) SH_VMLIST;
/*
 *
 *********************************************************************/

static long my_vread(char *buf, char *addr, unsigned long count)
{
        struct vm_struct *tmp;
        char *vaddr, *buf_start = buf;
        unsigned long n;

        /* Don't allow overflow */
        if ((unsigned long) addr + count < count)
                count = -(unsigned long) addr;

        read_lock(sh_vmlist_lock_ptr);
        for (tmp = sh_vmlist; tmp; tmp = tmp->next) {
                vaddr = (char *) tmp->addr;
                if (addr >= vaddr + tmp->size - PAGE_SIZE)
                        continue;
                while (addr < vaddr) {
                        if (count == 0)
                                goto finished;
                        *buf = '\0';
                        buf++;
                        addr++;
                        count--;
                }
                n = vaddr + tmp->size - PAGE_SIZE - addr;
                do {
                        if (count == 0)
                                goto finished;
                        *buf = *addr;
                        buf++;
                        addr++;
                        count--;
                } while (--n > 0);
        }
finished:
        read_unlock(sh_vmlist_lock_ptr);
	if (debug)
	  {
	    printk(KERN_INFO "samhain_kmem:  start %lu\n", (unsigned long) buf_start);
	    printk(KERN_INFO "samhain_kmem:  end   %lu\n", (unsigned long) buf);
	    printk(KERN_INFO "samhain_kmem:  size  %lu\n", (unsigned long) (buf - buf_start));
	  }
        return buf - buf_start;
}

static ssize_t read_kmem(struct file *file, char __user *buf, 
                         size_t count, loff_t *ppos)
{
  unsigned long p = *ppos;
  ssize_t low_count, read, sz;
  char * kbuf; /* k-addr because vread() takes vmlist_lock rwlock */
  
  if (debug) {
    printk(KERN_INFO "samhain_kmem: read_kmem entry\n");
    printk(KERN_INFO "samhain_kmem:  p    %lu\n", (unsigned long) p);
    printk(KERN_INFO "samhain_kmem:  high %lu\n", (unsigned long) high_memory);
  }
 
  read = 0;
  if (p < (unsigned long) high_memory) {
    low_count = count;

    if (debug) {
      printk(KERN_INFO "samhain_kmem:  low_count(1)  %ld\n", (long) low_count);
    }

    if (count > (unsigned long) high_memory - p)
      low_count = (unsigned long) high_memory - p;
    
    if (debug) {
      printk(KERN_INFO "samhain_kmem:  low_count(2)  %ld\n", (long) low_count);
    }

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
    /* we don't have page 0 mapped on sparc and m68k.. */
    if (p < PAGE_SIZE && low_count > 0) {
      size_t tmp = PAGE_SIZE - p;
      if (tmp > low_count) tmp = low_count;
      if (clear_user(buf, tmp))
	{
	  if (debug) {
	    printk(KERN_INFO "samhain_kmem: Bad address, line %d\n", __LINE__);
	  }
	  return -EFAULT;
	}
      buf += tmp;
      p += tmp;
      read += tmp;
      low_count -= tmp;
      count -= tmp;
    }
#endif

    if (debug) {
      printk(KERN_INFO "samhain_kmem:  low_count(3)  %ld\n", (long) low_count);
    }

    while (low_count > 0) {
      /*
       * Handle first page in case it's not aligned
       */
      if (-p & (PAGE_SIZE - 1))
	sz = -p & (PAGE_SIZE - 1);
      else
	sz = PAGE_SIZE;
      
      sz = min_t(unsigned long, sz, low_count);
      
      /*
       * On ia64 if a page has been mapped somewhere as
       * uncached, then it must also be accessed uncached
       * by the kernel or data corruption may occur
       */
      kbuf = xlate_dev_kmem_ptr((char *)p);
      
      if (copy_to_user(buf, kbuf, sz))
	{
	  if (debug) {
	    printk(KERN_INFO "samhain_kmem: Bad address, line %d\n", __LINE__);
	    printk(KERN_INFO "samhain_kmem:  size %ld\n", (long) sz);
	    printk(KERN_INFO "samhain_kmem:  kbuf %p\n", kbuf);
	    printk(KERN_INFO "samhain_kmem:  buf  %p\n", buf);
	    printk(KERN_INFO "samhain_kmem:  high %lu\n", (unsigned long) high_memory);
	  }
	  return -EFAULT;
	}
      buf += sz;
      p += sz;
      read += sz;
      low_count -= sz;
      count -= sz;
      if (debug) {
	printk(KERN_INFO "samhain_kmem:  low_count(4)  %ld\n", (long) low_count);
      }
    }
  }

  if (debug) {
    printk(KERN_INFO "samhain_kmem: read_kmem mid\n");
    printk(KERN_INFO "samhain_kmem:  count  %lu\n", (unsigned long) count);
  }

  if (count > 0) {
    kbuf = (char *)__get_free_page(GFP_KERNEL);
    if (!kbuf)
      {
	if (debug) {
	  printk(KERN_INFO "samhain_kmem: out of memory\n");
	}
	return -ENOMEM;
      }
    while (count > 0) {
      int len = count;
      
      if (len > PAGE_SIZE)
	len = PAGE_SIZE;
      len = my_vread(kbuf, (char *)p, len);
      if (!len)
	break;
      if (copy_to_user(buf, kbuf, len)) {
	if (debug) {
	  printk(KERN_INFO "samhain_kmem: Bad address, line %d\n", __LINE__);
	  printk(KERN_INFO "samhain_kmem:  size %ld\n", (long) len);
	  printk(KERN_INFO "samhain_kmem:  kbuf %p\n", kbuf);
	  printk(KERN_INFO "samhain_kmem:  buf  %p\n", buf);
	  printk(KERN_INFO "samhain_kmem:  high %lu\n", (unsigned long) high_memory);
	}
	free_page((unsigned long)kbuf);
	return -EFAULT;
      }
      count -= len;
      buf += len;
      read += len;
      p += len;
    }
    free_page((unsigned long)kbuf);
  }
  *ppos = p;
  if (debug) {
    printk(KERN_INFO "samhain_kmem: read_kmem end\n");
    printk(KERN_INFO "samhain_kmem:  read  %ld\n", (long) read);
  }
  return read;
}


static loff_t memory_lseek(struct file * file, loff_t offset, int orig)
{
  loff_t ret;
 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35) 
  mutex_lock(&file->f_dentry->d_inode->i_mutex);
#else
  mutex_lock(&file->f_path.dentry->d_inode->i_mutex);
#endif

  switch (orig) {
  case 0:
    file->f_pos = offset;
    ret = file->f_pos;
    force_successful_syscall_return();
    break;
  case 1:
    file->f_pos += offset;
    ret = file->f_pos;
    force_successful_syscall_return();
    break;
  default:
    if (debug) {
      printk(KERN_INFO "samhain_kmem: invalid input %d\n", orig);
    }
    ret = -EINVAL;
  }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35) 
  mutex_unlock(&file->f_dentry->d_inode->i_mutex);
#else
  mutex_unlock(&file->f_path.dentry->d_inode->i_mutex);
#endif
  return ret;
}

static const struct file_operations File_Ops_Kmem = {
  .llseek            = memory_lseek,
  .read              = read_kmem,
  .mmap              = mmap_kmem,
  .open              = open_kmem,
  .release           = close_kmem,
  .get_unmapped_area = get_unmapped_area_mem,
};


/* Init function called on module entry 
 */
static int my_module_init( void )
{
  int ret = 0;

  proc_entry = create_proc_entry( "kmem", 0400, NULL ); 

  if (proc_entry == NULL) {
    
    ret = -ENOMEM;
    
    printk(KERN_INFO "samhain_kmem: Couldn't create proc entry\n");
    
  } else {
    
/* 2.6.30 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    proc_entry->owner     = THIS_MODULE;
#endif
    proc_entry->proc_iops = &Inode_Ops_Kmem;
    proc_entry->proc_fops = &File_Ops_Kmem;
    
    proc_entry->uid       = 0;
    proc_entry->gid       = 0;
    proc_entry->mode      = S_IFREG | S_IRUSR;
    
    if (debug) {
      printk(KERN_INFO "samhain_kmem: module is now loaded.\n");
    }
  }

  return ret;
}

/* Cleanup function called on module exit */

static void my_module_cleanup( void )
{
  remove_proc_entry("kmem", NULL);

  if (debug) {
    printk(KERN_INFO "samhain_kmem: module is now unloaded.\n");
  }
  return;
}



/* Declare entry and exit functions */

module_init( my_module_init );

module_exit( my_module_cleanup );
