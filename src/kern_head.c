/* 
 * need to #define SH_USE_KERN
 *
 */
#define SH_SYSCALL_CODE

#include "config.h"

#if defined(HOST_IS_I86LINUX) || defined(HOST_IS_64LINUX)
#define SH_IDT_TABLE
#endif

#include <stdio.h>
#include <stdlib.h>

#if defined(SH_USE_KERN) 

#undef _
#define _(string)  string
#undef N_
#define N_(string) string

void usage(int flag)
{
  printf("\n");
  printf("Usage: kern_head [-v | --verbose]\n");
  printf("       kern_head [-h | --help]\n");
  printf("\n");
  /*
   * printf("       You need superuser privileges to use this program,\n");
   * printf("       because only the superuser can read from /dev/kmem.\n");
   * printf("\n");
   */
  exit(flag);
}

#if defined(HOST_IS_LINUX)


#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/utsname.h>
#include <sys/mman.h>

/* number of system calls */
#define SH_MAXCALLS 512

#include "kern_head.h"

static int verbose = 0;

typedef struct _smap_entry {
#ifdef SH_SYSCALL_CODE
  unsigned int  code[2];  /* 8 bytes */
#endif
  unsigned long addr;
  char          name[64];
} smap_entry;

union {
  unsigned long addr_sys_call_table;
  unsigned char str_sys_call_table[sizeof(unsigned long)];
} sh_sys_call;

#define SYS_CODE_SIZE 1024

static unsigned long addr_system_call;
static unsigned char system_call_code[SYS_CODE_SIZE];

#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

static int kmem_read (int fd, unsigned long addr, unsigned char * buf, int len)
{
  if (lseek(fd, addr, SEEK_SET) == (off_t) (-1))
    {
      if (verbose)
	perror("kmem_read: lseek");
      return -1;
    }
  if (read(fd, buf, len) < 0)
    {
      if (verbose)
	perror("kmem_read: read");
      return -1;
    }
  return 0;
}

static int kmem_mmap (int fd, unsigned long addr, unsigned char * buf, int len)
{
  size_t    moff, roff;
  size_t    sz;
  char    * kmap;

  sz = getpagesize(); /* unistd.h */

  moff = ((size_t)(addr/sz)) * sz;                 /* lower page boundary */
  roff = addr - moff;    /* off relative to lower address of mmapped area */
  kmap = mmap(0, len+sz, PROT_READ, MAP_PRIVATE, fd, moff);/* sys/mman.h */

  if (kmap == MAP_FAILED)
    {
      /* then, try read()
       */
      if (verbose)
	fprintf(stderr, "kmem_mmap: mmap() failed, now trying read()\n");

      if (0 == kmem_read (fd, addr, buf, len))
	return 0;

      perror("kmem_mmap: mmap");
      return -1;
    }

  memcpy (buf, &kmap[roff], len);
      
  if (munmap(kmap, len+sz) != 0)
    {
      perror("kmem_mmap: munmap");
      return -1;
    }

  return 0;
}

int read_kcode (unsigned long addr, unsigned char * buf, int len)
{
  int fd;

  if (addr == 0UL)
    {
      perror("read_kcode: invalid input");
      return -1;
    }

  fd = open ("/dev/kmem", O_RDONLY);

  if (fd < 0)
    {
      if (verbose)
	fprintf(stderr, "read_kcode: /dev/kmem failed, now trying /proc/kmem\n");

      if (0 != access("/proc/kmem", R_OK)) 
	{
	  perror("read_kcode: access /proc/kmem");

	  fprintf(stderr, "\n");
      
	  fprintf(stderr, "NOTE:  kern_head: apparently you have no /dev/kmem, and the\n");
	  fprintf(stderr, "       samhain_kmem module is not loaded\n");
	  fprintf(stderr, "       If you get this message, please proceed as follows:\n");
	  fprintf(stderr, "       $ make samhain_kmem.ko\n");
	  fprintf(stderr, "       $ sudo /sbin/insmod samhain_kmem.ko; sudo ./kern_head > sh_ks.h; sudo /sbin/rmmod samhain_kmem\n");
	  fprintf(stderr, "       $ make\n\n");
	  exit (EXIT_FAILURE);
	}
      fd = open ("/proc/kmem", O_RDONLY);
    }

  if (fd < 0)
    {
      perror("read_kcode: open /dev/kmem and /proc/kmem");
      return -1;
    }

  if (kmem_mmap(fd, addr, buf, len) < 0)
    {
      close (fd);
      return -1;
    }

  close (fd);

  return 0;
}

int get_dispatch (int * qq)
{
  int i;

  if (addr_system_call == 0L || sh_sys_call.addr_sys_call_table == 0L)
    {
      fprintf(stderr, "get_dispatch: invalid data\n");
      return -1;
    }

  if (0 != read_kcode (addr_system_call, system_call_code, SYS_CODE_SIZE))
    {
      fprintf(stderr, "get_dispatch: could not read system_call code\n");
      return -1;
    }

  for (i = 0; i < (SYS_CODE_SIZE - 4); ++i)
    {
      if (system_call_code[i]   == sh_sys_call.str_sys_call_table[0] &&
	  system_call_code[i+1] == sh_sys_call.str_sys_call_table[1] &&
	  system_call_code[i+2] == sh_sys_call.str_sys_call_table[2] &&
	  system_call_code[i+3] == sh_sys_call.str_sys_call_table[3])
	{
	  /*
	    fprintf(stderr, "INFO: get_dispatch: found sys_call_table in "\
		    "system_call code at %d\n", i);
	  */
	  *qq = i;
	  return 0;
	}
    }
  fprintf(stderr, 
	  "get_dispatch: did not find sys_call_table in system_call code\n");
  fprintf(stderr, 
	  "** This indicates that either your System.map does not match\n");
  fprintf(stderr,
	  "** the currently running kernel, or that your System.map does\n");
  fprintf(stderr,
	  "** not provide the required information, and thus use of\n");
  fprintf(stderr,
	  "** the --with-kcheck option is not possible\n");
  return -1;
}

unsigned long get_symbol_from_systemmap (char * systemmap, 
                                         char * symbol, char flag)
{
  FILE * fp;
  char buf[512], addr[32], * p;
  unsigned long retval = 0;
#if defined(__x86_64__) || defined(__amd64__)
  int off = 8;
#else
  int off = 0;
#endif

  fp = fopen (systemmap, "r");

  if (!fp)
    {
      fprintf(stderr, "error opening <%s>\n", systemmap);
      perror("get_symbol_from_systemmap: fopen");
      return -1;
    }
  while (fgets(buf, 512, fp) != NULL)
    {
      if (buf[9+off] != flag)
        continue;

      p = strchr(buf, '\n');
      if (p != NULL)
        *p = '\0';

      if (0 != strcmp(&buf[11+off], symbol))
        continue;

      addr[0] = '0'; addr[1] = 'x'; addr[2] = '\0';
      strncat(&addr[2], buf, 8+off);

      retval = strtoul(addr, NULL, 0);
      if (retval == ULONG_MAX)
        {
          perror("get_symbol_from_systemmap");
          return -1;
        }
    }
  fclose(fp);
  return retval;
}


/* returns the number N of entries in syscall table
 * (0 .. N-1) with valid syscalls
 */
int fill_smap(smap_entry * sh_smap, int num)
{
  FILE * fp;
  char buf[512], addr[32], name[128];
  int  i, j, count = 0, maxcall = 0;
#if defined(__x86_64__) || defined(__amd64__)
  int off = 8;
#else
  int off = 0;
#endif

  fp = fopen (SYSTEMMAP, "r");

  if (!fp)
    {
      perror("fill_smap: fopen");
      fprintf(stderr, "fill_smap: error opening <%s>\n", SYSTEMMAP);
      return -1;
    }

  /* initialize
   */
  sh_sys_call.addr_sys_call_table = 0L;

  while (fgets(buf, 512, fp) != NULL)
    {
      
      if ( ( (buf[9+off] == 'D') || (buf[9+off] == 'd') || 
	     (buf[9+off] == 'R') || (buf[9+off] == 'r')) && 
	   0 == strncmp("sys_call_table", &buf[11+off], 14))
	{
	  printf("/* found sys_call_table */\n");
	  /* --- copy symbol address ---
	   */
	  addr[0] = '0'; addr[1] = 'x'; addr[2] = '\0';
	  strncat(&addr[2], buf, 8+off);
	  addr[10+off] = '\0';

	  sh_sys_call.addr_sys_call_table = strtoul(addr, NULL, 0);
	  if (sh_sys_call.addr_sys_call_table == ULONG_MAX)
	    {
	      perror("fill_smap");
	      return -1;
	    }
	  else
	    {
	      printf("#define SH_SYS_CALL_TABLE %s\n", addr);
	    }
	}

      if (buf[9+off] != 'T')
	continue;

      if (0 == strncmp("system_call", &buf[11+off], 11))
	{
	  printf("/* found system_call */\n");
	  /* --- copy symbol address ---
	   */
	  addr[0] = '0'; addr[1] = 'x'; addr[2] = '\0';
	  strncat(&addr[2], buf, 8+off);
	  addr[10+off] = '\0';
	  addr_system_call = strtoul(addr, NULL, 0);
	  if (addr_system_call == ULONG_MAX)
	    {
	      perror("fill_smap");
	      return -1;
	    }
	}


      if ( (buf[11+off]!='s' || buf[12+off]!='y' || 
	    buf[13+off]!='s' || buf[14+off]!='_') &&
	   (buf[11+off]!='o' || buf[12+off]!='l' || 
	    buf[13+off]!='d' || buf[14+off]!='_'))
	continue;

      for (i = 0; i < num; ++i)
	{
	  for (j = 0; j < 127; ++j)
	    {
	      if (buf[11+off+j] == '\n' || buf[11+off+j] == '\0')
		{
		  name[j] = '\0';
		  break;
		}
	      name[j] = buf[11+off+j];
	    }


	  if (0 == strcmp(name, sh_smap[i].name)) 
	    {
	      
	      /* --- copy symbol address ---
	       */
	      addr[0] = '0'; addr[1] = 'x'; addr[2] = '\0';
	      strncat(&addr[2], buf, 8+off);
	      addr[10+off] = '\0';
	      sh_smap[i].addr = strtoul(addr, NULL, 0);
	      if (sh_smap[i].addr == ULONG_MAX)
		{
		  perror("fill_smap");
		  return -1;
		}
	      ++count;
	      if (i > maxcall) maxcall = i;
	      /* printf("maxcall = %d\n", maxcall); */
	      /* break; */
      	    }
	}
    }
  fclose(fp);

  if ((count > 0) && (maxcall > 0))
    return maxcall+1;
  else
    return count;
}


int main(int argc, char * argv[])
{
  int i, count, maxcall, qq;
  smap_entry sh_smap[SH_MAXCALLS];
  struct utsname utbuf;
  char *p = NULL;

  unsigned long proc_root;
  unsigned long proc_root_iops;
  unsigned long proc_root_lookup;

  unsigned long addr_ni_syscall = 0;

  int major, minor, micro, is64 = 0;

  if (argc > 1)
    {
      if (strcmp(argv[1], "-h") == 0 ||  strcmp(argv[1], "--help") == 0)
	usage(EXIT_SUCCESS);
      else if (strcmp(argv[1], "-v") == 0 ||
	       strcmp(argv[1], "--verbose") == 0)
	verbose = 1;
    }

  if (0 != uname(&utbuf))
    {
      perror("kern_head: uname");
      exit (EXIT_FAILURE);
    }

  if (strncmp(utbuf.release, SH_KERNEL_VERSION, 3) != 0)
    {
      fprintf(stderr, "kern_head: current kernel version %s does not match\n",
	      utbuf.release);
      fprintf(stderr, "kern_head: %s from config.h\n", SH_KERNEL_VERSION);
      fprintf(stderr, "kern_head: continuing with %s\n", SH_KERNEL_VERSION);

      p = SH_KERNEL_VERSION;
    } else {
      p = utbuf.release;
    }

  if (3 != sscanf(p, "%d.%d.%d", &major, &minor, &micro))
    {
      perror("kern_head: sscanf");
      exit (EXIT_FAILURE);
    }

  if (major == 2)
    {
      if (minor != 4 && minor != 6)
	{
	  fprintf(stderr, "kern_head: kernel %s not supported\n", p);
	  exit (EXIT_FAILURE);
	}
    }

  
  if (utbuf.machine[0] != 'i' || utbuf.machine[2] != '8' || 
      utbuf.machine[3] != '6')
    {
      if (0 != strcmp(utbuf.machine, "x86_64"))
	{
	  fprintf(stderr, "kern_head: machine %s not supported\n", utbuf.machine);
	  exit (EXIT_FAILURE);
	}
      else
	{
	  is64 = 1;
	}
    }

  if (0 != getuid())
    {
      fprintf(stderr, "\n");
      
      fprintf(stderr, "NOTE:  kern_head: must run as 'root' (need to read from /dev/kmem)\n");
      fprintf(stderr, "       If you get this message, then proceed as follows:\n");
      fprintf(stderr, "       $ sudo ./kern_head > sh_ks.h\n");
      fprintf(stderr, "       $ make\n\n");
      exit (EXIT_FAILURE);
    }
      
  printf("#ifndef SH_KERN_CALLS_H\n");
  printf("#define SH_KERN_CALLS_H\n\n");

  printf("\n/* Kernel %s, machine %s, %d bit -- use table callz_2p4 */\n\n", 
	 p, utbuf.machine,
	 (is64 == 0) ? 32 : 64,
	 (is64 == 0) ? "syscalls_32" : "syscalls_64");

  /* initiate the system call table 
   */
  if (is64 == 0)
    {
      for (i = 0; i < SH_MAXCALLS; ++i)
	{
	  if (syscalls_32[i] == NULL)
	    break;
	  strcpy(sh_smap[i].name, syscalls_32[i]);
	  sh_smap[i].addr    = 0UL;
	}
      if (major > 2 || minor == 6) /* fix syscall map for 2.6 */
	{
	  strcpy(sh_smap[0].name,   "sys_restart_syscall");
	  strcpy(sh_smap[180].name, "sys_pread64");
	  strcpy(sh_smap[181].name, "sys_pwrite64");
	}
    }
  else /* x86_64 */
    {
      for (i = 0; i < SH_MAXCALLS; ++i)
	{
	  if (syscalls_64[i] == NULL)
	    break;
	  strcpy(sh_smap[i].name, syscalls_64[i]);
	  sh_smap[i].addr    = 0UL;
	}
    }

  count = i;

  /* get the actual number of the highest syscall and use no more.
   * get sys_call_table and system_call
   */
  maxcall = fill_smap(sh_smap, count);
  if ( maxcall < 0)
    {
      printf("#endif\n");
      fprintf(stderr, "kern_head: fill_smap failed\n");
      exit (EXIT_FAILURE);
    }

  if (addr_system_call == 0L) 
    {
      printf("#endif\n");
      fprintf(stderr, 
	      "kern_head: address of system_call not found in System.map\n");
      fprintf(stderr, 
	      "** This indicates that your System.map does not provide\n");
      fprintf(stderr, 
	      "** the required information, and thus use of the\n");
      fprintf(stderr, 
	      "** --with-kcheck option is not possible\n");
      exit (EXIT_FAILURE);
    }

  for (i = 0; i < maxcall; ++i)
    {
      if (0 == strcmp(sh_smap[i].name, "sys_ni_syscall"))
        {
          addr_ni_syscall = sh_smap[i].addr;
          break;
        }
    }

  if (minor < 6)
    {
      maxcall = (maxcall > 256) ? 256 : maxcall;
    }

  for (i = 0; i < maxcall; ++i)
    {
      if (sh_smap[i].addr == 0UL)
        {
          if (verbose > 0)
            fprintf(stderr, "** unknown syscall **: [%s]\n", sh_smap[i].name);
          strcpy(sh_smap[i].name, "sys_ni_syscall");
          sh_smap[i].addr = addr_ni_syscall;
        }
    }


  /* get the location of the syscall table address within system_call
   */
  if ( get_dispatch (&qq) < 0)
    {
      printf("#endif\n");
      fprintf(stderr, "kern_head: get_dispatch failed\n");
      exit (EXIT_FAILURE);
    }

  if (qq <= 252)
    printf("#define SYS_CALL_LOC  %d\n", qq);
  else
    {
      printf("#endif\n");
      fprintf(stderr, "kern_head: SYS_CALL_LOC (%d) too large\n", qq);
      exit(EXIT_FAILURE);
    }
  printf("#define SH_SYS_CALL_ADDR %#lx\n\n", addr_system_call);

  printf("static unsigned char system_call_code[256] = { 0 };\n");

  printf("#define SH_MAXCALLS %d\n\n", maxcall);

#ifdef SH_IDT_TABLE
  printf("static unsigned char idt_table[2048] = { 0 };\n");
#endif

  printf("typedef struct _sh_syscall_t {\n");
#ifdef SH_SYSCALL_CODE
  printf("  unsigned int  code[2];  /* 8 bytes */\n");
#endif
  printf("  unsigned long addr;\n");
  printf("  char *        name;\n");
  printf("} sh_syscall_t;\n\n");

  printf("static sh_syscall_t sh_syscalls[] = {\n");

  for (i = 0; i < maxcall; ++i) 
    {
#ifdef SH_SYSCALL_CODE
      printf(" /* %03d */   { { 0, 0 }, 0, N_(%c%s%c) },\n", 
	     i, '"', sh_smap[i].name, '"');
#else
      printf(" /* %03d */   { 0, N_(%c%s%c) },\n", 
	     i, '"', sh_smap[i].name, '"');
#endif
    }
#ifdef SH_SYSCALL_CODE
  printf(" /* eof */   { { 0x00000000, 0x00000000 }, 0x00000000,  NULL }\n");
#else
  printf(" /* eof */   { 0x00000000,  NULL }\n");
#endif
  printf("};\n\n");


  /* get proc addresses
   */
  proc_root =  get_symbol_from_systemmap (SYSTEMMAP, 
                                          "proc_root", 'D');
  if (proc_root == 0) 
    {
      proc_root =  get_symbol_from_systemmap (SYSTEMMAP, 
                                              "proc_root", 'd');
    }
  if (proc_root == 0) 
    {
      proc_root =  get_symbol_from_systemmap (SYSTEMMAP, 
                                              "proc_root", 'R');
    }
  if (proc_root != 0) {
    printf("#define PROC_ROOT_LOC %#lx\n\n", proc_root);
  }

  proc_root_lookup =  get_symbol_from_systemmap (SYSTEMMAP, 
                                                 "proc_root_lookup", 't');
  if (proc_root_lookup == 0) 
    {
      proc_root_lookup =  get_symbol_from_systemmap (SYSTEMMAP, 
                                                     "proc_root_lookup", 'T');
    }
  if (proc_root_lookup != 0) {
    printf("#define PROC_ROOT_LOOKUP_LOC %#lx\n\n", proc_root_lookup);
  }

  proc_root_iops =  get_symbol_from_systemmap (SYSTEMMAP, 
                                               "proc_root_inode_operations", 
                                               'd');
  if (proc_root_iops == 0) 
    {
      proc_root_iops = get_symbol_from_systemmap (SYSTEMMAP, 
                                                  "proc_root_inode_operations",
                                                  'D');
    }
  if (proc_root_iops == 0) 
    {
      proc_root_iops = get_symbol_from_systemmap (SYSTEMMAP, 
                                                  "proc_root_inode_operations",
                                                  'R');
    }
  if (proc_root_iops != 0) {
    printf("#define PROC_ROOT_IOPS_LOC %#lx\n\n", proc_root_iops);
  }

  if (KERNEL_VERSION(major,minor,micro) >= KERNEL_VERSION(2,6,17)) 
    {
      printf("#define TWO_SIX_SEVENTEEN_PLUS 1\n\n");
    }

  printf("#endif\n");

  exit (EXIT_SUCCESS);
}

/* if defined(HOST_IS_LINUX) */
#endif

/************************************************************
 *
 *
 *  FreeBSD Implementation
 *
 ************************************************************/

#if defined(HOST_IS_FREEBSD) || defined(__OpenBSD__)

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <kvm.h>
#include <fcntl.h>
#include <nlist.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/utsname.h>

#ifdef __FreeBSD__
#include <sys/sysent.h>
#endif

#include <sys/syscall.h>

#ifndef  SYS_MAXSYSCALL
#define  SYS_MAXSYSCALL	512
#endif

/* number of system calls */
#define SH_MAXCALLS 512
#include "kern_head.h"
static int verbose = 0;

#ifdef __OpenBSD__
struct proc;
struct sysent {
	short sy_narg;
	short sy_argsize;
	int   (*sy_call)(struct proc *, void *, register_t *);
};
#endif

typedef struct _smap_entry {
  unsigned int  code[2];  /* 8 bytes */
  unsigned long addr;
  char          name[64];
} smap_entry;

union {
  unsigned long addr_sys_call_table;
  unsigned char str_sys_call_table[sizeof(unsigned long)];
} sh_sys_call;

struct nlist sys_list[SYS_MAXSYSCALL+1];

struct  nlist   list[2];


int main(int argc, char * argv[])
{
  int i, count, which;
  smap_entry sh_smap[SYS_MAXSYSCALL];
  struct utsname utbuf;
  char errbuf[_POSIX2_LINE_MAX];

  struct sysent  sy;
  unsigned long offset = 0L;
  kvm_t *kd;

  list[0].n_name = "_sysent";
  list[1].n_name = NULL;

  if (argc > 1)
    {
      if (strcmp(argv[1], "-h") == 0 ||  strcmp(argv[1], "--help") == 0)
	usage(EXIT_SUCCESS);
      else if (strcmp(argv[1], "-v") == 0 ||
	       strcmp(argv[1], "--verbose") == 0)
	verbose = 1;
    }

  if (0 != uname(&utbuf))
    {
      perror("kern_head: uname");
      exit (EXIT_FAILURE);
    }

#ifdef __OpenBSD__
  if      (utbuf.release[0] == '3')
    which = 38;
  else if (utbuf.release[0] == '4')
    which = 40;
#else
  if      (utbuf.release[0] == '4')
    which = 4;
  else if (utbuf.release[0] == '5')
    which = 5;
  else if (utbuf.release[0] == '6')
    which = 5;
#endif
  else
    {
      fprintf(stderr, "kern_head: kernel %s not supported\n", utbuf.release);
      exit (EXIT_FAILURE);
    }

  if (utbuf.machine[0] != 'i' || utbuf.machine[2] != '8' || 
      utbuf.machine[3] != '6')
    {
      fprintf(stderr, "kern_head: machine %s not supported\n", utbuf.machine);
      exit (EXIT_FAILURE);
    }

  if (0 != getuid())
    {
      fprintf(stderr, "\n");
      fprintf(stderr, "NOTE:  kern_head: must run as 'root' ");
      fprintf(stderr, "(need to read from kernel)\n");
      fprintf(stderr, "       If you get this message, then proceed ");
      fprintf(stderr, "as follows:\n");
      fprintf(stderr, "       $ su\n");
      fprintf(stderr, "       $ ./kern_head > sh_ks.h\n");
      fprintf(stderr, "       $ exit\n");
      fprintf(stderr, "       $ make\n\n");
      exit (EXIT_FAILURE);
    }

  kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);
  if (!kd)
    {
      fprintf(stderr, "check_sysent: kvm_openfiles: %s\n", errbuf);
      exit(EXIT_FAILURE);
    }

  i = kvm_nlist(kd, list);
  if (i == -1)
    {
      fprintf(stderr, "check_sysent: kvm_nlist: %s\n", kvm_geterr(kd));
      exit(EXIT_FAILURE);
    }
  else if (i == 1)
    {
      fprintf(stderr, "check_sysent: kvm_nlist: _sysent not found\n");
      exit(EXIT_FAILURE);
    }
  else if (list[0].n_value == 0)
    {
      fprintf(stderr, "check_sysent: kvm_nlist: zero address for _sysent\n");
      exit(EXIT_FAILURE);
    }

  if (which == 4)
    printf("\n/* Kernel %s, machine %s -- use table %s */\n\n", 
        	 utbuf.release, utbuf.machine, "callz_fbsd");
  else if (which == 5 || which == 6)
    printf("\n/* Kernel %s, machine %s -- use table %s */\n\n",
                 utbuf.release, utbuf.machine, "callz_fbsd5");
  else if (which == 38 || which == 40)
    printf("\n/* Kernel %s, machine %s -- use table %s */\n\n",
                 utbuf.release, utbuf.machine, "callz_obsd");
      
      
  i = 0;
  if (which == 4) {
    while ((callz_fbsd[i] != NULL) && (i < SYS_MAXSYSCALL))
      {
	sys_list[i].n_name = callz_fbsd[i];
	/* fprintf(stderr, "sys_list[%d] = %s\n", i, sys_list[i].n_name); */
	++i;
      }
    if ((utbuf.release[1] == '.') && (utbuf.release[2] == '1') && 
	(utbuf.release[3] == '0'))
      {
	sys_list[336].n_name = callz_fbsd[151]; /* sendfile -> nosys */
      }
  } else if (which == 5 || which == 6) {
    while ((callz_fbsd5[i] != NULL) && (i < SYS_MAXSYSCALL))
      {
	sys_list[i].n_name = callz_fbsd5[i];
	/* fprintf(stderr, "sys_list[%d] = %s\n", i, sys_list[i].n_name); */
	++i;
      }
  }
  else if (which == 38 || which == 40) {
    while ((callz_obsd[i] != NULL) && (i < SYS_MAXSYSCALL))
      {
	sys_list[i].n_name = callz_obsd[i];
	/* fprintf(stderr, "sys_list[%d] = %s\n", i, sys_list[i].n_name); */
	++i;
      }
  }
  
  count = i;
  sys_list[i].n_name = NULL;
   
  i = kvm_nlist(kd, sys_list);
  if (i == -1)
    {
      fprintf(stderr, "check_sysent: kvm_nlist: %s\n", kvm_geterr(kd));
      /* exit(EXIT_FAILURE); */
    }
  else if (i != 0 && verbose != 0)
     {
	fprintf(stderr, "check_sysent: kvm_nlist: %d out of %d invalid.\n",
		i, count);
	fprintf(stderr, "              Probably the table in kern_head.h\n");
	fprintf(stderr, "              is not for your kernel version.\n");
	fprintf(stderr, "              (No reason to worry, kcheck will "\
                                       "work anyway)\n\n");
     }

  for (i = 0; i < count /* SYS_MAXSYSCALL */; i++) 
    {
       if (NULL == sys_list[i].n_name)
	 break;
       if (!sys_list[i].n_value && 0 != strcmp(sys_list[i].n_name, "_nosys")
	   && verbose != 0)
	{
	  fprintf(stderr,"check_sysent: not found: slot %03d [%s]\n", 
		  i, sys_list[i].n_name);
	  /* exit(EXIT_FAILURE); */
	}
      offset = list[0].n_value + (i*sizeof(struct sysent));
      if (kvm_read(kd, offset, &sy, sizeof(struct sysent)) < 0)
	{
	  fprintf(stderr,"check_sysent: kvm_read: %s\n", kvm_geterr(kd));
	  exit(EXIT_FAILURE);
	}

      if (verbose > 0)
	fprintf(stderr, "(kvm_nlist) %#lx   %#lx (sysent[%03d])  %03d [%s]\n",
		(unsigned long) sys_list[i].n_value,
		(unsigned long) sy.sy_call,
		i, i, sys_list[i].n_name);

      if((unsigned long)sy.sy_call != sys_list[i].n_value && 
	 sys_list[i].n_value != 0 &&
	 0 != strcmp(sys_list[i].n_name, "_nosys") &&
	 (unsigned long)sy.sy_call != sys_list[151].n_value)  
	{
          fprintf(stderr,
                  "WARNING: (kvm_nlist) %#lx != %#lx (sysent[%03d])  %03d [%s]\n",
		  (unsigned long) sys_list[i].n_value,
		  (unsigned long) sy.sy_call,
		  i, i, sys_list[i].n_name);
	}
      sh_smap[i].addr = (unsigned long) sy.sy_call;
      strncpy(sh_smap[i].name, sys_list[i].n_name, 64);
      if(kvm_read(kd, (unsigned int) sy.sy_call, &(sh_smap[i].code[0]), 
		  2 * sizeof(unsigned int)) < 0)
	{
	  fprintf(stderr,"check_sysent: kvm_read: %s\n", kvm_geterr(kd));
	  exit(EXIT_FAILURE);
	}
    }

  if(kvm_close(kd) < 0) 
    {
      fprintf(stderr,"check_sysent: kvm_nlist: %s\n", kvm_geterr(kd));
      exit(EXIT_FAILURE);
    }
 
  printf("#ifndef SH_KERN_CALLS_H\n");
  printf("#define SH_KERN_CALLS_H\n\n");

  printf("#define SH_MAXCALLS %d\n\n", count);

  printf("typedef struct _sh_syscall_t {\n");
  printf("  unsigned int  code[2];  /* 8 bytes */\n");
  printf("  unsigned long addr;\n");
  printf("  char *        name;\n");
  printf("} sh_syscall_t;\n\n");

  printf("static sh_syscall_t sh_syscalls[] = {\n");
  for (i = 0; i < count; ++i) {
    printf(" /* %03d */ {{ 0x%-8.8x, 0x%-8.8x }, 0x%-8.8lx, N_(%c%s%c) },\n", 
	   i, sh_smap[i].code[0], sh_smap[i].code[1], 
	   sh_smap[i].addr, '"', sh_smap[i].name, '"');
  }
  printf(" /* eof */   { { 0x00000000, 0x00000000 }, 0x00000000,  NULL }\n");
  printf("};\n\n");
  printf("#endif\n");
  return 0;
}
/* if defined(HOST_IS_FREEBSD) */
#endif

/* #if defined(SH_USE_KERN) */
#else

#include <stdio.h>
#include <stdlib.h>

int main()
{
  printf("#ifndef SH_KERN_CALLS_H\n");
  printf("#define SH_KERN_CALLS_H\n\n");

  printf("/* Dummy header. */\n\n");

  printf("typedef struct _sh_syscall_t {\n");
  printf("  unsigned long addr;\n");
  printf("  char *        name;\n");
  printf("} sh_syscall_t;\n\n");

  printf("#endif\n");

  return (EXIT_SUCCESS);
}

/* #ifdef SH_USE_KERN */
#endif
