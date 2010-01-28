
#ifndef SH_KERN_H
#define SH_KERN_H

#include "sh_modules.h"

#ifdef SH_USE_KERN
int sh_kern_init  (struct mod_type * arg);
int sh_kern_timer (time_t tcurrent);
int sh_kern_check (void);
int sh_kern_end   (void);
int sh_kern_null  (void);

int sh_kern_set_activate (const char * c);
int sh_kern_set_severity (const char * c);
int sh_kern_set_timer    (const char * c);
int sh_kern_set_idt      (const char * c);
int sh_kern_set_pci      (const char * c);
int sh_kern_set_sct_addr (const char * c);
int sh_kern_set_sc_addr  (const char * c);
int sh_kern_set_proc_root (const char * c);
int sh_kern_set_proc_root_lookup (const char * c);
int sh_kern_set_proc_root_iops (const char * c);

extern sh_rconf sh_kern_table[];
#endif

/* #ifndef SH_UTMP_H */
#endif
