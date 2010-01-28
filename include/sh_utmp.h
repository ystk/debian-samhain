
#ifndef SH_UTMP_H
#define SH_UTMP_H

#include "sh_modules.h"

#ifdef SH_USE_UTMP
int sh_utmp_init   (struct mod_type * arg);
int sh_utmp_timer  (time_t tcurrent);
int sh_utmp_check  (void);
int sh_utmp_end    (void);
int sh_utmp_reconf (void);

int sh_utmp_set_login_activate (const char * c);
int sh_utmp_set_login_solo     (const char * c);
int sh_utmp_set_login_multi    (const char * c);
int sh_utmp_set_logout_good    (const char * c);
int sh_utmp_set_login_timer    (const char * c);

extern sh_rconf sh_utmp_table[];
#endif

/* #ifndef SH_UTMP_H */
#endif
