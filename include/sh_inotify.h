#ifndef SH_INOTIFY_H
#define SH_INOTIFY_H

#define SH_INOTIFY_MAX 128

typedef struct 
{
  int    watch[SH_INOTIFY_MAX];
  int    flag[SH_INOTIFY_MAX];
  char * file[SH_INOTIFY_MAX];
  int    count;

} sh_watches;

int sh_inotify_wait_for_change(char * filename, sh_watches * watches, 
			       int  * errnum,   int waitsec);

int sh_inotify_add_watch(char * filename, sh_watches * watches, int  * errnum);

void sh_inotify_remove(sh_watches * watches);

#define SH_INOTIFY_ERROR(a) (a != 0)

#endif
