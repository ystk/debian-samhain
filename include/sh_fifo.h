
#ifndef SH_FIFO_H
#define SH_FIFO_H

/*****************************************************
 *
 * the maximum number of entries the fifo will hold
 * - additional entries are simply not accepted -
 *
 *****************************************************/

#define SH_FIFO_MAX 16384

/*****************************************************
 *
 * the type definitions for the fifo
 *
 *****************************************************/

struct dlist {
  struct dlist * next;
  char         * data;
  char         * s_xtra;
  int            i_xtra;
  int            transact;
  struct dlist * prev;
};

typedef struct fifo_str {
  struct dlist * head_ptr;
  struct dlist * tail_ptr;
  int            fifo_cts;
} SH_FIFO;

/*****************************************************
 *
 * fifo functions
 *
 *****************************************************/

/* Initialize the list.
 *
 */
#define fifo_init(fifo_p) { fifo_p->fifo_cts = 0; fifo_p->head_ptr = NULL; \
 fifo_p->tail_ptr = NULL; }


/* Push an item on the head of the list.
 *
 * Returns: -1 if the list is full, 0 on success 
 */
int push_list (SH_FIFO * fifo, char * indat, int in_i, const char * in_str);

/* Push an item on the tail of the list.
 *
 * Returns: -1 if the list is full, 0 on success 
 */
int push_tail_list (SH_FIFO * fifo, char * indat, int in_i, const char * in_str);

/* pop an item from the tail of the list
 *
 * Returns: NULL if the list is empty, 
 *          freshly allocated memory on success (should be free'd by caller) 
 */
char * pop_list (SH_FIFO * fifo);


sh_string * tag_list (SH_FIFO * fifo, char * tag,
		      int(*check)(int, const char*, const char*, const void*),
		      const void * info, int okNull);
void rollback_list (SH_FIFO * fifo);
void mark_list (SH_FIFO * fifo);
void reset_list (SH_FIFO * fifo);
int commit_list (SH_FIFO * fifo);

#endif
