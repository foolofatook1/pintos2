#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include <stdbool.h>

typedef int tid_t;

struct process
{

	tid_t tid;
	
	struct list_elem elem;
	struct semaphore exit_sema;
	
	int exit_status;
	bool waited_for;
	bool has_exited;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_kill (void);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
