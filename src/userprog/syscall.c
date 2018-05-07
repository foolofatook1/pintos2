#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/block.h"

/* System calls. */
static void syscall_handler (struct intr_frame *);
static int halt (void);
static int exit (int status);
static int exec (const char *file);
static int wait (int thread_id);
static bool create (const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open (const char *file);
static size_t filesize (int fd);
static size_t read (int fd, void *buffer_, off_t length);
static int write (int fd, const void *buffer, unsigned length);
static int seek (int fd, unsigned position);
static unsigned tell (int fd);
static int close (int fd);

/* Helper functions. */
static struct file *get_file(int fd);
static void pointer_check(void *esp);
static void pointer_check_range(const void *start, off_t length);
static int allocate_fd (void);
static struct file *get_file (int fd);
void clean (void);
/* Lock for the file system. */
static struct lock filesys_lock;

struct fd_list_node
{
	int fd;
	struct file *file;
	struct list_elem elem;
};

	void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init (&filesys_lock);
}

/* Parses arguments for the stack. */
#define GET_ARGS1(type1, function) \
	pointer_check(f->esp+4); \
f->eax = function ( \
		*((type1*) (f->esp+4)) \
		);

#define GET_ARGS2(type1, type2, function) \
	pointer_check(f->esp+4); \
pointer_check(f->esp+8); \
f->eax = function ( \
		*((type1*) (f->esp+4)), \
		*((type2*) (f->esp+8)) \
		);

#define GET_ARGS3(type1, type2, type3, function) \
	pointer_check(f->esp+4); \
pointer_check(f->esp+8); \
pointer_check(f->esp+12); \
f->eax = function ( \
		*((type1*)(f->esp+4)), \
		(void*) *((uint32_t*) (f->esp+8)), \
		*((type3*) (f->esp+12)) \
		);

/* Helper Functions. */
/* Retrieves the file associated with given descriptor. */
	static struct file *
get_file (int fd)
{
	struct list_elem *itp;
	struct fd_list_node *ep = NULL;

	for (itp = list_begin(&thread_current()->fd_table);
			itp != list_end(&thread_current()->fd_table);
			itp = list_next(itp))
	{
		ep = list_entry(itp, struct fd_list_node, elem);
		if (ep->fd == fd)
			return ep->file;
	}
	return NULL;
}

/* Checks if the pointer is valid. */
	static void
pointer_check(void *esp)
{
	if(esp == NULL || pagedir_get_page(thread_current()->pagedir, esp) == NULL
			|| (uint32_t)esp > (((uint32_t)PHYS_BASE) - 4))
	{
		/* Calls thread_exit() and exit_sets status to -1. */
		process_kill();
		return;
	}
	return;
}

	static void
pointer_check_range(const void *start, off_t length)
{
	if(start + length < start)
		process_kill ();
	int32_t i;
	for(i = 0; i < length; ++i)
		pointer_check(start + i);
}

/* Allocates a unique file descriptor for the given file. */
	static int
allocate_fd (void)
{
	static struct lock fd_lock;
	lock_init(&fd_lock);

	static int next_fd = 2;
	int fd;

	lock_acquire (&fd_lock);
	fd = next_fd++;
	lock_release (&fd_lock);

	return fd;
}

/* Cleans out the fd_table and closes the file. */
	void 
clean (void)
{
	struct list_elem *it;
	struct list_elem *aux;
	struct fd_list_node *rem;

	for(it = list_begin(&thread_current()->fd_table);
			it != list_end(&thread_current()->fd_table);
			it = list_next(it))
	{
		rem = list_entry(it, struct fd_list_node, elem);
		aux = it;
		it = it->prev;

		list_remove(aux);

		lock_acquire(&filesys_lock);
		file_close(rem->file);
		lock_release(&filesys_lock);
		free(rem);
	}
}


/* System Calls. */
/* Terminates pintos by calling shutdown_power_off(). */
	static int 
halt (void)
{
	shutdown_power_off();
	NOT_REACHED();
}

/* Exits current user program, and sends the exit status to the kernel. 
   If the process's parent waits for it this status is returned. */
	static int
exit (int status)
{
	thread_current()->the_process->exit_status = status;
	thread_exit ();

	NOT_REACHED();
}

/* Runs the executable given in command line. */
	static int
exec (const char *file)
{
	pointer_check(file);

	int child_tid = process_execute(file);

	if(child_tid < 0)
		return -1;

	struct list_elem *it;
	struct process *pr = NULL;
	for (it = list_begin(&thread_current()->child_processes);
			it != list_end(&thread_current()->child_processes);
			it = list_next(it))
	{
		pr = list_entry(it, struct process, elem);
		if(pr->tid == child_tid)
			break;
	}

	sema_down (&pr->load_sema);
	if(pr->load_fail)
		return -1;

	return child_tid;
}

/* Waits for a child process pid and get child's exit status. */
	static int 
wait (int thread_id)
{
	return process_wait(thread_id);
}

/* Creates new file. Creating new file does not open it! 
   That is done in open syscall. */
	static bool
create (const char *file, unsigned initial_size)
{
	pointer_check(file);

	lock_acquire(&filesys_lock);
	bool ret = filesys_create(file, initial_size);
	lock_release(&filesys_lock);

	return ret;
}

/* Deletes the given file. Can be removed if it is open or closed. */
	static bool
remove(const char *file)
{
	pointer_check(file);

	lock_acquire(&filesys_lock);
	filesys_remove(file);
	lock_release(&filesys_lock);

	return true;
}


/* Opens given file. */
	static int
open (const char *file)
{
	pointer_check(file);

	lock_acquire(&filesys_lock);
	struct file *new_file = filesys_open(file);
	lock_release(&filesys_lock);

	if (new_file == NULL)
		return -1;
	if (strcmp(file, thread_current()->name) == 0)
		file_deny_write(new_file);

	/* find the file. */
	struct fd_list_node *new_fd = (struct fd_list_node *) 
		malloc(sizeof(struct fd_list_node));
	new_fd->fd = allocate_fd();
	new_fd->file = new_file;
	list_push_back(&(thread_current()->fd_table), &(new_fd->elem));
	return new_fd->fd;

}


/* Returns the size in bytes of the file open as fd. */
	static size_t
filesize (int fd)
{
	struct file *file = get_file(fd);

	if(file == NULL)
	{
		return 0;
	}

	lock_acquire(&filesys_lock);
	off_t ret = file_length(file);
	lock_release(&filesys_lock);

	return ret;
}

/* Reads size bytes from the file open as fd into buffer.
   Returns the number of bytes actually read. */
	static size_t
read (int fd, void *buffer_, off_t length)
{
	if(length < 0 || fd == 1)
		return -1;

	pointer_check(buffer_);

	char *buffer = (char *)(buffer_);
	if(fd == 0)
	{
		int i;
		for(i = 0; i < length; ++i)
			buffer[i] = input_getc();
		return length;
	}
	else
	{
		struct file *f = get_file(fd);
		if(f == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		off_t ret = file_read(f, buffer, length);
		lock_release(&filesys_lock);

		return ret;
	}
}

	
/* Writes size bytes from buffer to the open file. 
   Returns the number of bytes written. */
	static int 
write (int fd, const void *buffer_, unsigned length)
{
	pointer_check_range(buffer_, length);
	char *buffer = (char *)(buffer_);
	if(fd == STDOUT_FILENO)
	{
		/* write to console. */
		putbuf((char *)buffer, (size_t)length);
		return (int)length;
	}
	else
	{	/* write to file. */
		struct file *f = get_file(fd);
		if(f == NULL)
			return 0;
		lock_acquire(&filesys_lock);
		int result = file_write(f, buffer, length);
		lock_release(&filesys_lock);
		return result;
	}
}

/* Changes the next byte to be read or written in open file
   to position from the beginning of the new file (in bytes). */
	static int 
seek (int fd, unsigned position)
{
	struct file *f = get_file(fd);

	if (f == NULL)
		return 0;

	f->pos = position;
	return 0;
}

/* Returns the position of the next byte to be read or written 
   in open file. (in bytes) */
	static unsigned
tell (int fd)
{
	struct file *f = get_file(fd);

	if(f == NULL)
		return -1;

	return f->pos;
}

/* Closes the file identified by a fd. */
	static int
close (int fd)
{
	struct list_elem *itp;
	struct fd_list_node *ep = NULL;

	for (itp = list_begin(&thread_current()->fd_table);
			itp != list_end(&thread_current()->fd_table);
			itp = list_next(itp))
	{
		if(ep->fd == fd)
			break;
	}
	if(ep != NULL)
	{
		list_remove(&(ep->elem));
		lock_acquire(&filesys_lock);
		file_close(ep->file);
		lock_release(&filesys_lock);
		free(ep);
	}
	return 0;
}

	static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	pointer_check(f->esp);
	int32_t sys_code = *(int*)f->esp;
	thread_current()->f = f;
	switch(sys_code)
	{
		case SYS_HALT:
			{
				halt();
				break;
			}
		case SYS_EXIT:
			{
				GET_ARGS1(int, exit);
				break;
			}
		case SYS_EXEC:
			{
				GET_ARGS1(const char *, exec);
				break;
			}
		case SYS_WAIT:
			{
				GET_ARGS1(int, wait);
				break;
			}
		case SYS_CREATE:
			{
				GET_ARGS2(const char *, unsigned, create);
				break;
			}
		case SYS_REMOVE:
			{
				GET_ARGS1(const char *, remove);
				break;
			}
		case SYS_OPEN:
			{
				GET_ARGS1(const char *, open);
				break;
			}
		case SYS_FILESIZE:
			{
				GET_ARGS1(int, filesize);
				break;
			}
		case SYS_READ:
			{
				GET_ARGS3(int, int, off_t, read);
				break;
			}
		case SYS_WRITE:
			{
				GET_ARGS3(int, void *, unsigned, write);
				break;
			}
		case SYS_SEEK:
			{
				GET_ARGS2(int, unsigned, seek);
				break;
			}
		case SYS_TELL:
			{
				GET_ARGS1(int, tell);
				break;
			}
		case SYS_CLOSE:
			{
				GET_ARGS1(int, close);
				break;
			}
	}
}
