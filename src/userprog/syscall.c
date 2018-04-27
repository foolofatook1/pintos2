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

static void syscall_handler (struct intr_frame *);
static int get_user(const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static bool valid_pointer_check(void *esp);
static int halt (void);
static int exit (int status);
static int write (int fd, const void *buffer, unsigned length);
static void pointer_check(void *esp);
static void pointer_check_range(const void *start, off_t length);

	void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

#define GET_ARGS1(type1, function) \
	pointer_check(f->esp+4); \
f->eax = function ( \
		*((type1*) (f->esp)) \
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

	static void
pointer_check(void *esp)
{
	if(valid_pointer_check(esp))
	{
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

/* UADDR must be below PHYS_BASE. 
   Returns byte value if successful, -1 if segfault. */
	static int
get_user(const uint8_t *uaddr)
{
	if(!is_user_vaddr(uaddr))
		return -1;
	int result;
	asm("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}

/* Writes BYTE to user address UDST. */
	static bool
put_user (uint8_t *udst, uint8_t byte)
{
	if(!is_user_vaddr(udst))
		return false;
	int error_code;
	asm("movl $1f, %0; movb %b2, %1; 1:"
			: "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

	static bool
valid_pointer_check(void *esp)
{
	if(esp != NULL && (uint32_t)esp < (((uint32_t)PHYS_BASE) - 4)
			&& get_user((uint8_t *)esp) != -1)
		return 0;
	return 1;
}

/* Terminates pintos by calling shutdown_power_off(). */
	static int 
halt (void)
{
	printf("\n\nGOODBYE!\n\n");
	shutdown_power_off();
	NOT_REACHED();
}

	static int
exit (int status)
{
	thread_current()->exit_status = status;
	process_kill ();
	NOT_REACHED();
}

	static int 
write (int fd, const void *buffer_, unsigned length)
{
	pointer_check_range(buffer_, length);
	char *buffer = (char *)(buffer_);
	if(fd == STDOUT_FILENO)
	{
		putbuf((char *)buffer, (size_t)length);
		return (int)length;
	}
	else
		return -1;
}

	static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	pointer_check(f->esp);
	int32_t sys_code = *(int*)f->esp;

	if(sys_code < 0 || sys_code >= 20)
	{
		process_kill();
		return;
	}

	//printf("HELLO%d\n\n", sys_code);
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
		case SYS_WRITE:
			{
				GET_ARGS3(int, void *, unsigned, write);
				break;
			}
	}
}
