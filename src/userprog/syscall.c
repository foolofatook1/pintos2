#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);

/*#define GET_ARGS1(type1, function) \
	pointer_check(f->esp); \
f->eax = function ( \
		*((type1*) (f->esp)) \
		);*/

	static void 
kill_program (void)
{
	thread_exit ();
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

	static void
get_args(struct intr_frame *f)
{
	int fd = *((int*)f->esp + 1);
	void *buffer = (void *)(*((int*)f->esp + 2));
	unsigned size = *((unsigned*)f->esp + 3);
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
exit (void)
{}

	static void
pointer_check(void *esp)
{
	if(valid_pointer_check(esp))
	{
		kill_program();
		return;
	}
	return;
}

	static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	pointer_check(f->esp);
	int32_t sys_code = *(int*)f->esp;

	if(sys_code < 0 || sys_code >= 20)
	{
		kill_program();
		return;
	}

	printf("HELLO%d\n\n", sys_code);
	switch(sys_code)
	{
		case SYS_HALT:
			{
				halt();
				break;
			}
	/*	case SYS_EXIT:
			{
				GET_ARGS1(int, exit)
				break;
			}*/
	}
}

	void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
