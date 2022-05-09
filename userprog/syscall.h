#include "threads/thread.h"
#include "threads/synch.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct lock fs_lock;
struct intr_frame *fr;
void syscall_init (void);
struct fd_str{
	struct file *file;
	int fd;
	struct lock file_lock;
	struct list_elem elem;
	struct thread *t;
};

/*
  system call function derived from Pintos PDF = TYKIM
 */


#endif /* userprog/syscall.h */
