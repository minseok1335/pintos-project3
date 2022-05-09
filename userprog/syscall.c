#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/timer.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h" // to add PHYS_BASE and is_user_vaddr - TYKIM
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/exception.h"
#include "vm/page.h"

extern struct intr_frame *fault_fr;
struct file
  {
    struct inode *inode;
    off_t pos;
    bool deny_write;
  };
int fd_number;
struct list fd_list;
static void syscall_handler (struct intr_frame *);
struct intr_frame *fr;
struct lock fs_lock;

void
syscall_init (void)
{
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	fd_number = 2;
	list_init(&fd_list);
	lock_init(&fs_lock);
}

void halt(void) {
  shutdown_power_off();
}

void exit(int status) {
	lock_acquire(&fs_lock);
	struct thread *parent = thread_current()->parent;
	struct list_elem *e;
	for(e = list_begin(&parent->child_lock_list);e != list_end(&parent->child_lock_list); e = list_next(e)){
		struct lock_elem *lock = list_entry( e, struct lock_elem, elem);
		if (lock->tid == thread_current()->tid)
			lock->status = status;
	}

  	printf ("%s: exit(%d)\n",thread_current()->name,status);
	lock_release(&fs_lock);
  	thread_exit();
}

int exec(char* cmd_line){
	char **next;
	char *file_name = (char* ) malloc (strlen(cmd_line) + 1);
	memcpy(file_name,cmd_line,strlen(cmd_line)+1);
	file_name = strtok_r(file_name," ",&next);
	struct file *f = filesys_open(file_name);
	timer_msleep(13000);
	if (f == NULL)
		return -1;
	free(file_name);
	int retval = process_execute(cmd_line);
	timer_msleep(13000);

	return retval;

}

bool remove(char* file_name){
	lock_acquire(&fs_lock);
	bool success = filesys_remove(file_name);
	lock_release(&fs_lock);
	return success;
}

bool create(char* file_name, unsigned initial_size){
	
	if (file_name == '\0'){ 	
		exit(-1);		
	}
	lock_acquire(&fs_lock);
	bool success = filesys_create(file_name, initial_size);
	lock_release(&fs_lock);

	return success;


}


int filesize(int fd){
	int retval;
	if(list_empty( &fd_list)){
		return;
	}
	struct list_elem *e;
	for (e = list_begin(&fd_list); e != list_end(&fd_list); e = list_next(e))
	{
		struct fd_str *fs = list_entry(e,struct fd_str,elem);
		if(fs->fd == fd)
		{
			retval = file_length(fs->file);
			return retval;
			
		}
		if (e == list_end(&fd_list))
			break;
	}
	return -1;
}


int read(int fd, const void* buffer, unsigned int size){

	int retval;

	if (fd == 0){
		lock_acquire (&fs_lock);
		retval = input_getc();
		lock_release(&fs_lock);
		return retval;
	}

  struct list_elem *e;
	for (e = list_begin(&fd_list); e != list_end(&fd_list); e = list_next(e))
	{
		struct fd_str *fs = list_entry(e,struct fd_str,elem);

		if(fs->fd == fd)
		{	
			struct vm_entry *v = find_vme(buffer);
			if(v != NULL && buffer< 0xbf85ee00 && !v->writable ){
				exit(-1);
			}
			file_deny_write(fs->file);
			lock_acquire (&fs_lock);
			retval = file_read(fs->file,buffer,size);
			timer_msleep(500);
			lock_release(&fs_lock);
			return retval;
		}
		if (e == list_end(&fd_list))
			break;
	}
	return -1;
}


int write(int fd, const void* buffer, unsigned int size){
	int retval;

  	if (fd == 1){
		lock_acquire (&fs_lock);
  		putbuf(buffer,size);
		lock_release (&fs_lock);
		return retval;
	}

	struct list_elem *e;
	for (e = list_begin(&fd_list); e != list_end(&fd_list); e = list_next(e))
	{
		struct fd_str *fs = list_entry(e,struct fd_str,elem);
		if(fs->fd == fd)
		{	
			lock_acquire (&fs_lock);	
			retval = file_write(fs->file,buffer,size);
			timer_msleep(500);
			lock_release (&fs_lock);
			return retval;
		}
		if (e == list_end(&fd_list))
			break;
	}
	return -1;

}

int open(char* file_name){
	// lock_acquire(&fs_lock);
	struct file *temp = filesys_open(file_name);
	// lock_release(&fs_lock);
	if (temp == NULL){
		return -1;
	}
	struct fd_str *fs = (struct fd_str*) malloc (sizeof(struct fd_str));
	if(fs == NULL){
		return -1;
	}
	fs->file = temp;
	fs->fd = fd_number;
	fs->t = thread_current();
	thread_current()->fd_count++;
	if(!list_empty(&fd_list)){
		struct list_elem *e;
		for (e = list_begin(&fd_list); e != list_end(&fd_list); e = list_next(e)){
			struct fd_str *ft = list_entry(e,struct fd_str,elem);
			if(ft->file->inode == temp->inode)
				file_deny_write(fs->file);
		 }
	}
	lock_init(&fs->file_lock);
	lock_acquire(&fs->file_lock);
	list_push_back(&fd_list,&fs->elem);
	int retval = fd_number;
	fd_number++;
	return retval;

}

void seek(int fd, unsigned int position){
	if(list_empty( &fd_list))
		return;
	struct list_elem *e;
	for (e = list_begin(&fd_list); e != list_end(&fd_list); e = list_next(e)){
		struct fd_str *fs = list_entry(e,struct fd_str,elem);
		if(fs->fd == fd){
			file_seek(fs->file, position);
			file_allow_write(fs->file);
			return;
		}
		if (e == list_end(&fd_list))
			break;
	}
	return;

}

void tell(int fd){
	if(list_empty( &fd_list))
		return;
	struct list_elem *e;
	for (e = list_begin(&fd_list); e != list_end(&fd_list); e = list_next(e)){
		struct fd_str *fs = list_entry(e,struct fd_str,elem);
		if(fs->fd == fd){
			file_tell(fs->file);
			return;
		}
		if (e == list_end(&fd_list))
			break;
	}
	return;
}

void close(int fd){
	if(list_empty( &fd_list))
		return;
	struct list_elem *e;
	for (e = list_begin(&fd_list); e != list_end(&fd_list); e = list_next(e))
	{
		struct fd_str *fs = list_entry(e,struct fd_str,elem);
		if(fs->fd == fd)
		{
			if(!lock_held_by_current_thread(&fs->file_lock))
				return -1;
			lock_release(&fs->file_lock);
			fs->t->fd_count--;
			file_close(fs->file);
			fs->fd = -1;
			e = list_remove(&fs->elem);
			free(fs);
			if (e == list_end(&fd_list))
				break;
		}
	}
}

/*
  Adrress checking for user program - not to touch kernel address space - TYKIM
 */

void address_checker(struct intr_frame *f)
{

    if(is_kernel_vaddr(f->esp))
    {
        printf ("%s: exit(-1)\n",thread_current()->name);
        thread_exit();
        return;
    }
    else
			  return;
}

int mmap (int fd, void *addr){
	if(fd == 0 || fd == 1){
		return -1;
	}

	if(addr>=PHYS_BASE || addr <0x08048000){
		return -1;
	}

	if(find_vme(addr)!=NULL){
		return -1;
	}

	if(pg_round_down(addr) != addr){
		return -1;
	}

	off_t read_bytes;
	off_t zero_bytes;
	off_t offset = 0;
	struct list_elem *e;
	struct thread *t = thread_current();
	
	for (e = list_begin(&fd_list); e != list_end(&fd_list); e = list_next(e))
	{
		struct fd_str *fs = list_entry(e,struct fd_str,elem);
		
		if(fs->fd == fd)
		{
			struct mmap_file * mapped_file = (struct mmap_file*)malloc(sizeof(struct mmap_file));

			list_init(&mapped_file->vme_list);

			lock_acquire (&fs_lock);
			mapped_file->file = file_reopen(fs->file);
			lock_release(&fs_lock);

			mapped_file->addr = addr;

			read_bytes = file_length(mapped_file->file);
			
			zero_bytes = PGSIZE - read_bytes % PGSIZE;
			
			if(read_bytes == 0 || (read_bytes + addr) >=PHYS_BASE)
				break;

			while (read_bytes > 0 || zero_bytes > 0){
			
				size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
				size_t page_zero_bytes = PGSIZE - page_read_bytes;
				
				/*setting vme*/
				struct vm_entry *vme = (struct vm_entry*)malloc(sizeof(struct vm_entry));

				vme->type = VM_FILE;
				vme->vaddr = addr;
				vme->writable = true;

				vme->is_loaded = false;
				vme->file = mapped_file->file;
				vme->offset = offset;

				vme->read_bytes = page_read_bytes;
				vme->zero_bytes = page_zero_bytes;
				vme->swap_slot = -1;
				
				lock_init(&vme->vme_lock);
				insert_vme(&t->vm, vme);
				list_push_back(&mapped_file->vme_list, &vme->mmap_elem);
				
				offset += page_read_bytes;
				/* Advance. */
				read_bytes -= page_read_bytes;
				zero_bytes -= page_zero_bytes;
				addr += page_read_bytes;
			}
			t->mmapid++;
			mapped_file->map_id = t->mmapid;

			list_push_back(&t->mmap_list, &mapped_file->elem);

			return t->mmapid;				
		}

		if (e == list_end(&fd_list))
			break;
	}
	return -1;

}

void munmap (int mapping){

	struct list_elem *e;
	int fd;
	struct thread* t = thread_current();

	
	for (e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list); e = list_next(e)){
        struct mmap_file * mf = list_entry(e, struct mmap_file, elem);
		
		if(mf->map_id == mapping){	
			for (e = list_begin (&mf->vme_list); e != list_end (&mf->vme_list);){
				struct vm_entry *vme = list_entry(e,struct vm_entry, mmap_elem);
				void *kpage = pagedir_get_page(t->pagedir, vme->vaddr);
				if(kpage != NULL && pagedir_is_dirty(t->pagedir, vme->vaddr)){
            		lock_acquire (&fs_lock);
					file_write_at(vme->file, kpage, PGSIZE, vme->offset);
					timer_msleep(100);
					lock_release(&fs_lock);
					vme->is_loaded = false;
					delete_frame(vme->pg);
					free(vme->pg);
				}

				pagedir_clear_page(t->pagedir, vme->vaddr);
				palloc_free_page(kpage);
				e = list_remove (e);
				delete_vme(&t->vm,vme);				
				free(vme);
			}
			lock_acquire (&fs_lock);	
			file_close(mf->file);
			lock_release(&fs_lock);
			list_remove(&mf->elem);
			free(mf);
			break;			
		}
    }
}

static void
syscall_handler (struct intr_frame *f)
{
	fr = f;
  address_checker(f);
	int syscall;
	memcpy(&syscall,f->esp,4);
	char* file_name;
	int status;
	int fd;
	int mapping;
	struct file* file;
	void* buffer;
	unsigned int *size;
	unsigned int *position;
	int retval;
	tid_t tid;
	char* cmd_line;
  switch(syscall)
	{
		/*
      write system call
      0 - SYS_HALT,                   Halt the operating system.
      1 - SYS_EXIT,                   Terminate this process.
      2 - SYS_EXEC,                   Start another process. on 2-2
      3 - SYS_WAIT,                   Wait for a child process to die. on 2-2
      4 - SYS_CREATE,                 Create a file.
			5 - SYS_REMOVE,									Delete a file.  on 2-2
			6 - SYS_OPEN,                   Open a file.
			7 - SYS_FILESIZE,								Obtain a file's size. on 2-2
			8 - SYS_READ,										Read from a file. on 2-2
			9 - SYS_WRITE,                  Write to a file.  on 2-2
			10 - SYS_SEEK										Change position in a file. on 2-2
			11 - SYS_TELL										Report current position in a file. on 2-2
      12 -SYS_CLOSE,                  Close a file.
	  13 - SYS_MMAP,
	  14 - SYS_MUNMAP
    */
		case 0:
      		halt();
			break;
		case 1:
			if(f->esp + 4 >= PHYS_BASE)
				exit(-1);
			memcpy(&status,f->esp + 4,sizeof (int));
			//arg passing
      		exit(status);
			break;
		case 2:
			memcpy(&cmd_line,f->esp + 4, sizeof (char *));
			if(find_vme(cmd_line) == NULL)
				exit(-1);
			lock_acquire(&fs_lock);
			retval = exec(cmd_line);
			lock_release(&fs_lock);
			f->eax = retval;
			break;
    case 3:
    	if(f->esp + 4 >= PHYS_BASE){
				exit(-1);
			}
		memcpy(&tid,f->esp + 4,sizeof(tid_t));
      	retval = process_wait(tid);
		f->eax = retval;
		break;
    case 4:
		if(f->esp + 4*4 >= PHYS_BASE || f->esp + 4*5 >= PHYS_BASE)
			exit(-1);
		memcpy(&file_name, f->esp + 4*4, sizeof(char *));
		memcpy(&size, f->esp + 4*5, sizeof(int));
		bool creation;
		if(find_vme(file_name) == NULL)
			exit(-1);
		creation = create(file_name, size);
		f-> eax = creation;
		break;
		case 5:
			if(f->esp + 4 >= PHYS_BASE)
				exit(-1);
			memcpy(&file_name,f->esp + 4,sizeof(char *));
			if (file_name == NULL || strlen(file_name) == 0){
				f->eax = -1;
				break;
			}
			bool removal;
			removal = remove(file_name);
			f->eax = removal;
			break;
    case 6:
			if(f->esp + 4 >= PHYS_BASE)
        exit(-1);
			memcpy(&file_name,f->esp + 4,sizeof(char *));
			if (file_name == NULL || !strlen(file_name)){
				f->eax = 4294967295;
				break;
			}
			retval = open(file_name);
			f->eax = retval;
      break;
		case 7:
			if(f->esp + 4 >= PHYS_BASE)
				exit(-1);
			memcpy(&fd,f->esp + 4,sizeof(int));
			retval = filesize(fd);
			f->eax = retval;
			break;
		case 8:
			if(f->esp >= PHYS_BASE)
				exit(-1);
			memcpy(&fd,f->esp + 5*4,sizeof(int));
			memcpy(&buffer,f->esp + 6*4,sizeof(void*));
			memcpy(&size,f->esp + 7*4,sizeof(unsigned int));
			if(buffer >= PHYS_BASE)
				exit(-1);
			if(find_vme(buffer)==NULL && buffer < 0xbf85ee00)
				exit(-1);
			retval = read(fd,buffer,size);
			f->eax = retval;
			break;
		case 9:
			if(f->esp >= PHYS_BASE)
				exit(-1);
			memcpy(&fd,f->esp + 5*4,sizeof(int));
			memcpy(&buffer,f->esp + 6*4,sizeof(void*));
			memcpy(&size,f->esp + 7*4,sizeof(unsigned int));
			if(buffer >= PHYS_BASE)
				exit(-1);
			if(find_vme(buffer)==NULL)
				exit(-1);
			retval = write(fd,buffer,size);
			f->eax = retval;
			break;
		case 10:
			if(f->esp + 4*4 >= PHYS_BASE || f->esp + 4*5 >= PHYS_BASE)
				exit(-1);
			memcpy(&fd,f->esp + 4*4,sizeof(int));
			memcpy(&position, f->esp + 4*5, sizeof(int));
			seek(fd,position);
			break;
		case 11:
			if(f->esp + 4 >= PHYS_BASE)
				exit(-1);
			memcpy(&fd,f->esp + 4,sizeof(int));
			tell(fd);
			break;
    case 12:
			if(f->esp + 4 >= PHYS_BASE)
        exit(-1);
			memcpy(&fd,f->esp + 4,sizeof(int));
			if(fd == 0 || fd == 1 || fd < 0 )
				exit(-1);
			close(fd);
      break;
	case 13:
		if(f->esp >= PHYS_BASE)
				exit(-1);
		memcpy(&fd,f->esp + 4*4,sizeof(int));
		memcpy(&buffer,f->esp + 5*4,sizeof(void*));
		if(buffer >= PHYS_BASE)
			exit(-1);
		retval = mmap(fd,buffer);
		f->eax = retval;	
		break;
	case 14:
		if(f->esp + 4 >= PHYS_BASE)
        	exit(-1);		
		memcpy(&mapping,f->esp + 4,sizeof(int));
		munmap(mapping);
		break;
		default:
			break;

	}
}
