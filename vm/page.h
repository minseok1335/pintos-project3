#include <hash.h>
#include <list.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "filesys/file.h"
#include "threads/synch.h"

#define VM_BIN 0  
#define VM_FILE 1 
#define VM_ANON 2 


#ifndef PAGE_H
#define PAGE_H
struct vm_entry{
    uint8_t type;               
    void *vaddr;                
    bool writable;              

    bool is_loaded;              
    struct file *file;          

    struct page* pg; 

    struct list_elem mmap_elem; 
    
    size_t offset;              
    size_t read_bytes;          
    size_t zero_bytes;          

    size_t swap_slot;           
    
    struct hash_elem elem;      

    struct lock vme_lock;
};

static unsigned vm_hash_func (const struct hash_elem *e, void *aux);
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void vm_destroy_func(struct hash_elem *e, void *aux);

bool vm_init (struct hash *vm);

bool insert_vme (struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);

struct vm_entry *find_vme (void *vaddr);
void vm_destroy (struct hash *vm);

struct mmap_file{
    int map_id;
    void *addr;
    struct file *file;
    struct list_elem elem;
    struct list vme_list;
};

struct page{
    struct vm_entry *vme;
    void * paddr;
    struct thread *t;
    struct list_elem lru_elem;
};

struct page *set_page(struct page *pg, struct vm_entry *vme, void *paddr, struct thread *t);
void vm_lock_init(void);
void vm_lock_acquire(void);
void vm_lock_release(void);
#endif