#include <hash.h>
#include <list.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "devices/block.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"



#define SLOT_SIZE 8192
#define SLOT_PER_PAGE 8
static unsigned int swap_slot[SLOT_SIZE] = {0,};
static struct block* swap_space;
struct lock swap_lock;


void swap_space_init(void){
    swap_space = block_get_role(BLOCK_SWAP);
}

void swap_lock_init(void){
    lock_init(&swap_lock);
}

bool swap_in(struct page* pg){

    // lock_acquire(&swap_lock);

    size_t swap_slot_index = pg->vme->swap_slot;
    void *buffer = pg->paddr;
    int swap_slot_start = swap_slot_index * SLOT_PER_PAGE;

    if(swap_slot_index < 0){
        // lock_release(&swap_lock);
        thread_exit();
    }

    if(swap_slot[swap_slot_index] != 1){
        // lock_release(&swap_lock);
        thread_exit();

    }

    if(read_swap_slot(swap_space, swap_slot_start, buffer) != SLOT_PER_PAGE){
        // lock_release(&swap_lock);
        thread_exit();

    }

    pg->vme->swap_slot = -1;
    swap_slot[swap_slot_index] = 0;
    // lock_release(&swap_lock);
    return true;

}


bool swap_out(struct page* pg){


    lock_acquire(&swap_lock);

    int swap_slot_index = check_swap_slot();
    void *buffer = pg->paddr;
    int swap_slot_start = swap_slot_index * SLOT_PER_PAGE;

    if(swap_slot_index < 0){
        lock_release(&swap_lock);
        thread_exit();
    }

    if(write_swap_slot(swap_space, swap_slot_start, buffer) != SLOT_PER_PAGE){
        lock_release(&swap_lock);
        thread_exit();
        return false;
    }
    
    pg->vme->type = VM_ANON;
    pg->vme->swap_slot = swap_slot_index;
    swap_slot[swap_slot_index] = 1;
    lock_release(&swap_lock);
    return true;

}


int read_swap_slot(struct block* swap_block, int swap_slot_index, void *buffer){
    int i;
    for(i = 0; i<SLOT_PER_PAGE; i++){
        block_read(swap_block, swap_slot_index, buffer);
        swap_slot_index++;
        buffer += BLOCK_SECTOR_SIZE;    
    }
    return i;
}


int write_swap_slot(struct block* swap_block, int swap_slot_index, void *buffer){
    int i;
    for(i = 0; i<SLOT_PER_PAGE; i++){
        block_write(swap_block, swap_slot_index, buffer);
        swap_slot_index++;
        buffer += BLOCK_SECTOR_SIZE;    
    }
    return i;    
}


int check_swap_slot(void){
    int i;
    for(i = 0; i<SLOT_SIZE; i++){
        if(swap_slot[i] == 0)
            return i;
    }
    return -1;
}
