#include <hash.h>
#include <list.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "devices/timer.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"


static struct list lru_list;
struct lock frame_lock;
static struct list_elem *e;
static bool flag = true;


void lru_list_init(void){

    list_init(&lru_list);

}

void frame_lock_init(void){

    lock_init(&frame_lock);

}

void insert_frame(struct page *pg){

    list_push_back(&lru_list, &pg->lru_elem);

}


void delete_frame(struct page *pg){

    list_remove(&pg->lru_elem);

}


struct page *frame_for_exchange(void){
    struct list_elem *e;
    struct page *pg;
    for(e = list_begin(&lru_list); e != list_end(&lru_list); ){
        pg = list_entry(e, struct page, lru_elem);
        if(!pagedir_is_accessed(pg->t->pagedir, pg->vme->vaddr)){          
            break;
        }
        pagedir_set_accessed(pg->t->pagedir, pg->vme->vaddr, false);
        e = list_next(e);
        if(e == list_end(&lru_list)){
            e = list_begin(&lru_list);
            timer_msleep(1000);
        }
    }    
    return pg; 
}


void *free_frame(void){
    lock_acquire(&frame_lock);
    void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    struct page *pg;
    
    while(kpage == NULL){ 
        pg = frame_for_exchange();

        if(pg->vme->type != VM_FILE){
            swap_out(pg);
        }
        else{
            if(pagedir_is_dirty(pg->t->pagedir, pg->vme->vaddr)){
                file_write_at(pg->vme->file, pg->paddr, PGSIZE, pg->vme->offset);
            }
        }

        pagedir_clear_page(pg->t->pagedir, pg->vme->vaddr);
        pg->vme->is_loaded = false;
        pg->vme->pg = NULL;
        palloc_free_page(pg->paddr);
        delete_frame(pg);
        free(pg);
        kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    }
    lock_release(&frame_lock);
    return kpage;
}



void frame_lock_acquire(void){
    lock_acquire(&frame_lock);
}


void frame_lock_release(void){
    lock_release(&frame_lock);
}