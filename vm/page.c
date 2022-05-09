#include "vm/page.h"
#include <hash.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "filesys/file.h"


struct lock vm_lock;

/* Computes and returns the hash value for hash element E, given
   auxiliary data AUX. (hash_int()) */
static unsigned vm_hash_func (const struct hash_elem *e, void *aux UNUSED){

    struct vm_entry *v = hash_entry(e, struct vm_entry, elem);
    return hash_int(v->vaddr);

}


/* Compares the value of two hash elements A and B, given
   auxiliary data AUX.  Returns true if A is less than B, or
   false if A is greater than or equal to B.   
   ->Returns true if X is less than Y, or
   false if X is greater than or equal to Y. */
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    /* x == a */
    struct vm_entry *x = hash_entry(a, struct vm_entry, elem);
    /* y == b */
    struct vm_entry *y = hash_entry(b, struct vm_entry, elem);
  
    return y->vaddr > x->vaddr;
}


static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED){

    struct vm_entry *v = hash_entry(e, struct vm_entry, elem);

    struct thread *t = thread_current();
    
    if(pagedir_is_dirty(t->pagedir, v->vaddr)){
        void* kpage = pagedir_get_page(t->pagedir, v->vaddr);
        if(kpage != NULL && v->file != NULL){
            file_write_at(v->file, kpage, PGSIZE, v->offset);
            file_close(v->file);
        }
        else if(kpage == NULL && v->file != NULL && v->swap_slot != -1){
            v->pg = (struct page*)malloc(sizeof(struct page));
            kpage = free_frame();
            set_page(v->pg, v, kpage, t);
            swap_in(v->pg);
            file_write_at(v->file, v->pg->paddr, PGSIZE, v->offset);
            file_close(v->file);
            free(v->pg);
        }
        pagedir_clear_page(t->pagedir, v->vaddr);
        palloc_free_page(kpage);    
    }
    else{
        void* kpage = pagedir_get_page(t->pagedir, v->vaddr);
        pagedir_clear_page(t->pagedir, v->vaddr);
        palloc_free_page(kpage);
        if(v->file != NULL){
            file_close(v->file);
        }
    }
    if(v->is_loaded){
        v->is_loaded = false;
        delete_frame(v->pg);        
        free(v->pg); 
    }    
    
    delete_vme(&t->vm, v);
    free(v);
}


// static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED){

//     struct vm_entry *v = hash_entry(e, struct vm_entry, elem);
//     struct thread *t = thread_current();
//     void* kpage;
//     if(v->type == VM_BIN){
//         kpage = pagedir_get_page(t->pagedir, v->vaddr);
//         if(pagedir_is_dirty(t->pagedir, v->vaddr)){            
//             if(kpage != NULL){
//                 file_write_at(v->file, kpage, PGSIZE, v->offset);                
//                 v->is_loaded = false;
//                 delete_frame(v->pg);
//                 free(v->pg);
//             }
//         }    
//         file_close(v->file);
//         pagedir_clear_page(t->pagedir, v->vaddr);
//         palloc_free_page(kpage);    
//     }
//     else if(v->type == VM_ANON && v->file != NULL){
//         if(pagedir_is_dirty(t->pagedir, v->vaddr)){
//             if(v->is_loaded){
//                 kpage = pagedir_get_page(t->pagedir, v->vaddr);
//                 if(kpage != NULL){
//                     file_write_at(v->file, kpage, PGSIZE, v->offset);                
//                     v->is_loaded = false;
//                     delete_frame(v->pg);
//                     free(v->pg);
//                 }
//                 file_close(v->file);
//                 pagedir_clear_page(t->pagedir, v->vaddr);
//                 palloc_free_page(kpage);
//             }
//             else if(v->swap_slot != -1){
//                 kpage = free_frame();
//                 v->pg = (struct page*)malloc(sizeof(struct page));
//                 set_page(v->pg, v, kpage, t);
//                 swap_in(v->pg);
//                 file_write_at(v->file, kpage, PGSIZE, v->offset);                
//                 v->is_loaded = false; 
//                 free(v->pg);
//                 file_close(v->file);
//                 pagedir_clear_page(t->pagedir, v->vaddr);
//                 palloc_free_page(kpage);
//             }
//         }
//         else{
//             kpage = pagedir_get_page(t->pagedir, v->vaddr);
//             v->is_loaded = false;
//             delete_frame(v->pg);
//             free(v->pg);
//             file_close(v->file);
//             pagedir_clear_page(t->pagedir, v->vaddr);
//             palloc_free_page(kpage);
//         }
//     }
//     else if(v->type == VM_ANON && v->file == NULL){
//         if(v->is_loaded){
//             pagedir_clear_page(t->pagedir, v->vaddr);
//             palloc_free_page(v->pg->paddr);
//             delete_frame(v->pg);
//             free(v->pg);
//         }
//         else{
//             pagedir_clear_page(t->pagedir, v->vaddr);
//         }
//     }
    
//     delete_vme(&t->vm, v);
//     free(v);
// }



bool vm_init (struct hash *vm) {
    
    return hash_init(vm, vm_hash_func, vm_less_func, NULL);

}

/*hash_insert (vm version)*/
bool insert_vme (struct hash *vm, struct vm_entry *vme){

    if(!lock_held_by_current_thread(&thread_current()->vm_lock))
        lock_acquire(&thread_current()->vm_lock);

    struct hash_elem *old = hash_insert(vm, &vme->elem);

    if(old == NULL){

        if(lock_held_by_current_thread(&thread_current()->vm_lock))
            lock_release(&thread_current()->vm_lock);

        return true; /* insertion success */
    }
    else{

        if(lock_held_by_current_thread(&thread_current()->vm_lock))
            lock_release(&thread_current()->vm_lock);
        return false;/* insertion fail */
    }

}


/*hash_delete (vm version)*/
bool delete_vme (struct hash *vm, struct vm_entry *vme){

    if(!lock_held_by_current_thread(&thread_current()->vm_lock))
        lock_acquire(&thread_current()->vm_lock);

    if (hash_delete (vm, &vme->elem) == NULL){

        if(lock_held_by_current_thread(&thread_current()->vm_lock))
            lock_release(&thread_current()->vm_lock);

        return false;
    }
    else{

        if(lock_held_by_current_thread(&thread_current()->vm_lock))
            lock_release(&thread_current()->vm_lock);

        return true;
    }
}



// /* vaddr -> vm_entry */
struct vm_entry *find_vme (void *vaddr){

    if(!lock_held_by_current_thread(&thread_current()->vm_lock))
        lock_acquire(&thread_current()->vm_lock);

    struct vm_entry page;
    struct hash_elem *e;
    // printf("%d\n",thread_current()->tid );

    page.vaddr = pg_round_down(vaddr);

    e = hash_find (&thread_current()->vm, &page.elem);
    
    if(e == NULL){

        if(lock_held_by_current_thread(&thread_current()->vm_lock))
            lock_release(&thread_current()->vm_lock);

        return NULL;
    }

    if(lock_held_by_current_thread(&thread_current()->vm_lock))
        lock_release(&thread_current()->vm_lock);

    return hash_entry(e, struct vm_entry, elem);

}

/* delete vm */
void vm_destroy (struct hash *vm){
    vm_lock_acquire();
    hash_destroy(vm, vm_destroy_func);    
    vm_lock_release();
}


struct page *set_page(struct page *pg, struct vm_entry *vme, void *paddr, struct thread *t){

    pg->vme = vme;
    pg->paddr = paddr;
    pg->t = t;
    return pg;
}

void vm_lock_init(void){
    lock_init(&vm_lock);
}

void vm_lock_acquire(void){
    lock_acquire(&vm_lock);
}

void vm_lock_release(void){
    lock_release(&vm_lock);
}