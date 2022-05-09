#include <hash.h>
#include <list.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "filesys/file.h"
#include "vm/page.h"


#ifndef FRAME_H
#define FRAME_H
void lru_list_init(void);
void insert_frame(struct page *pg);
void delete_frame(struct page *pg);
struct page *frame_for_exchange(void);
void *free_frame(void);
void frame_lock_acquire(void);
void frame_lock_release(void);
#endif