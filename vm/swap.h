#include "vm/page.h"
#include "vm/frame.h"
#include <hash.h>
#include <list.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "devices/block.h"


#ifndef SWAP_H
#define SWAP_H
struct swap_space_meta;


void swap_space_init(void);
bool swap_in(struct page* pg);
bool swap_out(struct page* pg);
#endif