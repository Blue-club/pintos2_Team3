#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "devices/disk.h"
struct page;
enum vm_type;

struct anon_page {
    struct swap_anon* swap_anon;
};

struct swap_anon{
    bool use;
    disk_sector_t sectors[8];
    struct page* page;  //필요한가?
    struct list_elem swap_elem;
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
