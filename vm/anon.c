/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

struct list swap_list;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	list_init(&swap_list);
	swap_disk = disk_get(1, 1);
	disk_sector_t max_sector_size = disk_size(swap_disk);
	for(int i =0; i< max_sector_size; i += 8){
		struct swap_anon* swap_anon = malloc(sizeof(struct swap_anon));
		swap_anon->page=NULL;
		swap_anon->use = false;
		for(int j = 0; j<8; j++)
			swap_anon->sectors[j] = i+j;
		list_push_back(&swap_list, &swap_anon->swap_elem);
	}
}

struct swap_anon*
find_blank_swap(){
	struct list_elem* e = list_head (&swap_list);
   	while ((e = list_next (e)) != list_end (&swap_list)){
		struct swap_anon* swap_anon=list_entry(e, struct swap_anon, swap_elem);
		if(!swap_anon->use){
			return swap_anon;
		}
   	}
	return NULL;
}


/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	struct swap_anon *swap_anon = anon_page->swap_anon;
	for(int i=0; i<8 ; i++){
		disk_read(swap_disk,swap_anon->sectors[i],kva + DISK_SECTOR_SIZE * i);
	}
	anon_page->swap_anon = NULL;
	swap_anon->use = false;

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool      
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	struct swap_anon *swap_anon = find_blank_swap();
	for(int i=0; i<8 ; i++){
		disk_write(swap_disk,swap_anon->sectors[i], page->frame->kva + DISK_SECTOR_SIZE * i);
	}
	page->writable = is_writable(pml4e_walk(page->curr->pml4, page->va,0));
	swap_anon->use = true;
	anon_page->swap_anon = swap_anon;
	page->frame = NULL;
	pml4_clear_page(page->curr->pml4, page->va);
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;

}
