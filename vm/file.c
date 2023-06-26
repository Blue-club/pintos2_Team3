/* file.c: Implementation of memory backed file object (mmaped object). */
#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/mmu.h"
#include <hash.h>
#include <list.h>


static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

static bool lazy_load_file (struct page *page, void *aux);
/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
	struct file_page *file_page = &page->file;
	file_page ->mmap_start = VM_IS_MMAP(type);
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	struct file* file = file_page->file;
	off_t ofs = file_page->ofs;
	int page_read_bytes = file_page->read_bytes;
	int page_zero_bytes = file_page->zero_bytes;
	file_seek(file,ofs);
	page_read_bytes == (int)file_read(file,page->frame->kva, page_read_bytes);
	memset (page->frame->kva+page_read_bytes, 0, page_zero_bytes);
	page->swap =false;
	return true;

}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	struct file* file = file_page->file; // 파일 포인터 갱신
	if(file && pml4_is_dirty(thread_current()->pml4, page->va)){
		file_write_at(file, page->frame->kva, file_page->read_bytes, file_page->ofs);
		pml4_set_dirty(thread_current()->pml4,page->va,0);
	}
	page->frame = NULL;
	page->swap =true;
	pml4_clear_page(thread_current()->pml4, page->va);
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	file = file_reopen(file);
	if(file == NULL) return false;
	void* start_addr = addr;
	struct supplemental_page_table *spt = &thread_current()->spt;
	enum vm_type check = VM_MARKER_MMAP;
	struct list* mmap_list;
	while(length >0){
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE-page_read_bytes;
		struct file_loader *file_loader = malloc(sizeof(struct file_loader));
		file_loader->page_read_bytes = page_read_bytes;
		file_loader->page_zero_bytes = page_zero_bytes;
		file_loader->ofs = offset;
		file_loader->file = file;
		if (!vm_alloc_page_with_initializer (VM_FILE | check, addr,
					writable, lazy_load_file, file_loader)){
			free(file_loader);
			return false;
		}
		struct page* page = spt_find_page(spt,addr);
		if(check){
			list_init(&page->mmap_list);
			mmap_list = &page->mmap_list;
		}
		list_push_front(mmap_list,&page->mmap_elem);
		
		/* Advance. */
		length -= page_read_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
		check = 0;
	}

	return true;
}

/* Do the munmap */
void do_munmap(void *addr) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = spt_find_page(spt, addr);
    struct list *mmap_list = &page->mmap_list;
    struct list_elem *e;

    struct file *file = NULL; // 파일 포인터 초기화
    for (e = list_begin(mmap_list); e != list_end(mmap_list);) {
        page = list_entry(e, struct page, mmap_elem);
        if (VM_TYPE(page->operations->type) == VM_UNINIT) {
			e = list_remove(e);
            spt_remove_page(spt, page);
            continue;
        }
		if(!pml4_is_dirty(thread_current()->pml4, page->va)){
			e = list_remove(e);			
			continue;
		}
        struct file_page *file_page = &page->file;
        if (file == NULL) {
            file = file_page->file; // 파일 포인터 갱신
        }

        file_write_at(file, page->frame->kva, file_page->read_bytes, file_page->ofs);
		e = list_remove(e);
		if(page->frame !=NULL){
			free_frame(page->frame);
		}
		//dealloc 넣었음
		spt_remove_page(spt, page);
    }
    if (file != NULL) {
        file_close(file);
    }
}






static bool
lazy_load_file (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	struct file_loader *file_loader = (struct file_loader*)aux;
	struct file *file = file_loader->file;
	off_t ofs = file_loader->ofs;
	uint8_t *upage = page->va;
	uint32_t page_read_bytes = file_loader->page_read_bytes;
	uint32_t page_zero_bytes = file_loader->page_zero_bytes;
	
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	
	file_seek(file,ofs);
	page_read_bytes = (int)file_read(file,page->frame->kva, page_read_bytes);
	page_zero_bytes = PGSIZE - page_read_bytes;
	memset (page->frame->kva+page_read_bytes, 0, page_zero_bytes);
    // memcpy (page->va, page->frame->kva,PGSIZE);
	struct  file_page* file_page = &page->file;
	file_page ->ofs = ofs;
	file_page ->read_bytes = page_read_bytes;
	file_page ->zero_bytes = page_zero_bytes;
	file_page -> file = file;
	// free(file_loader);

	return true;
}


