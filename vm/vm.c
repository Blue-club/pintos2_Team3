/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "include/threads/thread.h"
#include "threads/mmu.h"
#include "vm/uninit.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}
void hash_action_destroy(struct hash_elem* hash_elem, void *aux);
/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	// 현재 스레드의 보조 페이지 테이블에 대한 포인터를 얻습니다.
	struct supplemental_page_table *spt = &thread_current ()->spt;

	// upage가 이미 사용 중인지 확인합니다.
	if (spt_find_page (spt, upage) == NULL) {
		
		// 새로운 페이지 구조체를 동적으로 할당합니다.
		struct page *page = malloc(sizeof(struct page));

		if (page == NULL)
			goto err;

		// 가상 메모리 타입에 따라 초기화자 함수 포인터를 설정합니다.
		int ty = VM_TYPE (type);
		bool seg = (VM_IS_CODE(type) == VM_MARKER_CODE);
		bool (*initializer)(struct page *, enum vm_type, void *);
		
		switch(ty){
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
		}
		// uninit_new 함수를 호출하여 페이지를 초기화합니다.
        uninit_new(page, upage, init, type, aux, initializer);

		page->writable = writable;
		page->seg = seg;

		 // 페이지를 보조 페이지 테이블에 삽입합니다.
        if (!spt_insert_page(spt, page)) {
            free(page);
            goto err;
        }

        return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	/* TODO: Fill this function. */
	// 대상 페이지 생성 및 가상 주소 설정
	struct page* target_page= malloc(sizeof(struct page));
	// 가상 주소를 페이지 경계로 내림 정렬하여 대상 페이지의 가상 주소로 설정.
	va = pg_round_down(va);
	target_page->va = va;

	// 페이지 테이블에서 페이지 검색
	struct hash_elem *elem = hash_find(&spt->pages, &target_page->hash_elem);

	free(target_page);
	// 페이지를 찾은 경우 해당 페이지 반환
	if (elem != NULL) {
		struct page *found_page = hash_entry(elem, struct page, hash_elem);
		return found_page;
	}
	// 페이지를 찾지 못한 경우 NULL 반환
	else {
        return NULL;
    }
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	// 페이지를 해시 테이블에 삽입
	struct hash_elem *elem = hash_insert(&spt->pages, &page->hash_elem);

	//hash_insert함수는 성공하면 NULL반환
	if (elem == NULL)
		succ = true;
	
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(spt,&page->hash_elem);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = malloc(sizeof(struct frame));
    if (frame == NULL) {
        return NULL; // 할당 실패 시 NULL 반환
    }

    void *kva = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kva == NULL) {
		PANIC("To do");
        // free(frame); // 할당된 frame 메모리를 해제
        // return NULL; // 할당 실패 시 NULL 반환
    }

    frame->kva = kva;
    frame->page = NULL;

    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	void* page_addr=pg_round_down(addr);
	struct page* page = spt_find_page(&thread_current()->spt, page_addr);
	while(page == NULL){
		vm_alloc_page(VM_ANON, page_addr, true);
		vm_claim_page(page_addr);
		page_addr+= PGSIZE;
		page = spt_find_page(&thread_current()->spt, page_addr);
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	page = spt_find_page(spt, addr);
	if(page != NULL){
		if(!write || page->writable){
			return vm_do_claim_page (page);
		}
	}
	else if(addr == thread_current()->rsp-8){
		if(!user) 
			return false;
		vm_stack_growth(addr);
		return true;
	}
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	//spt에서 주어진 가상 주소 va에 해당하는 페이지를 찾아 변수 page에 할당합니다.
	struct page *page = spt_find_page(spt, va);
	/* TODO: Fill this function */
    if (page == NULL) {
		page = malloc(sizeof(struct page));
		if(page==NULL){
			return false;
		}
		page -> va = va;
        spt_insert_page(spt,page);
    }

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *t = thread_current ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	void *page_va = page->va;
    void *frame_pa = frame->kva;
	
    // 현재 스레드의 페이지 테이블에서 페이지의 VA가 매핑되어 있는지 확인합니다.
    if (pml4_get_page(t->pml4, page_va) == NULL ){
        // 페이지 테이블에 페이지의 VA를 프레임의 PA로 매핑합니다.
        if(pml4_set_page(t->pml4, page_va, frame_pa, page->writable)) {
        // 매핑이 성공하면 디스크로부터 페이지를 프레임으로 스왑 인합니다.

        return swap_in(page, frame_pa);
		}
    }
	

    return false;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    // 페이지 해시 테이블을 초기화합니다.
    // hash_init 함수는 주어진 해시 테이블을 초기화하고 비교 함수와 해시 함수를 설정합니다.
    // pages 멤버는 페이지를 저장하는 해시 테이블입니다.
    hash_init(&spt->pages, hash_func, less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst, struct supplemental_page_table *src) {
    struct hash_iterator i;
    struct hash *src_hash = &src->pages;
    struct hash *dst_hash = &dst->pages;

    hash_first(&i, src_hash);
    while (hash_next(&i)) {
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        
        // Allocate and claim the page in dst
		enum vm_type type = src_page->operations->type;
		if(type== VM_UNINIT){
			struct uninit_page *uninit_page = &src_page->uninit;
			struct file_loader* file_loader = (struct file_loader*)uninit_page->aux;
			struct file_loader* new_file_loader = malloc(sizeof(struct file_loader));
			memcpy(new_file_loader, uninit_page->aux, sizeof(struct file_loader));
			new_file_loader -> file = file_duplicate(file_loader->file);
			//writable true
			vm_alloc_page_with_initializer(uninit_page->type,src_page->va,true,uninit_page->init,new_file_loader);
        	vm_claim_page(src_page->va);
		}else{
        	vm_alloc_page(src_page->operations->type, src_page->va, true);
        	vm_claim_page(src_page->va);
        	memcpy(src_page->va, src_page->frame->kva,PGSIZE);
		}

        // Insert the copied page into dst's supplemental page table

    }
    
    return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt ) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->pages, hash_action_destroy);
}

void hash_action_destroy(struct hash_elem* hash_elem_, void *aux){
	struct page* page = hash_entry(hash_elem_, struct page, hash_elem);

	if(page!=NULL){
		if (VM_TYPE(page->operations->type) == VM_FILE) {
        	struct file_page *file_page = &page->file;
			struct file* file = file_page->file; // 파일 포인터 갱신
			if(file)
				file_write_at(file, page->frame->kva, file_page->read_bytes, file_page->ofs);
		}
		
	   vm_dealloc_page(page);
	}

}


// 해시 함수: 주어진 hash_elem 구조체를 사용하여 페이지의 가상 주소에 대한 해시 값을 계산합니다.
uint64_t hash_func(const struct hash_elem *e, void *aux) {
    const struct page *pg = hash_entry(e, struct page, hash_elem);

    return hash_bytes(&pg->va, sizeof(void*));
}

// 비교 함수: 주어진 두 hash_elem 구조체를 사용하여 페이지의 가상 주소를 비교합니다.
// 가상 주소가 큰 페이지가 작은 페이지보다 앞에 오도록 true 또는 false를 반환합니다.
bool less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    const struct page *pg_a = hash_entry(a, struct page, hash_elem);
    const struct page *pg_b = hash_entry(b, struct page, hash_elem);

    return pg_a->va < pg_b->va;
}

