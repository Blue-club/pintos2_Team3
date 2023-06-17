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

	struct supplemental_page_table *spt = &thread_current ()->spt;
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		
		/* TODO: Insert the page into the spt. */
		struct page *page = malloc(sizeof(struct page));
        if (page == NULL)
            goto err;

		int ty = VM_TYPE (type);
		int st = VM_IS_STACK(type);
		// 수정해야 함 (vm_initializer아님)
		bool (*initializer)(struct page *, enum vm_type, void *);
		switch(ty){
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
		}
        // Initialize the page using uninit_new
        uninit_new(page, upage, init, type, aux, initializer);

		
        /* Insert the page into the spt. */
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
	if(page == NULL){
		return false;
	}
	return vm_do_claim_page (page);
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
        if(pml4_set_page(t->pml4, page_va, frame_pa, true)) {
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
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
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