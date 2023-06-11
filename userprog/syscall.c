#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"
#include "lib/stdio.h"
#include "lib/user/syscall.h"

tid_t fork(const char *thread_name, struct intr_frame *f);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {

	/* rax = 시스템 콜 넘버 */
	int syscall_n = f->R.rax; /* 시스템 콜 넘버 */
	switch (syscall_n)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
	}
}



void check_address(void *addr)
{
	if (addr == NULL)
		exit(-1);

	if (!is_user_vaddr(addr)) // 유저 영역이 아니거나 NULL이면 프로세스 종료
		exit(-1);

	if (pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}

/* 주소 값이 유저 영역에서 사용하는 주소 값인지 확인 */
void halt(void)
{
	power_off();
}

void exit(int status)
{
    struct thread *t = thread_current(); // 현재 스레드를 가져옵니다.
    t->exit_status = status; // 현재 스레드의 종료 상태(exit status)를 지정합니다.
    printf("%s: exit(%d)\n", t->name, status); // 현재 스레드의 이름과 종료 상태를 출력합니다.
    thread_exit(); // 스레드를 종료합니다.
}

bool create (const char *file, unsigned initial_size){
	/*주소 값이 유저 영역에서 사용하는 주소 값인지 확인*/
	check_address(file);
	/*파일 이름과 파일 사이즈를 인자 값으로 받아 파일 생성*/
	return filesys_create(file, initial_size);
}

bool remove (const char *file){
	/*주소 값이 유저 영역에서 사용하는 주소 값인지 확인*/
	check_address(file);
	/*파일 이름에 해당하는 파일을 제거하는 함수*/
	return filesys_remove(file);
}


int open(const char *file_name)
{
    check_address(file_name); // 주소 유효성 검사를 수행합니다.
    struct file *file = filesys_open(file_name); // 파일 시스템에서 파일을 엽니다.

    if (file == NULL) // 파일 열기에 실패한 경우
        return -1; // 오류를 나타내기 위해 -1을 반환합니다.

    int fd = process_add_file(file); // 현재 프로세스에 파일을 추가하고 파일 디스크립터(fd)를 얻습니다.

    if (fd == -1) // 파일을 추가하는 데 실패한 경우
        file_close(file); // 열었던 파일을 닫습니다.
    return fd; // 파일 디스크립터(fd)를 반환합니다.
}


// 파일 디스크립터를 사용하여 파일의 크기를 가져오는 함수
int filesize(int fd) {
    // 주어진 파일 디스크립터로부터 파일 객체를 가져옴
    struct file *file = process_get_file(fd);
 
    // 파일 객체가 NULL인 경우, 즉 파일을 찾을 수 없는 경우 -1을 반환
    if (file == NULL) 
        return -1;
	// 파일 객체의 크기를 가져와서 반환
    return file_length(file);

}


// 주어진 파일 디스크립터를 사용하여 파일 내에서 지정된 위치로 이동하는 함수
void seek(int fd, unsigned position) {

	if(fd<2)
		return;
    // 주어진 파일 디스크립터로부터 파일 객체를 가져옴
    struct file *file = process_get_file(fd);
    // 파일 객체가 NULL인 경우 함수 종료
    if (file == NULL) {
        return;
    }
    // 파일 객체의 위치를 주어진 position으로 이동
    file_seek(file, position);
}

// 주어진 파일 디스크립터를 사용하여 파일 내 현재 커서의 위치를 반환하는 함수
unsigned tell(int fd) {

    // 주어진 파일 디스크립터로부터 파일 객체를 가져옴
    struct file *file = process_get_file(fd);

    // 파일 객체가 NULL인 경우 함수 종료
    if (file == NULL) {
        return;
    }

    // 파일 객체의 현재 커서 위치를 반환
    return file_tell(file);
}

// 주어진 파일 디스크립터를 사용하여 열린 파일을 닫는 함수
void close(int fd) {

    // 주어진 파일 디스크립터로부터 파일 객체를 가져옴
    struct file *file = process_get_file(fd);

    // 파일 객체가 NULL인 경우 함수 종료
    if (file == NULL) {
        return;
    }
	file_close(file);
	process_close_file(fd);
}

// 주어진 파일 디스크립터를 사용하여 파일로부터 데이터를 읽어오는 함수
int read(int fd, void *buffer, unsigned size) {
    // 주어진 buffer의 주소 유효성을 확인
    check_address(buffer);
    check_address(buffer + size - 1);
 
    // buffer를 unsigned char 포인터로 캐스팅하여 사용하기 위한 변수
    unsigned char *buf = buffer;
    int bytes_written;
 
    // 주어진 파일 디스크립터로부터 파일 객체를 가져옴
    struct file *file = process_get_file(fd);
 
    // 파일 객체가 NULL인 경우, 즉 파일을 찾을 수 없는 경우 -1을 반환
    if (file == NULL) {
        return -1;
    }
 
    if (fd == STDIN_FILENO) {
        // 파일 디스크립터가 표준 입력인 경우, 키보드 입력을 받아 buffer에 저장
        char key;
        for (int bytes_written = 0; bytes_written < size; bytes_written++) {
            key = input_getc();
            *buf++ = key;
            if (key == '\0') {
                break;
            }
        }
    } else if (fd == STDOUT_FILENO) {
        // 파일 디스크립터가 표준 출력인 경우, 읽기 작업을 지원하지 않으므로 -1을 반환
        return -1;
    } else {
        // 일반 파일인 경우, 파일을 읽어와서 buffer에 저장하고 읽은 바이트 수를 반환
        lock_acquire(&filesys_lock);
        bytes_written = file_read(file, buffer, size);
        lock_release(&filesys_lock);
    }
 
    return bytes_written;
}

int write(int fd, const void *buffer, unsigned size) {
    check_address(buffer);
    struct file *file = process_get_file(fd);
    /* 실행된 후 쓰여진 바이트 수를 저장하는 변수 */
    int bytes_written = 0;
 
    lock_acquire(&filesys_lock);
 
    if (fd == STDOUT_FILENO) {
        /* 쓰기가 표준 출력인 경우, 버퍼의 내용을 화면에 출력하고 쓰여진 바이트 수를 저장 */
        putbuf(buffer, size);
        bytes_written = size;
    } else if (fd == STDIN_FILENO) {
        /* 쓰기가 표준 입력인 경우, 파일 시스템 잠금 해제 후 -1 반환 */
        lock_release(&filesys_lock);
        return -1;
    } else if (fd >= 2) {
        if (file == NULL) {
            /* 쓰기가 파일에 대한 것인데 파일이 없는 경우, 파일 시스템 잠금 해제 후 -1 반환 */
            lock_release(&filesys_lock);
            return -1;
        }
        /* 파일에 버퍼의 내용을 쓰고 쓰여진 바이트 수를 저장 */
        bytes_written = file_write(file, buffer, size);
    }
 
    lock_release(&filesys_lock);
 
    return bytes_written;
}


tid_t fork(const char *thread_name, struct intr_frame *f)
{	
	// 현재 프로세스를 포크하여 새로운 자식 프로세스를 생성하는 process_fork 함수를 호출하고 그 결과를 반환합니다.
    return process_fork(thread_name, f); 
}

int exec(const char *file_name)
{
    check_address(file_name); // 주소 유효성 검사를 수행합니다.
    char *file_name_copy = palloc_get_page(PAL_ZERO); // 페이지 할당을 통해 file_name을 복사할 메모리를 할당합니다.
    if (file_name_copy == NULL)
        exit(-1); // 메모리 할당 실패 시 status -1로 프로세스를 종료합니다.
    strlcpy(file_name_copy, file_name, PGSIZE); // file_name을 할당받은 메모리에 복사합니다.
    // 스레드의 이름을 변경하지 않고 file_name_copy를 실행합니다.
    if (process_exec(file_name_copy) == -1)
        exit(-1); // 실행 실패 시 status -1로 프로세스를 종료합니다.
}

int wait(int pid)
{
	return process_wait(pid);
}

// 파일 객체에 대한 파일 디스크립터를 생성하는 함수
int process_add_file(struct file *file) {
    struct thread *t = thread_current();  // 현재 실행 중인 스레드 구조체
    struct file **fdt = t->fdt;  // 현재 스레드의 파일 디스크립터 테이블
    int fd = t->fdidx;  // 현재 스레드의 파일 디스크립터 인덱스
 
    // 파일 디스크립터 테이블에서 비어있는 위치를 찾아 파일을 추가한다.
    while (t->fdt[fd] != NULL && fd < FDCOUNT_LIMIT) {
        fd++;
    }
    if (fd >= FDCOUNT_LIMIT) {
        // 파일 디스크립터 테이블이 가득찬 경우, -1을 반환한다.
        return -1;
    }
 
    t->fdidx = fd;  // 다음 파일에 할당될 파일 디스크립터 인덱스 갱신
    fdt[fd] = file;  // 파일 객체를 파일 디스크립터 테이블에 추가
 
    return fd;  // 할당된 파일 디스크립터 반환
}

// 주어진 파일 디스크립터를 사용하여 스레드의 파일 테이블에서 파일 객체를 찾아 반환하는 함수
struct file *process_get_file(int fd) {
    // 파일 디스크립터가 유효한 범위를 벗어나면 NULL을 반환
    if (fd < 0 || fd >= FDCOUNT_LIMIT) {
        return NULL;
    }
 
    // 현재 실행 중인 스레드의 정보를 가져옴
    struct thread *t = thread_current();
    // 현재 스레드의 파일 테이블을 가져옴
    struct file **fdt = t->fdt;
 
    // 파일 테이블에서 주어진 파일 디스크립터에 해당하는 파일 객체를 가져옴
    struct file *file = fdt[fd];
 
    // 찾은 파일 객체를 반환
    return file;
}

// 파일 디스크립터 테이블에서 파일 객체를 제거하는 함수
void process_close_file(int fd)
{
    struct thread *t = thread_current(); // 현재 스레드를 가져옵니다.
    struct file **fdt = t->fdt; // 파일 디스크립터 테이블을 가져옵니다.
    if (fd < 0 || fd > FDCOUNT_LIMIT)
        return NULL; // 주어진 파일 디스크립터가 유효 범위를 벗어난 경우 함수를 종료합니다.
    fdt[fd] = NULL; // 주어진 파일 디스크립터에 해당하는 인덱스를 NULL로 설정하여 파일 객체를 제거합니다.
}
