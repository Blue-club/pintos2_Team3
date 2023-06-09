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



void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork(const char *thread_name, struct intr_frame *f);
int exec(const char *cmd_line);
int wait(int pid);






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
	int sys_number = f->R.rax;
	// TODO: Your implementation goes here.
	switch(sys_number) {
		case (SYS_HALT):
			halt();
            break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		// case SYS_FORK:
		// 	fork(f->R.rdi, f->R.rsi);		
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// case SYS_WAIT:
		// 	wait(f->R.rdi);
		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi);	
			break;	
		case SYS_REMOVE:
			remove(f->R.rdi);		
			break;
		case SYS_OPEN:
			open(f->R.rdi);		
			break;
		 case SYS_FILESIZE:
		 	filesize(f->R.rdi);
			break;
		case SYS_READ:
			read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rdx);
			break;	
		case SYS_TELL:
			tell(f->R.rdi);
			break;	
		case SYS_CLOSE:
			close(f->R.rdi);
		// default:
		// 	thread_exit();
	}

	// printf ("system call!\n");
}
/* 주소 값이 유저 영역에서 사용하는 주소 값인지 확인 */
void check_address(void *addr){
	struct thread *t = thread_current();

	/* 인자로 받아온 주소가 유저영역의 주소가 아니거나 , 주소가 NULL이거나 
	해당 페이지가 존재하지 않을경우 프로그램 종료 */
	if(!is_user_vaddr(addr) || addr == NULL)
		exit(-1);
	if(pml4_get_page(t->pml4, addr) == NULL)
		exit(-1);
}
/* pintos 종료시키는 시스템 콜 */
void halt(void){
	power_off();
}

/* 현재 프로세스를 종료시키는 시스템 콜*/
void exit(int status){
	/* 종료 시 프로세스 이름 출력하고 정상적으로 종료시 status 0*/
	struct thread *t = thread_current();
	t->exit_status = status;
    printf("%s: exit%d\n", t->name, status);
	thread_exit();
}
bool create (const char *file, unsigned initial_size){
	/*주소 값이 유저 영역에서 사용하는 주소 값인지 확인*/
	check_address(file);
	/*파일 이름과 파일 사이즈를 인자 값으로 받아 파일 생성*/
	if(filesys_create(file,initial_size)){
		return true;
	}
	else{
		return false;
	}
}

bool remove (const char *file){
	/*주소 값이 유저 영역에서 사용하는 주소 값인지 확인*/
	check_address(file);
	/*파일 이름에 해당하는 파일을 제거하는 함수*/
	if(filesys_remove(file)){
		return true;
	}
	else{
		return false;
	}
}

int write(int fd, const void *buffer, unsigned size) {
    check_address(buffer);
    
    /* 실행된 후 쓰여진 바이트 수를 저장하는 변수 */
    int bytes_written=0;

    lock_acquire(&filesys_lock);

    if (fd == STDOUT_FILENO) {
        /* 쓰기가 표준 출력인 경우, 버퍼의 내용을 화면에 출력하고 쓰여진 바이트 수를 저장 */
        putbuf(buffer, size);
        bytes_written = size;
    }
    else
	{
		if (fd < 2)
			return -1;
		struct file *file = process_get_file(fd);
		if (file == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		bytes_written = file_write(file, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_written;
}

int open (const char *file_name) {
    check_address(file_name);  // 주소 유효성 검사

    struct file *file = filesys_open(file_name);  // 파일 시스템에서 파일 열기

    if (file == NULL) {
        return -1;  // 파일 열기 실패 시 -1 반환
    }

    int fd = process_add_file(file);  // 파일을 프로세스에 추가하고 파일 디스크립터 얻기

    if (fd == -1) {
        file_close(file);  // 파일 디스크립터 추가 실패 시 열었던 파일 닫기
    }

    return fd;  // 파일 디스크립터 반환
}


// 파일 디스크립터를 사용하여 파일의 크기를 가져오는 함수
int filesize(int fd) {
    // 주어진 파일 디스크립터로부터 파일 객체를 가져옴
    struct file *file = process_get_file(fd);

    // 파일 객체가 NULL인 경우, 즉 파일을 찾을 수 없는 경우 -1을 반환
    if (file == NULL) {
        return -1;
    }

    // 파일 객체의 크기를 가져와서 반환
    return file_length(file);
}


// 주어진 파일 디스크립터를 사용하여 파일로부터 데이터를 읽어오는 함수
int read(int fd, void *buffer, unsigned size) {
    // 주어진 buffer의 주소 유효성을 확인
    check_address(buffer);

    // buffer를 unsigned char 포인터로 캐스팅하여 사용하기 위한 변수
    unsigned char *buf = buffer;
    int bytes_written = 0;

    lock_acquire(&filesys_lock);
	if (fd == STDIN_FILENO)
	{
		for (int i = 0; i < size; i++)
		{
			*buf++ = input_getc();
			bytes_written++;
		}
		lock_release(&filesys_lock);
	}
	else
	{
		if (fd < 2)
		{

			lock_release(&filesys_lock);
			return -1;
		}
		struct file *file = process_get_file(fd);
		if (file == NULL)
		{

			lock_release(&filesys_lock);
			return -1;
		}
		bytes_written = file_read(file, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_written;
}

// 주어진 파일 디스크립터를 사용하여 파일 내에서 지정된 위치로 이동하는 함수
void seek(int fd, unsigned position) {

    // 주어진 파일 디스크립터로부터 파일 객체를 가져옴
    struct file *file = process_get_file(fd);

    // 파일 객체가 NULL인 경우 함수 종료
    if (file == NULL) {
        return;
    }

    // 파일 객체의 위치를 주어진 position으로 이동
    file_seek(file, position);
}

unsigned tell (int fd){
	struct file *file = process_get_file(fd);

	if (file == NULL) {
		return;
	}
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
