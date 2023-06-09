#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);

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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int systemcall = f->R.rax;
	printf("\n%d\n", systemcall);

	switch (systemcall)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		break;
	case SYS_EXEC:
		break;
	case SYS_WAIT:
		break;
	case SYS_CREATE:
		create(f->R.rsi, f->R.rdi);
		break;
	case SYS_REMOVE:
		remove(f->R.rsi);
		break;
	case SYS_OPEN:
		break;
	case SYS_FILESIZE:
		break;
	case SYS_READ:
		break;
	case SYS_WRITE:
		printf("%s", (char *)f->R.rsi); // rsi가 문자열 가리키는 포인터
		break;
	case SYS_SEEK:
		break;
	case SYS_TELL:
		break;
	case SYS_CLOSE:
		break;
	default:
		break;
	}
}

void check_address(void *addr){
	struct thread *cur = thread_current();
	if (addr == NULL || !(is_user_vaddr(addr))||pml4_get_page(cur->pml4, addr) == NULL){
		exit(-1);
	}
}

// pintos를 종료시키는 시스템 콜
void halt(void){
	power_off(); // 핀토스를 종료시키는 함수
}

// 현재 프로세스를 종료시키는 시스템 콜
void exit(int status){
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n",thread_name(), status);
	thread_exit();
}

//파일을 생성하는 시스템 콜
bool create(const char* file, unsigned initial_size){
	//check_address(file);
	return filesys_create(file,initial_size); // 파일 이름과 파일 사이즈를 인자 값으로 받아 파일을 생성하는 함수
}

//파일을 삭제하는 시스템 콜
bool remove(const char* file){
	//check_address(file);
	return filesys_remove(file); // 파일 이름에 해당하는 파일을 제거하는 함수
}