#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

// Project2-4 File descriptor
static struct file *find_file_by_fd(int fd);
// Project2-extra
const int STDIN = 1;
const int STDOUT = 2;

void exit(int status);

int exec(char *file_name);
void check_address(uaddr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int dup2(int oldfd, int newfd);


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

	char *fn_copy;
	int siz;

	switch (f->R.rax)
	{
	// case SYS_HALT:
	// 	halt();
	// 	break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	// case SYS_FORK:
	// 	f->R.rax = fork(f->R.rdi, f);
	// 	break;
	// case SYS_EXEC:
	// 	if (exec(f->R.rdi) == -1)
	// 		exit(-1);
	// 	break;
	// case SYS_WAIT:
	// 	f->R.rax = process_wait(f->R.rdi);
	// 	break;
	// case SYS_CREATE:
	// 	f->R.rax = create(f->R.rdi, f->R.rsi);
	// 	break;
	// case SYS_REMOVE:
	// 	f->R.rax = remove(f->R.rdi);
	// 	break;
	// case SYS_OPEN:
	// 	f->R.rax = open(f->R.rdi);
	// 	break;
	// case SYS_FILESIZE:
	// 	f->R.rax = filesize(f->R.rdi);
	// 	break;
	// case SYS_READ:
	// 	f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
	// 	break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	// case SYS_SEEK:
	// 	seek(f->R.rdi, f->R.rsi);
	// 	break;
	// case SYS_TELL:
	// 	f->R.rax = tell(f->R.rdi);
	// 	break;
	// case SYS_CLOSE:
	// 	close(f->R.rdi);
	// 	break;
	// case SYS_DUP2:
	// 	f->R.rax = dup2(f->R.rdi, f->R.rsi);
	// 	break;
	// default:
	// 	exit(-1);
	// 	break;
	}

	// printf ("system call!\n");
	// thread_exit ();
}

void check_address(const uint64_t *uaddr) {

	struct thread *cur = thread_current();
	if	(uaddr == NULL || !(is_user_vaddr(uaddr)) || pml4_get_page(cur->pml4, uaddr) == NULL)
	{
		exit(-1);
	}
}

int write(int fd, const void *buffer, unsigned size) {
	if(fd==1){
		putbuf(buffer, size);
		return size;
	}
	return -1;
}

void exit(int status)
{
	// struct thread *cur = thread_current();
	// cur->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status); // Process Termination Message
	thread_exit();
}

// int exec(char *file_name)
// {
// 	struct thread *cur = thread_current(); // 왜해주지..?
// 	// check_address(file_name); // 주소 유효성 검사

// 	// 문제점) SYS_EXEC - process_exec의 process_cleanup 때문에 f->R.rdi 날아감
// 	// 여기서 file_name 동적할당해서 복사한 뒤, 그걸 넘겨주기
// 	int siz = strlen(file_name) + 1;
// 	//strlen(file_name) +1 에서  +1은 '\n'을 위한 것
// 	// +1 은 char*(8byte)만큼 늘어나는 것을 의미하므로, 한글자 더 읽을 수 있게됨

// 	char *fn_copy = palloc_get_page(PAL_ZERO); // 힙에 메모리 동적 할당 해주기
// 	if (fn_copy == NULL) // 할당 실패시 
// 		exit(-1);
// 	strlcpy(fn_copy, file_name, siz); //file_name을 fn_copy에 복사해 넣기
// 	// file_name 내 공백을 기준으로 쪼개어주어야 하나, 다른 곳에서 file_name을 사용할 수 있으므로
// 	// memcpy를 통해 원본 복사(깊은 복사)로 넘겨주기

// 	// 실패 시, 할당한 page free하고 -1 리턴함
// 	if (process_exec(fn_copy) == -1)
// 		return -1;

// 	// Not reachable
// 	NOT_REACHED();
// 	return 0;
// }