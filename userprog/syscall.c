#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/flags.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "vm/vm.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

// Project2-4 File descriptor
static struct file *find_file_by_fd(int fd);
int add_file_to_fdt(struct file *file);
void remove_file_from_fdt(int fd);

// Project2-extra
const int STDIN = 1;
const int STDOUT = 2;

int exec(char *file_name);
tid_t fork(const char *thread_name, struct intr_frame *f);
struct page * check_address(void *addr);
void check_valid_buffer(void* buffer, unsigned size, void* rsp, bool to_write);
void halt(void);
void exit(int status);
int wait(tid_t tid);
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
void* mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

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

	lock_init(&file_rw_lock); // ????????? ?????????
}

/* The main system call interface */
void syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
#ifdef VM
		thread_current()->rsp_stack = f->rsp;
#endif

	char *fn_copy;
	int siz;
	switch (f->R.rax)
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
		if (exec(f->R.rdi) == -1)
			exit(-1);
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
		check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 1);
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 0);
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
		break;
	case SYS_DUP2:
		f->R.rax = dup2(f->R.rdi, f->R.rsi);
		break;
	 // for VM
	case SYS_MMAP:
		f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
		break;
	case SYS_MUNMAP:
		munmap(f->R.rdi);
		break;
	default:
		exit(-1);
		break;
	}
}

// pintos ???????????? ?????? 
void halt(void) {
	power_off();
}

// ?????? ??????
bool create(const char *file, unsigned initial_size) {
	// check_address(file);
	// return filesys_create(file, initial_size);
	if (file)
        return filesys_create(file,initial_size); // ASSERT, dir_add (name!=NULL)
    else
        exit(-1);
}

// ?????? ??????
bool remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}

// page??? ?????? check_address ??????
struct page * check_address(void *addr) {
    if (is_kernel_vaddr(addr)) {
        exit(-1);
    }
    return spt_find_page(&thread_current()->spt, addr);
}

void check_valid_buffer(void* buffer, unsigned size, void* rsp, bool to_write) {
    for (int i = 0; i < size; i++) {
        struct page* page = check_address(buffer + i);    // ????????? ?????? buffer?????? buffer + size????????? ????????? ??? ???????????? ????????? ???????????? ??????
        if(page == NULL)
            exit(-1);
        if(to_write == true && page->writable == false)
            exit(-1);
    }
}

void exit(int status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status); // Process Termination Message
	thread_exit();
}

tid_t fork(const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
}

int exec(char *file_name)
{
	check_address(file_name); 

	int siz = strlen(file_name) + 1;

	//?????? ?????? ????????? ??????
	char *fn_copy = palloc_get_page(PAL_ZERO);

	if(fn_copy == NULL)
		exit(-1);
	
	strlcpy(fn_copy, file_name, siz);

	if (process_exec(fn_copy) == -1)
		return -1;

	NOT_REACHED();
	return 0;
}

int wait(tid_t tid){
	return process_wait(tid);
}

int open(const char *file) {
	check_address(file);

	// open_null ????????? ?????? ??????
	if (file == NULL) {
		return -1;
	}

	struct file *fileobj = filesys_open(file);
	// filesys_open()??? return file_open(inode) -> file_open()??? return file ?????????, 
	// fileobj = ?????? ????????? ?????? file??? ???

	if (fileobj == NULL)
		return -1;

	int fd = add_file_to_fdt(fileobj);

	if (fd == -1)
		file_close(fileobj);
	
	return fd;		
}

// Find open spot in current thread's fdt and put file in it. Returns the fd.
int add_file_to_fdt(struct file *file) {
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable;

	// Project2-extra - (multi-oom) Find open spot from the front
	while(cur->fdIdx < FDCOUNT_LIMIT && fdt[cur->fdIdx])
		cur->fdIdx++;
	
	// error - fdt full
	if (cur->fdIdx >= FDCOUNT_LIMIT)
		return -1;
	
	fdt[cur->fdIdx] = file;
	return cur->fdIdx;
}

// ???????????? ?????? ??????(bytes) ??????
int filesize(int fd) {
	struct file *fileobj = find_file_by_fd(fd);
	
	if(fileobj == NULL)
		return -1;
	return file_length(fileobj);
}

static struct file *find_file_by_fd(int fd) {
	struct thread *cur = thread_current();

	// error- invalid fd
	if (fd <0 || fd >= FDCOUNT_LIMIT)
		return NULL;
	return cur ->fdTable[fd]; // automatically returns NULL if empty
}

void seek(int fd, unsigned position) {
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj <= 2)
		return;
	fileobj->pos = position;  
}

unsigned tell(int fd) {
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj <= 2)
		return;
	return file_tell(fileobj); // find_tell()??? file->pos??? ??????
}

// close file descriptor fd. Ignores NULL file. Returns nothing.
void close(int fd) {
	struct file *fileobj = find_file_by_fd(fd);
	if(fileobj == NULL)
		return;
	
	struct thread *cur = thread_current();

	if(fd == 0 || fileobj == STDIN)
	{
		cur->stdin_count--;
	}
	else if(fd == 1 || fileobj == STDOUT)
	{
		cur->stdout_count--;
	}

	remove_file_from_fdt(fd);
	if (fd <=1 || fileobj <= 2)
		return;

	if (fileobj->dupCount == 0)
		file_close(fileobj);
	else
		fileobj->dupCount--;
}

void remove_file_from_fdt(int fd) {
	struct thread *cur = thread_current();

	//error -invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;
	cur->fdTable[fd] = NULL;
}

int read(int fd, void *buffer, unsigned size) {
	int ret;
	struct thread *cur = thread_current();

	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;

	// ??????????????? ???????????? ???????????? ??????
	if (fileobj == STDIN)
	{
		if (cur->stdin_count == 0) {
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}
		else {
			int i;
			unsigned char *buf = buffer;
			for (i =0; i < size; i++) {
				char c = input_getc(); // ???????????? ???????????? ?????? ??????
				*buf++ = c;
				if (c == '\0')
					break;
			}
			ret = i;
		}
	}
	else if (fileobj == STDOUT) {
		ret = -1;
	}
	// ???????????? read?????? ?????? 
	else {
		lock_acquire(&file_rw_lock);
		ret = file_read(fileobj, buffer, size); // file_read()??? bytes_read ?????????
		lock_release(&file_rw_lock);
	}
	return ret;
}

int write(int fd, const void *buffer, unsigned size) {
	int ret;

	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;
	struct thread *cur = thread_current();

	if(fileobj == STDOUT){
		if(cur->stdout_count == 0) {
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}
		else {
			putbuf(buffer, size);
			ret = size;
		}
	}
	else if (fileobj == STDIN) {
		ret = -1;
	}
	// ????????? write?????? ?????? 
	else {
		lock_acquire(&file_rw_lock);
		ret = file_write(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}
	return ret;
}

// Creates 'copy' of oldfd into newfd. If newfd is open, close it. Returns newfd on success, -1 on fail (invalid oldfd)
// After dup2, oldfd and newfd 'shares' struct file, but closing newfd should not close oldfd (important!)
int dup2(int oldfd, int newfd)
{
	struct file *fileobj = find_file_by_fd(oldfd);
	if (fileobj == NULL)
		return -1;

	struct file *deadfile = find_file_by_fd(newfd);

	if (oldfd == newfd)
		return newfd;

	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable;

	// Don't literally copy, but just increase its count and share the same struct file
	// [syscall close] Only close it when count == 0

	// Copy stdin or stdout to another fd
	if (fileobj == STDIN)
		cur->stdin_count++;
	else if (fileobj == STDOUT)
		cur->stdout_count++;
	else
		fileobj->dupCount++;

	close(newfd);
	fdt[newfd] = fileobj;
	return newfd;
}

// for Memory Mapped Files
/*
 * addr: ????????? ????????? ??????(page ??????)
 * fd: ??????????????? ?????? ?????? ????????? ????????? ??????
 * length: ????????? ????????? ??????
 */
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset) {

    if (offset % PGSIZE != 0) {
        return NULL;
    }

    if (pg_round_down(addr) != addr || is_kernel_vaddr(addr) || addr == NULL || (long long)length <= 0)
        return NULL;
    
    if (fd == 0 || fd == 1)
        exit(-1);
    
    // vm_overlap
    if (spt_find_page(&thread_current()->spt, addr))
        return NULL;

    struct file *target = process_get_file(fd);
	// struct file *target = find_file_by_fd(fd);

    if (target == NULL)
        return NULL;

    void * ret = do_mmap(addr, length, writable, target, offset);

    return ret;
}

void munmap (void *addr) {
    do_munmap(addr);
}