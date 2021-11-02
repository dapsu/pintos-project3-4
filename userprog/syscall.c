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
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "string.h"
#include "filesys/fat.h"


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
bool sys_chdir(const char *path_name);
bool sys_mkdir(const char *dir);
bool sys_readdir(int fd, char *name);
bool is_dir(int fd);
struct cluster_t *sys_inumber(int fd);
int symlink (const char *target, const char *linkpath);

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

	lock_init(&file_rw_lock); // 초기화 해주기
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
	// for filesystem
    case SYS_CHDIR:
        f->R.rax = sys_chdir(f->R.rdi);
        break;
    case SYS_MKDIR:
        f->R.rax = sys_mkdir(f->R.rdi);
        break;
    case SYS_READDIR:
        f->R.rax = sys_readdir(f->R.rdi, f->R.rsi);
        break;
	case SYS_ISDIR:
        f->R.rax = is_dir(f->R.rdi);
        break;
    case SYS_INUMBER:
        f->R.rax = sys_inumber(f->R.rdi);
        break;
	case SYS_SYMLINK:
        f->R.rax = symlink(f->R.rdi, f->R.rsi);
        break;
	// default:
	// 	exit(-1);
	// 	break;
	}
}

// pintos 프로그램 종료 
void halt(void) {
	power_off();
}

// 파일 생성
bool create(const char *file, unsigned initial_size) {
	// check_address(file);
	// return filesys_create(file, initial_size);
	if (file)
        return filesys_create(file,initial_size); // ASSERT, dir_add (name!=NULL)
    else
        exit(-1);
}

// 파일 삭제
bool remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}

// page에 맞게 check_address 수정
struct page * check_address(void *addr) {
    if (is_kernel_vaddr(addr)) {
        exit(-1);
    }
    return spt_find_page(&thread_current()->spt, addr);
}

void check_valid_buffer(void* buffer, unsigned size, void* rsp, bool to_write) {
    for (int i = 0; i < size; i++) {
        struct page* page = check_address(buffer + i);    // 인자로 받은 buffer부터 buffer + size까지의 크기가 한 페이지의 크기를 넘을수도 있음
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

	//힙에 동적 메모리 할당
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

	// open_null 테스트 패스 위해
	if (file == NULL) {
		return -1;
	}

	struct file *fileobj = filesys_open(file);
	// filesys_open()은 return file_open(inode) -> file_open()은 return file 이므로, 
	// fileobj = 리턴 값으로 받은 file이 됨

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

// 열려있는 파일 크기(bytes) 리턴
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
	return file_tell(fileobj); // find_tell()은 file->pos을 반환
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

	// 터미널에서 사용자가 입력하는 경우
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
				char c = input_getc(); // 키보드로 입력받은 문자 반환
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
	// 파일에서 read하는 경우 
	else {
		lock_acquire(&file_rw_lock);
		ret = file_read(fileobj, buffer, size); // file_read()는 bytes_read 리턴함
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
	// 파일에 write하는 경우 
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
 * addr: 매핑을 시작할 주소(page 단위)
 * fd: 프로세스의 가상 주소 공간에 매핑할 파일
 * length: 매핑할 파일의 길이
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

// for directory
// 현재 디렉토리의 위치 변경
bool sys_chdir(const char *path_name) {
    if (path_name == NULL) {
        return false;
	}

    // name의 파일 경로 를 cp_name에 복사
    char *cp_name = (char *)malloc(strlen(path_name) + 1);
    strlcpy(cp_name, path_name, strlen(path_name) + 1);

    struct dir *chdir = NULL;

    if (cp_name[0] == '/') {	// 절대 경로로 디렉토리 되어 있다면
        chdir = dir_open_root();
    }
    else {						// 상대 경로로 디렉토리 되어 있다면
        chdir = dir_reopen(thread_current()->cur_dir);
	}

    // dir경로를 분석하여 디렉터리를 반환
    char *token, *savePtr;
    token = strtok_r(cp_name, "/", &savePtr);

    struct inode *inode = NULL;
    while (token != NULL) {
        // dir에서 token이름의 파일을 검색하여 inode의 정보를 저장
        if (!dir_lookup(chdir, token, &inode)) {
            dir_close(chdir);
            return false;
        }

        // inode가 파일일 경우 NULL 반환
        if (!inode_is_dir(inode)) {
            dir_close(chdir);
            return false;
        }

        // dir의 디렉터리 정보를 메모리에서 해지
        dir_close(chdir);
        
        // inode의 디렉터리 정보를 dir에저장
        chdir = dir_open(inode);

        // token에검색할경로이름저장
        token = strtok_r(NULL, "/", &savePtr);
    }
    // 스레드의현재작업디렉터리를변경
    dir_close(thread_current()->cur_dir);
    thread_current()->cur_dir = chdir;
    free(cp_name);
    return true;
}

// directory 생성
bool sys_mkdir(const char *dir) {
    lock_acquire(&file_rw_lock);
    bool new_dir = filesys_create_dir(dir);
    lock_release(&file_rw_lock);
    return new_dir;
}

// directory 내 파일 존재 여부 확인
bool sys_readdir(int fd, char *name) {
    if (name == NULL) {
        return false;
	}

    // fd리스트에서 fd에 대한 file정보 얻어옴 
    // struct file *target = process_get_file(fd);
	struct file *target = find_file_by_fd(fd);
    if (target == NULL) {
        return false;
	}

    // fd의 file->inode가 디렉터리인지 검사
    if (!inode_is_dir(file_get_inode(target))) {
        return false;
	}

    // p_file을 dir자료구조로 포인팅
    struct dir *p_file = target;
    if (p_file->pos == 0) {
        dir_seek(p_file, 2 * sizeof(struct dir_entry));		// ".", ".." 제외
	}

    // 디렉터리의 엔트리에서 ".", ".." 이름을 제외한 파일이름을 name에 저장
    bool result = dir_readdir(p_file, name);

    return result;
}

// file의 directory 여부 판단
bool is_dir(int fd) {
    // struct file *target = process_get_file(fd);
	struct file *target = find_file_by_fd(fd);

    if (target == NULL) {
        return false;
	}

    return inode_is_dir(file_get_inode(target));
}

// file의 inode가 기록된 sector 찾기
struct cluster_t *sys_inumber(int fd) {
    // struct file *target = process_get_file(fd);
	struct file *target = find_file_by_fd(fd);

    if (target == NULL) {
        return false;
	}

    return inode_get_inumber(file_get_inode(target));
}

// 바로가기 file 생성
int symlink (const char *target, const char *linkpath) {
    // SOFT LINK
    bool success = false;
    char* cp_link = (char *)malloc(strlen(linkpath) + 1);
    strlcpy(cp_link, linkpath, strlen(linkpath) + 1);

    // cp_name의경로분석
    char* file_link = (char *)malloc(strlen(cp_link) + 1);
    struct dir* dir = parse_path(cp_link, file_link);

    cluster_t inode_cluster = fat_create_chain(0);

    // link file 전용 inode 생성 및 directory에 추가
    success = (dir != NULL
               && link_inode_create(inode_cluster, target)
               && dir_add(dir, file_link, inode_cluster));

    if (!success && inode_cluster != 0) {
        fat_remove_chain(inode_cluster, 0);
	}
    
    dir_close(dir);
    free(cp_link);
    free(file_link);

    return success - 1;
}