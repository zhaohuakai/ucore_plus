#include <proc.h>
#include <trap.h>
#include <stdio.h>
#include <pmm.h>
#include <vmm.h>
#include <clock.h>
#include <assert.h>
#include <sem.h>
#include <event.h>
#include <mbox.h>
#include <stat.h>
#include <dirent.h>
#include <sysfile.h>
#include <kio.h>
#include <error.h>
#include <syscall.h>
#include <resource.h>
#include <iobuf.h>

static uint32_t sys_exit(uint32_t arg[])
{
	//kprintf("[syscall sys_exit]\n");
	int error_code = (int)arg[0];
	return do_exit(error_code);
}

static uint32_t sys_fork(uint32_t arg[])
{
	//kprintf("[syscall sys_fork]\n");
	struct trapframe *tf = pls_read(current)->tf;
	uintptr_t stack = tf->tf_esp;
	return do_fork(0, stack, tf);
}

static uint32_t sys_wait(uint32_t arg[])
{
	kprintf("[syscall sys_wait]\n");
	int pid = (int)arg[0];
	int *store = (int *)arg[1];
	return do_wait(pid, store);
}

static uint32_t sys_execve(uint32_t arg[])
{
	//kprintf("[syscall sys_execve]\n");
	const char *name = (const char *)arg[0];
	const char **argv = (const char **)arg[1];
	
	/*if(argv == NULL){
		argv = (const char **)0x6fffbf10;
		argv[0] = (const char *)arg[0];		
		argv[1] = NULL;
		
	}*/
	/*
	kprintf("argv = %x\n", argv);
	kprintf("argv addr=%x\n", &argv);
	kprintf("arg addr=%x\n", &arg);
	kprintf("arg[0] addr=%x\n", &arg[0]);
	kprintf("arg[1] addr=%x\n", &arg[1]);
	kprintf("argv[0] addr=%x\n", &argv[0]);
	*/
	const char **envp = (const char **)arg[2];
	return do_execve(name, argv, envp);
}

static uint32_t sys_clone(uint32_t arg[])
{
	kprintf("[syscall sys_clone]\n");
	struct trapframe *tf = pls_read(current)->tf;
	uint32_t clone_flags = (uint32_t) arg[0];
	uintptr_t stack = (uintptr_t) arg[1];
	if (stack == 0) {
		stack = tf->tf_esp;
	}
	return do_fork(clone_flags, stack, tf);
}

static uint32_t sys_exit_thread(uint32_t arg[])
{
	kprintf("[syscall sys_exit_thread]\n");
	int error_code = (int)arg[0];
	return do_exit_thread(error_code);
}

static uint32_t sys_yield(uint32_t arg[])
{
	kprintf("[syscall sys_yield]\n");
	return do_yield();
}

static uint32_t sys_kill(uint32_t arg[])
{
	kprintf("[syscall sys_kill]\n");
	int pid = (int)arg[0];
	return do_kill(pid, -E_KILLED);
}

static uint32_t sys_getpid(uint32_t arg[])
{
	kprintf("[syscall sys_getpid]\n");
	return pls_read(current)->pid;
}

static uint32_t sys_sleep(uint32_t arg[])
{
	unsigned int time = (unsigned int)arg[0];
	return do_sleep(time);
}

static uint32_t sys_gettime(uint32_t arg[])
{
	return (int)ticks;
}

static uint32_t sys_putc(uint32_t arg[])
{
	kprintf("[syscall sys_putc]\n");
	int c = (int)arg[0];
	kcons_putc(c);
	return 0;
}

static uint32_t sys_pgdir(uint32_t arg[])
{
	print_pgdir(kprintf);
	return 0;
}

static uint32_t sys_brk(uint32_t arg[])
{
	//kprintf("[syscall sys_brk]\n");
	uintptr_t *brk_store = (uintptr_t *) arg[0];
	return do_brk(brk_store);
}

static uint32_t sys_mmap(uint32_t arg[])
{
	kprintf("[syscall sys_mmap]\n");
	uintptr_t *addr_store = (uintptr_t *) arg[0];
	size_t len = (size_t) arg[1];
	uint32_t mmap_flags = (uint32_t) arg[2];
	return do_mmap(addr_store, len, mmap_flags);
}

static uint32_t sys_munmap(uint32_t arg[])
{
	kprintf("[syscall sys_munmap]\n");
	uintptr_t addr = (uintptr_t) arg[0];
	size_t len = (size_t) arg[1];
	return do_munmap(addr, len);
}

static uint32_t sys_shmem(uint32_t arg[])
{
	kprintf("[syscall sys_shmem]\n");
	uintptr_t *addr_store = (uintptr_t *) arg[0];
	size_t len = (size_t) arg[1];
	uint32_t mmap_flags = (uint32_t) arg[2];
	return do_shmem(addr_store, len, mmap_flags);
}

static uint32_t sys_sem_init(uint32_t arg[])
{
	int value = (int)arg[0];
	return ipc_sem_init(value);
}

static uint32_t sys_sem_post(uint32_t arg[])
{
	sem_t sem_id = (sem_t) arg[0];
	return ipc_sem_post(sem_id);
}

static uint32_t sys_sem_wait(uint32_t arg[])
{
	sem_t sem_id = (sem_t) arg[0];
	unsigned int timeout = (unsigned int)arg[1];
	return ipc_sem_wait(sem_id, timeout);
}

static uint32_t sys_sem_free(uint32_t arg[])
{
	sem_t sem_id = (sem_t) arg[0];
	return ipc_sem_free(sem_id);
}

static uint32_t sys_sem_get_value(uint32_t arg[])
{
	sem_t sem_id = (sem_t) arg[0];
	int *value_store = (int *)arg[1];
	return ipc_sem_get_value(sem_id, value_store);
}

static uint32_t sys_event_send(uint32_t arg[])
{
	int pid = (int)arg[0];
	int event = (int)arg[1];
	unsigned int timeout = (unsigned int)arg[2];
	return ipc_event_send(pid, event, timeout);
}

static uint32_t sys_event_recv(uint32_t arg[])
{
	int *pid_store = (int *)arg[0];
	int *event_store = (int *)arg[1];
	unsigned int timeout = (unsigned int)arg[2];
	return ipc_event_recv(pid_store, event_store, timeout);
}

static uint32_t sys_mbox_init(uint32_t arg[])
{
	unsigned int max_slots = (unsigned int)arg[0];
	return ipc_mbox_init(max_slots);
}

static uint32_t sys_mbox_send(uint32_t arg[])
{
	int id = (int)arg[0];
	struct mboxbuf *buf = (struct mboxbuf *)arg[1];
	unsigned int timeout = (unsigned int)arg[2];
	return ipc_mbox_send(id, buf, timeout);
}

static uint32_t sys_mbox_recv(uint32_t arg[])
{
	int id = (int)arg[0];
	struct mboxbuf *buf = (struct mboxbuf *)arg[1];
	unsigned int timeout = (unsigned int)arg[2];
	return ipc_mbox_recv(id, buf, timeout);
}

static uint32_t sys_mbox_free(uint32_t arg[])
{
	int id = (int)arg[0];
	return ipc_mbox_free(id);
}

static uint32_t sys_mbox_info(uint32_t arg[])
{
	int id = (int)arg[0];
	struct mboxinfo *info = (struct mboxinfo *)arg[1];
	return ipc_mbox_info(id, info);
}

static uint32_t sys_open(uint32_t arg[])
{
	//kprintf("[syscall sys_open]\n");
	const char *path = (const char *)arg[0];
	uint32_t open_flags = (uint32_t) arg[1];
	return sysfile_open(path, open_flags);
}

static uint32_t sys_close(uint32_t arg[])
{
	//kprintf("[syscall sys_close]\n");
	int fd = (int)arg[0];
	return sysfile_close(fd);
}

static uint32_t sys_read(uint32_t arg[])
{
	//kprintf("[syscall sys_read]\n");
	int fd = (int)arg[0];
	void *base = (void *)arg[1];
	size_t len = (size_t) arg[2];
	return sysfile_read(fd, base, len);
}

static uint32_t sys_write(uint32_t arg[])
{
	//kprintf("[syscall sys_write]\n");
	int fd = (int)arg[0];
	void *base = (void *)arg[1];
	size_t len = (size_t) arg[2];
	return sysfile_write(fd, base, len);
}

static uint32_t sys_seek(uint32_t arg[])
{
	kprintf("[syscall sys_seek]\n");
	int fd = (int)arg[0];
	off_t pos = (off_t) arg[1];
	int whence = (int)arg[2];
	return sysfile_seek(fd, pos, whence);
}

#define __sys_linux_lseek sys_seek

static uint32_t sys_fstat(uint32_t arg[])
{
	//kprintf("[syscall sys_fstat]\n");
	int fd = (int)arg[0];
	struct stat *stat = (struct stat *)arg[1];
	return sysfile_fstat(fd, stat);
}

static uint32_t sys_fsync(uint32_t arg[])
{
	kprintf("[syscall sys_fsync]\n");
	int fd = (int)arg[0];
	return sysfile_fsync(fd);
}

static uint32_t sys_chdir(uint32_t arg[])
{
	kprintf("[syscall sys_chdir]\n");
	const char *path = (const char *)arg[0];
	return sysfile_chdir(path);
}

static uint32_t sys_getcwd(uint32_t arg[])
{
	kprintf("[syscall sys_getcwd]\n");
	char *buf = (char *)arg[0];
	size_t len = (size_t) arg[1];
	return sysfile_getcwd(buf, len);
}

static uint32_t sys_mkdir(uint32_t arg[])
{
	kprintf("[syscall sys_mkdir]\n");
	const char *path = (const char *)arg[0];
	return sysfile_mkdir(path);
}

static uint32_t sys_link(uint32_t arg[])
{
	kprintf("[syscall sys_link]\n");
	const char *path1 = (const char *)arg[0];
	const char *path2 = (const char *)arg[1];
	return sysfile_link(path1, path2);
}

static uint32_t sys_rename(uint32_t arg[])
{
	kprintf("[syscall sys_rename]\n");
	const char *path1 = (const char *)arg[0];
	const char *path2 = (const char *)arg[1];
	return sysfile_rename(path1, path2);
}

static uint32_t sys_unlink(uint32_t arg[])
{
	kprintf("[syscall sys_unlink]\n");
	const char *name = (const char *)arg[0];
	return sysfile_unlink(name);
}

static uint32_t sys_getdirentry(uint32_t arg[])
{
	//kprintf("[syscall sys_getdirentry]\n");
	int fd = (int)arg[0];
	struct dirent *direntp = (struct dirent *)arg[1];
	return sysfile_getdirentry(fd, direntp, NULL);
}

static uint32_t sys_dup(uint32_t arg[])
{
	kprintf("[syscall sys_dup]\n");
	int fd1 = (int)arg[0];
	int fd2 = (int)arg[1];
	return sysfile_dup(fd1, fd2);
}

static uint32_t sys_pipe(uint32_t arg[])
{
	kprintf("[syscall sys_pipe]\n");
	int *fd_store = (int *)arg[0];
	return sysfile_pipe(fd_store);
}

static uint32_t sys_mkfifo(uint32_t arg[])
{
	kprintf("[syscall sys_mkfifo]\n");
	const char *name = (const char *)arg[0];
	uint32_t open_flags = (uint32_t) arg[1];
	return sysfile_mkfifo(name, open_flags);
}

static uint32_t sys_ioctl(uint32_t arg[])
{
	kprintf("[syscall sys_ioctl]\n");
	int fd = (int)arg[0];
	unsigned int cmd = arg[1];
	unsigned long data = (unsigned long)arg[2];
	return sysfile_ioctl(fd, cmd, data);
}

static uint32_t sys_init_module(uint32_t arg[])
{
	kprintf("[syscall sys_init_module]\n");
	void __user *umod = (void __user *)arg[0];
	unsigned long len = (unsigned long)arg[1];
	const char *urgs = (const char *)arg[2];
	return do_init_module(umod, len, urgs);
}

static uint32_t sys_cleanup_module(uint32_t arg[])
{
	kprintf("[syscall sys_cleanup_module]\n");
	const char __user *name = (const char __user *)arg[0];
	return do_cleanup_module(name);
}

static uint32_t sys_list_module(uint32_t arg[])
{
	kprintf("[syscall sys_list_module]\n");
	print_modules();
	return 0;
}

static uint32_t sys_mount(uint32_t arg[])
{
	kprintf("[syscall sys_mount]\n");
	const char *source = (const char *)arg[0];
	const char *target = (const char *)arg[1];
	const char *filesystemtype = (const char *)arg[2];
	const void *data = (const void *)arg[3];
	return do_mount(source, filesystemtype);
}

static uint32_t sys_umount(uint32_t arg[])
{
	kprintf("[syscall sys_umount]\n");
	const char *target = (const char *)arg[0];
	return do_umount(target);
}

static uint32_t sys_linux_mmap(uint32_t arg[])
{
	kprintf("[syscall sys_linux_mmap]\n");
	void *addr = (void *)arg[0];
	size_t len = arg[1];
	int fd = (int)arg[2];
	size_t off = (size_t) arg[3];
	return (uint32_t) sysfile_linux_mmap2(addr, len, 0, 0, fd, off);
}

static uint32_t sys_linux_sigaction(uint32_t arg[])
{
	//kprintf("[syscall sys_linux_sigaction]\n");
	return do_sigaction((int)arg[0], (const struct sigaction *)arg[1],
			    (struct sigaction *)arg[2]);
}

#define __sys_linux_sigaction sys_linux_sigaction
#define __sys_linux_rt_sigaction sys_linux_sigaction

static uint32_t sys_linux_sigprocmask(uint32_t arg[])
{
	kprintf("[syscall sys_linux_sigprocmask]\n");
	return do_sigprocmask((int)arg[0], (const sigset_t *)arg[1],
			      (sigset_t *) arg[2]);
}

#define __sys_linux_sigprocmask sys_linux_sigprocmask
#define __sys_linux_rt_sigprocmask sys_linux_sigprocmask

static uint32_t sys_linux_sigpending(uint32_t arg[])
{
	kprintf("[syscall sys_linux_sigpending]\n");
	return do_sigpending((sigset_t *) arg[0]);
}

#define __sys_linux_sigpending sys_linux_sigpending
#define __sys_linux_rt_sigpending sys_linux_sigpending

static uint32_t sys_linux_sigtkill(uint32_t arg[])
{
	kprintf("[syscall sys_linux_sigtkill]\n");
	return do_sigtkill((int)arg[0], (int)arg[1]);
}

#define __sys_linux_sigtkill sys_linux_sigtkill

static uint32_t sys_linux_sigsuspend(uint32_t arg[])
{
	kprintf("[syscall sys_linux_sigsuspend]\n");
	return do_sigsuspend((sigset_t *) arg[0]);
}

#define __sys_linux_sigsuspend sys_linux_sigsuspend
#define __sys_linux_rt_sigsuspend sys_linux_sigsuspend

static uint32_t sys_linux_sigkill(uint32_t arg[])
{
	kprintf("[syscall sys_linux_sigkill]\n");
	return do_sigkill((int)arg[0], (int)arg[1]);
}

#define __sys_linux_sigkill sys_linux_sigkill
#define __sys_linux_kill    sys_linux_sigkill

static uint32_t sys_linux_sigaltstack(uint32_t arg[])
{
	kprintf("[syscall sys_linux_sigaltstack]\n");
	const stack_t *stack = (const stack_t *)arg[0];
	stack_t *old = (stack_t *) arg[1];
	return do_sigaltstack(stack, old);
}

#define __sys_linux_sigaltstack sys_linux_sigaltstack

static uint32_t sys_linux_sigwaitinfo(uint32_t arg[])
{
	kprintf("[syscall sys_linux_sigwaitinfo]\n");
	const sigset_t *set = (const sigset_t *)arg[0];
	struct siginfo_t *info = (struct siginfo_t *)arg[1];
	return do_sigwaitinfo(set, info);
}

#define __sys_linux_sigwaitinfo sys_linux_sigwaitinfo

//this never used by user program
static uint32_t sys_linux_sigreturn(uint32_t arg[])
{
	kprintf("[syscall sys_linux_sigreturn]\n");
	return do_sigreturn();
}

#define __sys_linux_sigreturn sys_linux_sigreturn
#define __sys_linux_rt_sigreturn sys_linux_sigreturn

///////////////////////////////////////////

static uint32_t __sys_linux_ioctl(uint32_t args[])
{
	//kprintf("[syscall __sys_linux_ioctl]\n");
	int fd = (int)args[0];
	//FIXME
	if (fd < 3)
		return 0;
	unsigned int cmd = args[1];
	unsigned long data = (unsigned long)args[2];
	return sysfile_ioctl(fd, cmd, data);
}

static uint32_t __sys_linux_mmap2(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_mmap2]\n");
	//TODO
	void *addr = (void *)arg[0];
	size_t len = arg[1];
	int prot = (int)arg[2];
	int flags = (int)arg[3];
	int fd = (int)arg[4];
	size_t off = (size_t) arg[5];
#ifndef UCONFIG_BIONIC_LIBC
	kprintf
	    ("TODO __sys_linux_mmap2 addr=%08x len=%08x prot=%08x flags=%08x fd=%d off=%08x\n",
	     addr, len, prot, flags, fd, off);
#endif //UCONFIG_BIONIC_LIBC
	if (fd == -1 || flags & MAP_ANONYMOUS) {
		//print_trapframe(pls_read(current)->tf);
#ifdef UCONFIG_BIONIC_LIBC
		if (flags & MAP_FIXED) {
			return linux_regfile_mmap2(addr, len, prot, flags, fd,
						   off);
		}
#endif //UCONFIG_BIONIC_LIBC

		uint32_t ucoreflags = 0;
		if (prot & PROT_WRITE)
			ucoreflags |= MMAP_WRITE;
		int ret = __do_linux_mmap((uintptr_t) & addr, len, ucoreflags);
		//kprintf("@@@ ret=%d %e %08x\n", ret,ret, addr);
		if (ret)
			return MAP_FAILED;
		//kprintf("__sys_linux_mmap2 ret=%08x\n", addr);
		return addr;
	} else {
		return (uint32_t) sysfile_linux_mmap2(addr, len, prot, flags,
						      fd, off);
	}
}

static uint32_t __sys_linux_dup(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_dup]\n");
	int fd = (int)arg[0];
	return sysfile_dup(fd, NO_FD);
}

static uint32_t __sys_linux_fcntl(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_fcntl]\n");
	return -E_INVAL;
}

#ifdef UCONFIG_BIONIC_LIBC
static uint32_t __sys_linux_mprotect(uint32_t arg[])
{
	
	//kprintf("[syscall __sys_linux_mprotect]\n");
	void *addr = (void *)arg[0];
	size_t len = arg[1];
	int prot = arg[2];

	//kprintf("mprotect addr=0x%08x len=%08x prot=%08x\n", addr, len, prot);

	return do_mprotect(addr, len, prot);
}
#endif //UCONFIG_BIONIC_LIBC

static uint32_t __sys_linux_brk(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_brk]\n");
	uintptr_t brk = (uintptr_t) arg[0];
	return do_linux_brk(brk);
}

static uint32_t __sys_linux_getdents(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_getdents]\n");
	int fd = (int)arg[0];
	struct dirent *dir = (struct dirent *)arg[1];
	uint32_t count = arg[2];
	if (count < sizeof(struct dirent))
		return -1;
	int ret = sysfile_getdirentry(fd, dir, &count);
	if (ret < 0)
		return -1;
	return count;
}

static uint32_t __sys_linux_stat(uint32_t args[])
{
	kprintf("[syscall __sys_linux_stat]\n");
	char *fn = (char *)args[0];
	struct linux_stat *st = (struct linux_stat *)args[1];
	//kprintf("TODO __sys_linux_stat, %s %d\n", fn, sizeof(struct linux_stat));
	return sysfile_linux_stat(fn, st);
}

static uint32_t __sys_linux_fstat(uint32_t args[])
{
	kprintf("[syscall __sys_linux_fstat]\n");
	int fd = (int)args[0];
	struct linux_stat *st = (struct linux_stat *)args[1];
	//kprintf("TODO __sys_linux_fstat, %d %d\n", fd, sizeof(struct linux_stat));
	return sysfile_linux_fstat(fd, st);
}

static uint32_t __sys_linux_waitpid(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_waitpid]\n");
	int pid = (int)arg[0];
	int *store = (int *)arg[1];
	int options = (int)arg[2];
	void *rusage = (void *)arg[3];
	if (options && rusage)
		return -E_INVAL;
	return do_linux_waitpid(pid, store);
}

#define __sys_linux_wait4 __sys_linux_waitpid

static uint32_t __sys_linux_sched_yield(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_sched_yield]\n");
	return do_yield();
}

static uint32_t __sys_linux_ugetrlimit(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_ugetrlimit]\n");
	int res = (int)arg[0];
	struct linux_rlimit *lim = (struct linux_rlimit *)arg[1];
	return do_linux_ugetrlimit(res, lim);
}

/*
  Clone a task - this clones the calling program thread.
  * This is called indirectly via a small wrapper
  
 asmlinkage int sys_clone(unsigned long clone_flags, unsigned long newsp,
                          int __user *parent_tidptr, int tls_val,
                          int __user *child_tidptr, struct pt_regs *regs)
 */
static uint32_t __sys_linux_clone(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_clone]\n");
	struct trapframe *tf = pls_read(current)->tf;
	uint32_t clone_flags = (uint32_t) arg[0];
	uintptr_t stack = (uintptr_t) arg[1];
	if (stack == 0) {
		stack = tf->tf_esp;
	}
	return do_fork(clone_flags, stack, tf);
}

static uint32_t __sys_linux_pipe(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_pipe]\n");
	int *fd_store = (int *)arg[0];
	return sysfile_pipe(fd_store) ? -1 : 0;
}

static uint32_t __sys_linux_getppid(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_getppid]\n");
	struct proc_struct *parent = pls_read(current)->parent;
	if (!parent)
		return 0;
	return parent->pid;
}

struct linux_pollfd {
	int fd;			/* file descriptor */
	short events;		/* requested events */
	short revents;		/* returned events */
};

static uint32_t __sys_linux_poll(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_poll]\n");
	//FIXME
	struct linux_pollfd *fd = (struct linux_pollfd *)arg[0];
	int nfds = (int)arg[1];
	int timeout = (int)arg[2];	//ms
	fd->revents = fd->events;
	return nfds;
}

static uint32_t __sys_linux_exit(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_exit]\n");
	int error_code = (int)arg[0];
	return do_exit_thread(error_code);
}

static uint32_t __sys_linux_exit_group(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_exit_group]\n");
	int error_code = (int)arg[0];
	return do_exit(error_code);
}

static uint32_t __sys_linux_nanosleep(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_nanosleep]\n");
	//TODO: handle signal interrupt
	struct linux_timespec *req = (struct linux_timespec *)arg[0];
	struct linux_timespec *rem = (struct linux_timespec *)arg[1];
	return do_linux_sleep(req, rem);
}

/* always root */
static uint32_t __sys_linux_getuid(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_getuid]\n");
	return 0;
}

#define __sys_linux_geteuid __sys_linux_getuid
#define __sys_linux_getuid32 __sys_linux_getuid
#define __sys_linux_geteuid32 __sys_linux_geteuid

static uint32_t __sys_linux_getgid(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_getgid]\n");
	return 0;
}

#define __sys_linux_getegid __sys_linux_getgid
#define __sys_linux_getgid32 __sys_linux_getgid
#define __sys_linux_getegid32 __sys_linux_getegid

#include <linux_misc_struct.h>
static uint32_t __sys_linux_gettimeofday(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_gettimeofday]\n");
	struct linux_timeval *tv = (struct linux_timeval *)arg[0];
	struct linux_timezone *tz = (struct linux_timezone *)arg[1];
	return ucore_gettimeofday(tv, tz);
}

#ifdef UCONFIG_BIONIC_LIBC
static uint32_t __sys_linux_gettid(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_gettid]\n");
	return pls_read(current)->tid;
}

static uint32_t __sys_arm_linux_set_tls(uint32_t arg[])
{
	//kprintf("[syscall __sys_arm_linux_set_tls]\n");
	struct user_tls_desc *tlsp = (struct user_tls_desc *)arg[0];
	return do_set_tls(tlsp);
}

static uint32_t __sys_linux_stat64(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_stat64]\n");
	char *path = (char *)arg[0];
	struct linux_stat64 *filestat = arg[1];
	return sysfile_linux_stat64(path, filestat);
}

static uint32_t __sys_linux_madvise(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_madvise]\n");
	void *addr = (void *)arg[0];
	size_t len = arg[1];
	int advice = arg[2];
	return do_madvise(addr, len, advice);
}

static uint32_t __sys_linux_futex(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_futex]\n");
	uintptr_t uaddr = (uintptr_t) arg[0];
	int op = arg[1] & 127;
	int val = arg[2];
	return do_futex(uaddr, op, val);
}

static uint32_t __sys_linux_clock_gettime(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_clock_gettime]\n");
	struct linux_timespec *time = (struct linux_timespec *)arg[1];
	return do_clock_gettime(time);
}

static uint32_t __sys_linux_fstat64(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_fstat64]\n");
	int fd = (int)arg[0];
	struct linux_stat64 *st = (struct linux_stat64 *)arg[1];
	return sysfile_linux_fstat64(fd, st);
}

static uint32_t __sys_linux_fcntl64(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_fcntl64]\n");
	int fd = (int)arg[0];
	int cmd = (int)arg[1];
	int ctl_arg = (int)arg[2];

	return sysfile_linux_fcntl64(fd, cmd, ctl_arg);
}

static uint32_t __sys_linux_access(uint32_t arg[])
{
	kprintf("[syscall __sys_linux_access]\n");
	char *path = (char *)arg[0];
	int amode = (int)arg[1];
	return linux_access(path, amode);
}

static uint32_t __sys_linux_writev(uint32_t arg[])
{
	//kprintf("[syscall __sys_linux_writev]\n");
	int fd = (int)arg[0];
	struct iovec *iov = (struct iovec *)arg[1];
	int iovcnt = (int)arg[2];
	return sysfile_writev(fd, iov, iovcnt);
}

#endif //UCONFIG_BIONIC_LIBC

#define __UCORE_SYSCALL(x) [__NR_##x]  sys_##x
#define __LINUX_SYSCALL(x) [__NR_##x]  __sys_linux_##x

#define __ARM_LINUX_SYSCALL(x) [__ARM_NR_##x] __sys_arm_linux_##x

#define sys_dup2 sys_dup

#include <linux_unistd.h>

static uint32_t(*_linux_syscalls[]) (uint32_t arg[]) = {
	__LINUX_SYSCALL(exit),
	    __UCORE_SYSCALL(fork),
	    __UCORE_SYSCALL(read),
	    __UCORE_SYSCALL(write),
	    __UCORE_SYSCALL(open),
	    __UCORE_SYSCALL(close),
	    __UCORE_SYSCALL(link),
	    __UCORE_SYSCALL(unlink),
	    __UCORE_SYSCALL(execve),
	    __UCORE_SYSCALL(chdir),
	    __LINUX_SYSCALL(kill),
	    __UCORE_SYSCALL(rename), __UCORE_SYSCALL(mkdir),
	    /* rmdir */
	    __LINUX_SYSCALL(dup), __LINUX_SYSCALL(pipe),
	    /* times */
	    __LINUX_SYSCALL(brk),
	    __LINUX_SYSCALL(lseek),
	    __UCORE_SYSCALL(getpid),
	    __LINUX_SYSCALL(getppid),
	    __LINUX_SYSCALL(ioctl),
	    __LINUX_SYSCALL(fcntl),
	    __UCORE_SYSCALL(dup2),
	    __LINUX_SYSCALL(sigaction),
	    __LINUX_SYSCALL(stat),
	    __LINUX_SYSCALL(fstat),
	    __LINUX_SYSCALL(wait4),
	    __UCORE_SYSCALL(fsync),
	    __LINUX_SYSCALL(sigreturn),
	    __LINUX_SYSCALL(clone),
	    __LINUX_SYSCALL(sigprocmask),
	    __LINUX_SYSCALL(exit_group),
	    __UCORE_SYSCALL(getcwd),
	    __LINUX_SYSCALL(getdents),
	    __LINUX_SYSCALL(poll),
	    __LINUX_SYSCALL(rt_sigreturn),
	    __LINUX_SYSCALL(rt_sigaction),
	    __LINUX_SYSCALL(rt_sigprocmask), __LINUX_SYSCALL(rt_sigpending),
	    //__LINUX_SYSCALL(rt_sigtimedwait),
	    __LINUX_SYSCALL(rt_sigsuspend),
	    __LINUX_SYSCALL(ugetrlimit),
	    __LINUX_SYSCALL(mmap2),
	    __UCORE_SYSCALL(munmap),
	    __LINUX_SYSCALL(sched_yield),
	    __LINUX_SYSCALL(nanosleep),
	    __LINUX_SYSCALL(getuid),
	    __LINUX_SYSCALL(geteuid),
	    __LINUX_SYSCALL(getuid32),
	    __LINUX_SYSCALL(geteuid32),
	    __LINUX_SYSCALL(getgid),
	    __LINUX_SYSCALL(getegid),
	    __LINUX_SYSCALL(getgid32),
	    __LINUX_SYSCALL(getegid32), __LINUX_SYSCALL(gettimeofday),
#ifdef UCONFIG_BIONIC_LIBC
	    __LINUX_SYSCALL(mprotect),
	    __LINUX_SYSCALL(gettid),
	    __ARM_LINUX_SYSCALL(set_tls),
	    __LINUX_SYSCALL(stat64),
	    __LINUX_SYSCALL(madvise),
	    __LINUX_SYSCALL(futex),
	    __LINUX_SYSCALL(clock_gettime),
	    __LINUX_SYSCALL(fstat64),
	    __LINUX_SYSCALL(fcntl64),
	    __LINUX_SYSCALL(access), __LINUX_SYSCALL(writev),
#endif //UCONFIG_BIONIC_LIBC
};

#define NUM_LINUX_SYSCALLS        ((sizeof(_linux_syscalls)) / (sizeof(_linux_syscalls[0])))

/* Linux EABI
 * r7 = syscall num
 * r0 - r3 = args
 * NOTE: EABI requires kernel to save lr,
 * while it is saved by user code in OABI
 */

static int __sys_linux_entry(struct trapframe *tf)
{
	int num = tf->tf_regs.reg_r[7];
	//int p = NUM_LINUX_SYSCALLS;
	if (num < NUM_LINUX_SYSCALLS && _linux_syscalls[num]) {
		uint32_t arg[6];
		arg[0] = tf->tf_regs.reg_r[0];	// arg0
		arg[1] = tf->tf_regs.reg_r[1];	// arg1
		arg[2] = tf->tf_regs.reg_r[2];	// arg2
		arg[3] = tf->tf_regs.reg_r[3];	// arg3
		arg[4] = tf->tf_regs.reg_r[4];	// arg3
		arg[5] = tf->tf_regs.reg_r[5];	// arg3
		
		//kprintf("sizeof(_linux_syscalls)=%d\n",sizeof(_linux_syscalls));
		//kprintf("sizeof(_linux_syscalls[0])=%d\n",sizeof(_linux_syscalls[0]));
		//kprintf("p=%d\n",p);
		/*
		switch(num){			
			case 1:
				kprintf("[syscall no %d]\tsys_exit\n", num); 	break;
			case 2:
				kprintf("[syscall no %d]\tsys_fork\n", num); 	break;
			case 3:
				//kprintf("[syscall no %d]\tsys_read\n", num); 	break;
				kprintf("[syscall no %d]\tread(%d, %d)\n", num, arg[0], arg[2]); 	break;
			case 4:
				//kprintf("[syscall no %d]\tsys_write\n", num); 
				break;
			case 5:
				//kprintf("[syscall no %d]\tsys_open path=%s\n", num, arg[0] ); break;
				kprintf("[syscall no %d]\topen(%s)\n", num, arg[0]); break;
			case 6:
				//kprintf("[syscall no %d]\tsys_close\n", num); break;
				kprintf("[syscall no %d]\tclose(%d)\n", num, arg[0]); break;
			case 11:
				kprintf("[syscall no %d]\tsys_execve\n", num); 
				kprintf("addr arg[0] = %x\n", &arg[0]);
				kprintf("addr arg[1] = %x\n", &arg[1]);
				kprintf("addr arg[2] = %x\n", &arg[2]);
				break;
			case 19:
				kprintf("[syscall no %d]\tsys_seek\n", num); break;
			case 20:
				kprintf("[syscall no %d]\tsys_getpid\n", num); break;
			case 45:
				kprintf("[syscall no %d]\t_sys_linux_brk\n", num); break;
			case 54:
				kprintf("[syscall no %d]\t__sys_linux_ioctl\n", num); break;
			case 67:
				//kprintf("[syscall no %d]\tsys_linux_sigaction\n", num); 
				break;
			case 91:
				//kprintf("[syscall no %d]\tsys_munmap\n", num); break;
				kprintf("[syscall no %d]\tmunmap(%x, %d, %d)\n", num, arg[0], arg[1], arg[2]); break;
			case 125:
				//kprintf("[syscall no %d]\t__sys_linux_mprotect\n", num); break;
				kprintf("[syscall no %d]\tmprotect(%x, %d, %d)\n", num, arg[0], arg[1], arg[2]); break;
			case 192:
				//kprintf("[syscall no %d]\t__sys_linux_mmap2\n", num); break;
				kprintf("[syscall no %d]\tmmap(%x, %d, %d, %d, %d)\n", num, arg[0], arg[1], arg[2], arg[3], arg[4]); break;
			case 195:
				kprintf("[syscall no %d]\t__sys_linux_stat64\n", num); break;
			case 197:
				//kprintf("[syscall no %d]\t__sys_linux_fstat64\n", num); break;
				kprintf("[syscall no %d]\tfstat(%d)\n", num, arg[0]); break;
			case 199: // TODO
				kprintf("[syscall no %d]\t__sys_linux_getuid\n", num); break;
			case 200: // TODO
				kprintf("[syscall no %d]\t__sys_linux_getgid\n", num); break;
			case 201: // TODO
				kprintf("[syscall no %d]\t__sys_linux_getuid\n", num); break;
			case 202: // TODO
				kprintf("[syscall no %d]\t__sys_linux_getgid\n", num); break;
			case 220:
				//kprintf("[syscall no %d]\t__sys_linux_madvise\n", num); 
				break;
			case 221:				
				kprintf("[syscall no %d]\t__sys_linux_fcntl64\n", num); break;
			case 224:
				kprintf("[syscall no %d]\t__sys_linux_gettid\n", num); break;
			case 240:
				kprintf("[syscall no %d]\t__sys_linux_futex\n", num); break;				
			case 248:
				kprintf("[syscall no %d]\t__sys_linux_exit_group\n", num); break;
			case 263:
				kprintf("[syscall no %d]\t__sys_linux_clock_gettime\n", num); break;
			case 983045:				
				kprintf("[syscall no %d]\t__sys_arm_linux_set_tls\n", num); break;
			default:
				//kprintf("");
				kprintf("[syscall no %d]\t\n",num);
		}
		*/
		tf->tf_regs.reg_r[0] = _linux_syscalls[num] (arg);	// calling the system call, return value in r0
		
		switch(num){			
			case 1:
				kprintf("[syscall no %d]\tsys_exit\n", num); 	break;
			case 2:
				kprintf("[syscall no %d]\tsys_fork\n", num); 	break;
			case 3:
				kprintf("[syscall no %d]\tread(%d, %d) = %d\n", num, arg[0], arg[2], tf->tf_regs.reg_r[0]); 	break;
			case 4:
				//kprintf("[syscall no %d]\tsys_write\n", num); 
				break;
			case 5:
				kprintf("[syscall no %d]\topen(%s) = %d\n", num, arg[0], tf->tf_regs.reg_r[0]); break;
			case 6:
				kprintf("[syscall no %d]\tclose(%d) = %d\n", num, arg[0], tf->tf_regs.reg_r[0]); break;
			case 11:
				kprintf("[syscall no %d]\tsys_execve\n", num); 
				//kprintf("addr arg[0] = %x\n", &arg[0]);
				//kprintf("addr arg[1] = %x\n", &arg[1]);
				//kprintf("addr arg[2] = %x\n", &arg[2]);
				break;
			case 19:
				kprintf("[syscall no %d]\tsys_seek\n", num); break;
			case 20:
				kprintf("[syscall no %d]\tsys_getpid\n", num); break;
			case 45:
				kprintf("[syscall no %d]\t_sys_linux_brk\n", num); break;
			case 54:
				kprintf("[syscall no %d]\t__sys_linux_ioctl\n", num); break;
			case 67:
				//kprintf("[syscall no %d]\tsys_linux_sigaction\n", num); 
				break;
			case 91:
				kprintf("[syscall no %d]\tmunmap(%x, %d, %d) = %d\n", num, arg[0], arg[1], arg[2], tf->tf_regs.reg_r[0]); break;
			case 125:
				//kprintf("[syscall no %d]\tmprotect(%x, %d, %d) = %d\n", num, arg[0], arg[1], arg[2], tf->tf_regs.reg_r[0]); 
				break;
			case 146:
				//kprintf("[syscall no %d]\t sysfile_writev(fd=%08x iov=%08x iovcnt=%d) = %d\n", num, arg[0], arg[1], arg[2], tf->tf_regs.reg_r[0]);
				break;
			case 192:
				kprintf("[syscall no %d]\tmmap(%x, %d, %d, %d, %d) = %x\n", num, arg[0], arg[1], arg[2], arg[3], arg[4], tf->tf_regs.reg_r[0]); break;
			case 195:
				//kprintf("[syscall no %d]\t__sys_linux_stat64\n", num); 
				break;
			case 197:
				kprintf("[syscall no %d]\tfstat(%d) = %d\n", num, arg[0], tf->tf_regs.reg_r[0]); break;
			case 199: // TODO
				kprintf("[syscall no %d]\t__sys_linux_getuid\n", num); break;
			case 200: // TODO
				kprintf("[syscall no %d]\t__sys_linux_getgid\n", num); break;
			case 201: // TODO
				kprintf("[syscall no %d]\t__sys_linux_getuid\n", num); break;
			case 202: // TODO
				kprintf("[syscall no %d]\t__sys_linux_getgid\n", num); break;
			case 220:
				//kprintf("[syscall no %d]\t__sys_linux_madvise\n", num); 
				break;
			case 221:				
				kprintf("[syscall no %d]\t__sys_linux_fcntl64\n", num); break;
			case 224:
				kprintf("[syscall no %d]\t__sys_linux_gettid\n", num); break;
			case 240:
				kprintf("[syscall no %d]\t__sys_linux_futex\n", num); break;				
			case 248:
				kprintf("[syscall no %d]\t__sys_linux_exit_group\n", num); break;
			case 263:
				kprintf("[syscall no %d]\t__sys_linux_clock_gettime\n", num); break;
			case 983045:				
				kprintf("[syscall no %d]\t__sys_arm_linux_set_tls\n", num); break;
			default:
				kprintf("[syscall no %d]\t\n",num);
		}
		
		return 0;
	}else{
		return 0;
		kprintf("[!!! undefined syscall no %d]\n",num);
	}

	return -1;
}

static uint32_t(*syscalls[]) (uint32_t arg[]) = {
[SYS_exit] sys_exit,
	    [SYS_fork] sys_fork,
	    [SYS_wait] sys_wait,
	    [SYS_exec] sys_execve,
	    [SYS_clone] sys_clone,
	    [SYS_exit_thread] sys_exit_thread,
	    [SYS_yield] sys_yield,
	    [SYS_kill] sys_kill,
	    [SYS_sleep] sys_sleep,
	    [SYS_gettime] sys_gettime,
	    [SYS_getpid] sys_getpid,
	    [SYS_brk] sys_brk,
	    [SYS_mmap] sys_mmap,
	    [SYS_munmap] sys_munmap,
	    [SYS_shmem] sys_shmem,
	    [SYS_putc] sys_putc,
	    [SYS_pgdir] sys_pgdir,
	    [SYS_sem_init] sys_sem_init,
	    [SYS_sem_post] sys_sem_post,
	    [SYS_sem_wait] sys_sem_wait,
	    [SYS_sem_free] sys_sem_free,
	    [SYS_sem_get_value] sys_sem_get_value,
	    [SYS_event_send] sys_event_send,
	    [SYS_event_recv] sys_event_recv,
	    [SYS_mbox_init] sys_mbox_init,
	    [SYS_mbox_send] sys_mbox_send,
	    [SYS_mbox_recv] sys_mbox_recv,
	    [SYS_mbox_free] sys_mbox_free,
	    [SYS_mbox_info] sys_mbox_info,
	    [SYS_open] sys_open,
	    [SYS_close] sys_close,
	    [SYS_read] sys_read,
	    [SYS_write] sys_write,
	    [SYS_seek] sys_seek,
	    [SYS_fstat] sys_fstat,
	    [SYS_fsync] sys_fsync,
	    [SYS_chdir] sys_chdir,
	    [SYS_getcwd] sys_getcwd,
	    [SYS_mkdir] sys_mkdir,
	    [SYS_link] sys_link,
	    [SYS_rename] sys_rename,
	    [SYS_unlink] sys_unlink,
	    [SYS_getdirentry] sys_getdirentry,
	    [SYS_dup] sys_dup,
	    [SYS_pipe] sys_pipe,
	    [SYS_mkfifo] sys_mkfifo,
	    [SYS_ioctl] sys_ioctl,
	    [SYS_linux_mmap] sys_linux_mmap,
	    [SYS_linux_tkill] sys_linux_sigtkill,
	    [SYS_linux_sigaction] sys_linux_sigaction,
	    [SYS_linux_kill] sys_linux_sigkill,
	    [SYS_linux_sigprocmask] sys_linux_sigprocmask,
	    [SYS_linux_sigsuspend] sys_linux_sigsuspend,
	    [SYS_linux_sigreturn] sys_linux_sigreturn,
	    [SYS_init_module] sys_init_module,
	    [SYS_cleanup_module] sys_cleanup_module,
	    [SYS_list_module] sys_list_module,
	    [SYS_mount] sys_mount,[SYS_umount] sys_umount};

#define NUM_SYSCALLS        ((sizeof(syscalls)) / (sizeof(syscalls[0])))

void syscall()
{	
	uint32_t arg[5];
	struct trapframe *tf = pls_read(current)->tf;
	int num = tf->tf_err;	// SYS_xxx
	unsigned int num_linux_call = 0;
	if(num == 0){
		num_linux_call = tf->tf_regs.reg_r[7];
	}
	if (num == 0) {
		if (__sys_linux_entry(tf))
			goto bad_call;
		return;
	}
	if (num >= 0 && num < NUM_SYSCALLS) {
		if (syscalls[num] != NULL) {
			
			switch(num){
				case 1:
					kprintf("[##syscall no=%d sys_exit]\n", num); break;
				case 2:
					kprintf("[##syscall no=%d sys_fork]\n", num); break;
				case 3:
					kprintf("[##syscall no=%d sys_wait]\n", num); break;
				case 4:
					kprintf("[##syscall no=%d sys_execve]\n", num); break;
				case 19:
					kprintf("[##syscall no=%d sys_brk]\n", num); break;
				case 22:
					kprintf("[##syscall no=%d sys_shmem]\n", num); break;
				case 100:
					//kprintf("[##syscall no=%d sys_open]\n", num); 
					break;
				case 101:
					//kprintf("[##syscall no=%d sys_close]\n", num); 
					break;
				case 102:
					//kprintf("[##syscall no=%d sys_read]\n", num);
					break;
				case 103:
					//kprintf("[##syscall no=%d write arg[1]=%s, arg[2]=%d]\n",num,arg[1],arg[2]); 
					break;
				case 110:
					//kprintf("[##syscall no=%d sys_fstat]\n", num); 
					break;
				case 120:
					kprintf("[##syscall no=%d sys_chdir]\n", num); 
					break;
				case 121:
					kprintf("[##syscall no=%d sys_getcwd]\n", num); 
					break;
				case 128:
					//kprintf("[##syscall no=%d sys_getdirentry]\n",num); 
					break;
				default:
					kprintf("----- syscalls no. %d -----\n",num);
			}	
			
			arg[0] = tf->tf_regs.reg_r[0];	// arg0
			arg[1] = tf->tf_regs.reg_r[1];	// arg1
			arg[2] = tf->tf_regs.reg_r[2];	// arg2
			arg[3] = tf->tf_regs.reg_r[3];	// arg3
			tf->tf_regs.reg_r[0] = syscalls[num] (arg);	// calling the system call, return value in r0
			return;
		}
	}
bad_call:
	print_trapframe(tf);
	kprintf("undefined syscall %d linux_syscall %d, pid = %d, name = %s.\n",
		num, num_linux_call, pls_read(current)->pid, pls_read(current)->name);
	do_exit(-E_KILLED);
}
