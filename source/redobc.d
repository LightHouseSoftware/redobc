//import std.conv: octal;

import core.stdc.errno: errno, EAGAIN, ECHILD;
import core.stdc.inttypes : PRIx64;
import core.stdc.limits: PATH_MAX;
import core.stdc.stdarg;
import core.stdc.stdio: FILE, _IO_FILE, stderr;

//import core.sys.posix.fcntl: open;
import core.sys.posix.sys.stat: stat_t;
import core.sys.posix.sys.types: mode_t, off_t, pid_t, ssize_t;
import core.sys.posix.sys.wait: WNOHANG;

import core.sys.posix.unistd: getopt, optarg, optind;

import archbc;
import sha256bc;

extern(C) nothrow @nogc
{
	int access(scope const(char*) pathname, int mode);
	int chdir(const(char*) path);
	int close(int fd);
	int dprintf(int fd, scope const(char*) format, ...);
	int dup2(int oldfd, int newfd);
	int execl(const(char*) path, const(char*) arg, ...);
	void exit(int status);
	int fchdir(int fd);
	int fclose(shared(_IO_FILE)* stream);
	int fcntl(int fd, int cmd, long arg);
	int feof(shared(_IO_FILE)* stream);
	char* fgets(char* s, int n, shared(_IO_FILE)* stream);
	shared(_IO_FILE)* fopen(scope const(char*) filename, scope const(char*) mode);
	pid_t fork();
	int fprintf(shared(_IO_FILE)* stream, scope const(char*) format, ...); 
	int fstat(int fd, stat_t* buf);
	char* getcwd(char* dir, int len);
	char* getenv(scope const(char*) name);
	int lockf(int fd, int cmd, off_t len);  
	void* malloc (size_t size);
	int mkstemp(char* tmplt);
	int open(const(char*) pathname, int flags, ...);
	int openat(int dirfd, scope const(char*) pathname, int flags);
	void perror(scope const(char*) s);
	int pipe(int[2] pipefd);
	int printf(scope const(char*) format, ...);
	ssize_t read(int fd, void* buf, size_t count);
	int remove(const(char*) fname);
	int rename(const(char*) oldfname, const(char*) newfname);
	int setenv(scope const(char*) name, scope const(char*) value, int overwrite);
	int snprintf(scope char* s, size_t n, scope const(char*) format, ... );
	int stat(scope const(char*) path, stat_t* buf);
	inout(char)* strchr(return scope inout(char)* s, int c);
	int strcmp(scope const(char*) s1, scope const(char*) s2);
	char* strdup(scope const(char*) s);
	ulong strlen(scope const(char*) s);
	int strncmp(scope const(char*) s1, scope const(char*) s2, ulong n);
	char* strncpy(return scope char* s1, scope const char* s2, size_t n);
	char* strrchr(scope const(char*) str, int character);
	long strtol(scope inout(char)* nptr, scope inout(char)** endptr, int base);
	int vsnprintf(scope char* s, size_t n, scope const(char*) format, va_list arg);
	pid_t waitpid(pid_t pid, int* status, int options);  
	ssize_t write(int fd, const(void*) buf, size_t nbyte);
}


__gshared int
			dir_fd = -1,
			dep_fd = -1,
			poolwr_fd = -1,
			poolrd_fd = -1,
			level = -1,
			implicit_jobs = 1;
 
__gshared int
			kflag, jflag, xflag, fflag, sflag;
			
static void redo_ifcreate(int fd, char* target)
{
	dprintf(fd, "-%s\n", target);
}

extern(C) static char* check_dofile(const char *fmt, ...)
{
	static char[PATH_MAX] dofile;

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cast(char*) dofile.ptr, dofile.sizeof, fmt, ap);
	va_end(ap);

	if (access(cast(char*) dofile.ptr, F_OK) == 0) 
	{
		return cast(char*) dofile.ptr;
	} 
	else 
	{
		redo_ifcreate(dep_fd, cast(char*) dofile.ptr);
		return cast(char*) 0;
	}
}

static char* find_dofile(char* target)
{
	char[PATH_MAX] updir;
	char* u = updir.ptr;
	char* dofile;
	char* s;
	stat_t st, ost;

	dofile = check_dofile("./%s.do", target);
	if (dofile)
	{
		return dofile;
	}

	*u++ = '.';
	*u++ = '/';
	*u = 0;

	st.st_dev  = 0;
	ost.st_dev = 0;
	st.st_ino  = 0;
	ost.st_ino = 0;

	while (1) {
		ost = st;

		if (stat(cast(const(char*)) updir.ptr, &st) < 0)
		{
			return null;
		}
		
		if ((ost.st_dev == st.st_dev) && (ost.st_ino == st.st_ino))
		{
			break;
		}

		s = target;
		
		while (*s) 
		{
			if (*s++ == '.') 
			{
				dofile = check_dofile("%sdefault.%s.do", updir.ptr, s);
				if (dofile)
				{
					return dofile;
				}
			}
		}

		dofile = check_dofile("%sdefault.do", updir.ptr);
		
		if (dofile)
		{
			return dofile;
		}

		*u++ = '.';
		*u++ = '.';
		*u++ = '/';
		*u = 0;
	}

	return null;
}

static int envfd(const char* name)
{
	long fd;

	char* s = getenv(name);
	
	if (!s)
	{
		return -1;
	}

	fd = strtol(s, null, 10);
	
	if ((fd < 0) || (fd > 255))
	{
		fd = -1;
	}

	return cast(int) fd;
}

static void setenvfd(const char* name, int i)
{
	char[16] buf;
	snprintf(buf.ptr, buf.sizeof, "%d", i);
	setenv(name, buf.ptr, 1);
}

static char* datefile(int fd)
{
	static char[17] hexdate;
	stat_t st;

	fstat(fd, &st);
	snprintf(hexdate.ptr, hexdate.sizeof, cast(char*) ("%016" ~ cast(string) PRIx64), cast(ulong) st.st_ctime);

	return hexdate.ptr;
}

static int keepdir()
{
	int fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	
	if (fd < 0) 
	{
		perror("dir open");
		exit(-1);
	}
	
	return fd;
}

static char* targetchdir(char* target)
{
	char* base = strrchr(target, '/');
	
	if (base) 
	{
		*base = 0;
		
		int fd = openat(dir_fd, target, O_RDONLY | O_DIRECTORY);
		
		if (fd < 0) 
		{
			perror("openat dir");
			exit(111);
		}
		
		*base = '/';
		
		if (fchdir(fd) < 0) 
		{
			perror("chdir");
			exit(111);
		}
		
		close(fd);
		
		return base + 1;
	} 
	else 
	{
		fchdir(dir_fd);
		return target;
	}
}

static char* targetdep(char* target)
{
	static char[PATH_MAX] buf;
	snprintf(buf.ptr, buf.sizeof, ".dep.%s", target);
	return buf.ptr;
}

static char* targetlock(char* target)
{
	static char[PATH_MAX] buf;
	snprintf(buf.ptr, buf.sizeof, ".lock.%s", target);
	return buf.ptr;
}

static int sourcefile(char* target)
{
	if (access(targetdep(target), F_OK) == 0)
	{
		return 0;
	}

	if (fflag < 0)
	{
		return access(target, F_OK) == 0;
	}

	return find_dofile(target) is null;
}

static int check_deps(char* target)
{
	char* depfile;
	FILE* f;
	int ok = 1;
	int fd;
	int old_dir_fd = dir_fd;

	target = targetchdir(target);

	if (sourcefile(target))
	{
		return 1;
	}

	if (fflag > 0)
	{
		return 0;
	}

	depfile = targetdep(target);
	
	f = fopen(depfile, "r");
	
	if (!f)
	{
		return 0;
	}

	dir_fd = keepdir();

	while (ok && !feof(f)) 
	{
		char[4096] line;
		char* hash = line.ptr + 1;
		char* timestamp = line.ptr + 1 + 64 + 1;
		char* filename = line.ptr + 1 + 64 + 1 + 16 + 1;

		if (fgets(line.ptr, line.sizeof, f)) 
		{
			line[strlen(line.ptr) - 1] = 0;
			switch (line[0]) 
			{
				case '-':
					if (access(line.ptr + 1, F_OK) == 0)
					{
						ok = 0;
					}
					break;
				case '=':
					fd = open(filename, O_RDONLY);
					if (fd < 0) 
					{
						ok = 0;
					} 
					else 
					{
						if (strncmp(timestamp, datefile(fd), 16) != 0 && strncmp(hash, SHA256_hashfile(fd), 64) != 0)
						{
							ok = 0;
						}
						close(fd);
					}
					if (ok && strcmp(target, filename) != 0) 
					{
						ok = check_deps(filename);
						fchdir(dir_fd);
					}
					break;
				case '!':
					// pass
				default:
					ok = 0;
			}
		} 
		else 
		{
			if (!feof(f)) 
			{
				ok = 0;
				break;
			}
		}
	}

	fclose(f);

	close(dir_fd);
	dir_fd = old_dir_fd;

	return ok;
}

void vacate(int implicit)
{
	if (implicit)
	{
		implicit_jobs++;
	}
	else
	{
		write(poolwr_fd, "\0".ptr, 1);
	}
}

struct Job 
{
	Job* next;
	pid_t pid;
	int lock_fd;
	char* target;
	char* temp_depfile;
	char* temp_target;
	int implicit;
}

__gshared Job* jobhead;

// проверить эти методы. есть сомнения в передаче указателя на job в качестве аргумента. проверить передачу просто job
static void insert_job(Job* job)
{
	job.next = jobhead;
	jobhead = job;
}

static void remove_job(Job* job)
{
	if (jobhead == job)
	{
		jobhead = jobhead.next;
	}
	else 
	{
		Job* j = jobhead;
		while (j.next != job)
		{
			j = j.next;
		}
		j.next = j.next.next;
	}
}

Job* find_job(pid_t pid)
{
	Job* j;

	for (j = jobhead; j; j = j.next) 
	{
		if (j.pid == pid)
		{
			return j;
		}
	}

	return null;
}

__gshared char[PATH_MAX] uprel = "\0";

void compute_uprel()
{
	char* u = uprel.ptr;
	char* dp = getenv("REDO_DIRPREFIX");

	*u = 0;
	while (dp && *dp) 
	{
		*u++ = '.';
		*u++ = '.';
		*u++ = '/';
		*u = 0;
		// почему +1 ? по идее добавляет лишние точки в путь
		dp = strchr(dp + 1, '/');
	}
}

static int write_dep(int dep_fd, char* file)
{
	int fd = open(file, O_RDONLY);
	
	if (fd < 0)
	{
		return 0;
	}
	
	dprintf(dep_fd, "=%s %s %s%s\n", SHA256_hashfile(fd), datefile(fd), (*file == '/' ? "".ptr : cast(char*) uprel.ptr), file);
	close(fd);
	
	return 0;
}

int new_waitjob(int lock_fd, int implicit)
{
	pid_t pid;

	pid = fork();
	
	if (pid < 0) {
		perror("fork");
		vacate(implicit);
		exit(-1);
	} 
	else
	{
		if (pid == 0) 
		{
			lockf(lock_fd, F_LOCK, 0);
			close(lock_fd);
			exit(0);
		} 
		else 
		{
			Job* job = cast(Job*) malloc(Job.sizeof);
			
			if (!job)
			{
				exit(-1);
			}
			
			job.target   = null;
			job.pid      = pid;
			job.lock_fd  = lock_fd;
			job.implicit = implicit;
	
			insert_job(job);
		}
	}
	 
	return 0;
}

static char* redo_basename(char* dofile, char* target)
{
	static char[PATH_MAX] buf;
	int stripext = 0;
	char* s;

	if (strncmp(dofile, "default.", 8) == 0)
	{
		for (stripext = -1, s = dofile; *s; s++)
		{
			if (*s == '.')
			{
				stripext++;
			}
		}
	}

	strncpy(buf.ptr, target, buf.sizeof);
	while (stripext-- > 0) 
	{
		if (strchr(buf.ptr, '.')) 
		{
			char* e = strchr(buf.ptr, '\0');
			while (*--e != '.')
			{
				*e = 0;
			}
			*e = 0;
		}
	}

	return buf.ptr;
}

static void run_script(char* target, int implicit)
{
	char[16] temp_depfile = cast(char[]) ".depend.XXXXXX\0";
	char[16] temp_target_base = cast(char[]) ".target.XXXXXX\0";
	char[PATH_MAX] temp_target;
	char[PATH_MAX] rel_target;
	char[PATH_MAX] cwd;
	char* orig_target = target;
	int old_dep_fd = dep_fd;
	int target_fd;
	char* dofile;
	char* dirprefix;
	pid_t pid;

	target = targetchdir(target);

	dofile = find_dofile(target);
	
	if (!dofile) 
	{
		fprintf(stderr, "no dofile for %s.\n", target);
		exit(1);
	}

	//int lock_fd = open(targetlock(target), O_WRONLY | O_TRUNC | O_CREAT, octal!"666");
	int lock_fd = open(targetlock(target), O_WRONLY | O_TRUNC | O_CREAT, 0x1b6);
	
	if (lockf(lock_fd, F_TLOCK, 0) < 0) 
	{
		if (errno == EAGAIN) 
		{
			fprintf(stderr, "redo: %s already building, waiting.\n", orig_target);
			new_waitjob(lock_fd, implicit);
			return;
		} 
		else 
		{
			perror("lockf");
			exit(111);
		}
	}

	dep_fd = mkstemp(cast(char*) temp_depfile);

	target_fd = mkstemp(cast(char*) temp_target_base);

	fprintf(stderr, "redo%*.*s %s # %s\n", level * 2, level * 2, " ".ptr, orig_target, dofile);
	write_dep(dep_fd, dofile);

	getcwd(cwd.ptr, cwd.sizeof);
	dirprefix = strchr(cwd.ptr, '\0');
	dofile += 2;
	while (strncmp(dofile, "../", 3) == 0) 
	{
		chdir("..");
		dofile += 3;
		while (*--dirprefix != '/')
		{
			// empty
		}
	}
	
	if (*dirprefix)
	{
		dirprefix++;
	}

	snprintf(temp_target.ptr, temp_target.sizeof , "%s%s%s", dirprefix, (*dirprefix ? "/" : "").ptr, temp_target_base.ptr);
	snprintf(rel_target.ptr, rel_target.sizeof, "%s%s%s", dirprefix, (*dirprefix ? "/" : "").ptr, target);

	setenv("REDO_DIRPREFIX", dirprefix, 1);

	pid = fork();
	
	if (pid < 0) 
	{
		perror("fork");
		vacate(implicit);
		exit(-1);
	}
	else
	{
		if (pid == 0) 
		{ 
			char* basename = redo_basename(dofile, rel_target.ptr);
		
			if (old_dep_fd > 0)
			{
				close(old_dep_fd);
			}
			
			close(lock_fd);
			setenvfd("REDO_DEP_FD", dep_fd);
			setenvfd("REDO_LEVEL", level + 1);
			
			if (sflag > 0)
			{
				dup2(target_fd, 1);
			}
			else
			{
				close(target_fd);
			}
		
			if (access(dofile, X_OK) != 0)
			{  
				execl("/bin/sh", "/bin/sh", (xflag > 0 ? "-ex" : "-e").ptr, dofile, rel_target.ptr, basename, temp_target.ptr, cast(char*) 0);
			}
			else
			{
				execl(dofile, dofile, rel_target.ptr, basename, temp_target.ptr, cast(char*) 0);
			}
			vacate(implicit);
			exit(-1);
		} 
		else 
		{
			Job* job = cast(Job*) malloc(Job.sizeof);
			
			if (!job)
			{
				exit(-1);
			}
		
			close(target_fd);
			close(dep_fd);
			dep_fd = old_dep_fd;
		
			job.pid = pid;
			job.lock_fd = lock_fd;
			job.target = orig_target;
			job.temp_depfile = strdup(temp_depfile.ptr);
			job.temp_target = strdup(temp_target_base.ptr);
			job.implicit = implicit;
		
			insert_job(job);
		}
	}
}

static int try_procure()
{
	if (implicit_jobs > 0) 
	{
		implicit_jobs--;
		return 1;
	} 
	else 
	{
		if (poolrd_fd < 0)
		{
			return 0;
		}

		fcntl(poolrd_fd, F_SETFL, O_NONBLOCK);

		char[1] buf;
		return (read(poolrd_fd, &buf, 1) > 0);
	}
}

static int procure()
{
	if (implicit_jobs > 0) 
	{
		implicit_jobs--;
		return 1;
	} 
	else 
	{
		fcntl(poolrd_fd, F_SETFL, 0);

		char[1] buf;
		return (read(poolrd_fd, &buf, 1) > 0);
	}
}

void create_pool()
{
	poolrd_fd = envfd("REDO_RD_FD");
	poolwr_fd = envfd("REDO_WR_FD");
	
	if ((poolrd_fd < 0) || (poolwr_fd < 0)) 
	{
		int jobs = envfd("JOBS");
		
		if (jobs > 1) 
		{
			int i;
			int[2] fds;
			
			pipe(fds);
			poolrd_fd = fds[0];
			poolwr_fd = fds[1];

			for (i = 0; i < (jobs - 1); i++)
			{
				vacate(0);
			}

			setenvfd("REDO_RD_FD", poolrd_fd);
			setenvfd("REDO_WR_FD", poolwr_fd);
		} 
		else 
		{
			poolrd_fd = -1;
			poolwr_fd = -1;
		}
	}
}

static void redo_ifchange(int targetc, char** targetv)
{
	pid_t pid;
	int status;
	Job* job;

	int targeti = 0;

	// XXX
	//char[targetc] skip;
	char[4096] buf = void;
	char* skip = cast(char*) buf.ptr;

	create_pool();

	for (targeti = 0; targeti < targetc; targeti++)
	{
		skip[targeti] = cast(char) check_deps(targetv[targeti]);
	}

	targeti = 0;
	while (1) 
	{
		int procured = 0;
		if (targeti < targetc) 
		{
			char *target = targetv[targeti];

			if (skip[targeti]) 
			{
				targeti++;
				continue;
			}

			int implicit = (implicit_jobs > 0);
			if (try_procure()) 
			{
				procured = 1;
				targeti++;
				run_script(target, implicit);
			}
		}

		pid = waitpid(-1, &status, (procured ? WNOHANG : 0));

		if (pid == 0)
		{
			continue;
		}  

		if (pid < 0) 
		{
			if (errno == ECHILD && targeti < targetc)
			{
				continue;
			}
			else
			{
				break;
			}
		}

		if (WIFEXITED(status))
		{
			status = WEXITSTATUS(status);
		}

		job = find_job(pid);

		if (!job) 
		{
			exit(-1);
		}
		remove_job(job);

		if (job.target) 
		{
			if (status > 0) 
			{
				remove(job.temp_depfile);
				remove(job.temp_target);
			} 
			else 
			{
				stat_t st;
				char* target = targetchdir(job.target);
				char* depfile = targetdep(target);
				int dfd;

				dfd = open(job.temp_depfile, O_WRONLY | O_APPEND);
				if (stat(job.temp_target, &st) == 0) 
				{
					rename(job.temp_target, target);
					write_dep(dfd, target);
				} 
				else 
				{
					remove(job.temp_target);
					redo_ifcreate(dfd, target);
				}
				close(dfd);

				rename(job.temp_depfile, depfile);
				remove(targetlock(target));
			}
		}

		close(job.lock_fd);

		vacate(job.implicit);

		if ((kflag < 0) && (status > 0)) 
		{
			printf("failed with status %d\n", status);
			exit(status);
		}
	}
}

static void record_deps(int targetc, char** targetv)
{
	dep_fd = envfd("REDO_DEP_FD");
	if (dep_fd < 0)
	{
		return;
	}

	fchdir(dir_fd);

	for (int targeti = 0; targeti < targetc; targeti++) 
	{
		int fd = open(targetv[targeti], O_RDONLY);
		if (fd < 0)
		{
			continue;
		}
		write_dep(dep_fd, targetv[targeti]);
		close(fd);
	}
}
			
extern (C) int main(int argc, char** argv) {
	char* program;
	int opt, i;

	dep_fd = envfd("REDO_DEP_FD");

	level = envfd("REDO_LEVEL");
	if (level < 0)
	{
		level = 0;
	}
	
	program = strrchr(argv[0], '/');
	
	if (program)
	{
		program++;
	}
	else
	{
		program = argv[0];
	}
	
	while ((opt = getopt(argc, argv, "+kxfsj:C:")) != -1) 
	{
		switch (opt) 
		{
		case 'k':
			setenvfd("REDO_KEEP_GOING", 1);
			break;
		case 'x':
			setenvfd("REDO_TRACE", 1);
			break;
		case 'f':
			setenvfd("REDO_FORCE", 1);
			break;
		case 's':
			setenvfd("REDO_STDOUT", 1);
			break;
		case 'j':
			setenv("JOBS", optarg, 1);
			break;
		case 'C':
			if (chdir(optarg) < 0) {
				perror("chdir");
				exit(-1);
			}
			break;
		default:
			fprintf(stderr, "usage: %s [-kfsx] [-jN] [-Cdir] [TARGETS...]\n", program);
			exit(1);
		}
	}
	
	argc -= optind;
	argv += optind;

	fflag = envfd("REDO_FORCE");
	kflag = envfd("REDO_KEEP_GOING");
	xflag = envfd("REDO_TRACE");
	sflag = envfd("REDO_STDOUT");

	dir_fd = keepdir();
	
	if (strcmp(program, "redo") == 0) 
	{
		char* all = cast(char*) "all\0".ptr;
		char*[1] argv_def = [all];

		if (argc == 0) 
		{
			argc = 1;
			argv = argv_def.ptr;
		}

		fflag = 1;
		redo_ifchange(argc, argv);
		procure();
	} else if (strcmp(program, "redo-ifchange") == 0) {
		compute_uprel();
		redo_ifchange(argc, argv);
		record_deps(argc, argv);
		procure();
	} else if (strcmp(program, "redo-ifcreate") == 0) {
		for (i = 0; i < argc; i++)
		{
			redo_ifcreate(dep_fd, argv[i]);
		}
	} else if (strcmp(program, "redo-always") == 0) {
		dprintf(dep_fd, "!\n");
	} else if (strcmp(program, "redo-hash") == 0) {
		for (i = 0; i < argc; i++)
		{
			write_dep(1, argv[i]);
		}
	} else {
		fprintf(stderr, "not implemented %s\n", program);
		exit(-1);
	}
	
    return 0;
}
