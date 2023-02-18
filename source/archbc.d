module archbc;

version (AArch64)
{
	// from <fcntl.h>
	enum F_SETFL     = 0x00000004;
	enum O_APPEND    = 0x00000400;
	enum O_CLOEXEC   = 0x00080000;
	enum O_CREAT     = 0x00000040;
	enum O_DIRECTORY = 0x00004000;
	enum O_NONBLOCK  = 0x00000800;
	enum O_TRUNC     = 0x00000200;
	enum O_WRONLY    = 0x00000001;
	enum O_RDONLY    = 0x00000000;
	
	// from <unistd.h>
	enum F_LOCK  	 = 0x00000001;
	enum F_OK        = 0x00000000;
	enum F_TLOCK     = 0x00000002;
	enum X_OK        = 0x00000001;

	
	// from <bits/waitstatus.h>
	int WEXITSTATUS(int status)	{
		return ((status) & 0xff00) >> 8;
	}
	
	int WIFEXITED(int status) {
		return (WTERMSIG(status) == 0);
	}
	
	int WTERMSIG(int status) {
		return (status) & 0x7f;
	}
}

version (X86_64)
{
	// from <fcntl.h>
	enum F_SETFL     = 0x00000004;
	enum O_APPEND    = 0x00000400;
	enum O_CLOEXEC   = 0x00080000;
	enum O_CREAT     = 0x00000040;
	enum O_DIRECTORY = 0x00010000;
	enum O_NONBLOCK  = 0x00000800;
	enum O_TRUNC     = 0x00000200;
	enum O_WRONLY    = 0x00000001;
	enum O_RDONLY    = 0x00000000;
	
	// from <unistd.h>
	enum F_LOCK  	 = 0x00000001;
	enum F_OK    	 = 0x00000000;
	enum F_TLOCK 	 = 0x00000002;
	enum X_OK    	 = 0x00000001;
	
	// from <bits/waitstatus.h>
	int WEXITSTATUS(int status)	{
		return ((status) & 0xff00) >> 8;
	}
	
	int WIFEXITED(int status) {
		return (WTERMSIG(status) == 0);
	}
	
	int WTERMSIG(int status) {
		return (status) & 0x7f;
	}
}
