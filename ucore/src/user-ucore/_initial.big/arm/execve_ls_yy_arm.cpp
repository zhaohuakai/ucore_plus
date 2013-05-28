#include<unistd.h>
main()
{
	char * argv[ ]={"ls",(char *)0};
	char * envp[ ]={"PATH=/bin",0};
	execve("/bin/ls",argv,envp);
}
