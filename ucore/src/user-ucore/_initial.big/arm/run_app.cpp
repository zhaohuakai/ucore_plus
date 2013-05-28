#include <stdio.h>
#include <unistd.h>

int main(){
	printf("111111\n");
	execve("simple_hello_arm", NULL, NULL);
	printf("nothing\n");
	return 0;
}
