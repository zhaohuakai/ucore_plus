#include "stdio.h"
#include <fcntl.h>

int main(){
	int fp;
	fp=open("foo.jar",O_RDONLY);
	if(fp==-1) { 
        	return NULL;
	}
	printf("fp=%d\n", fp);
	long size = lseek(fp,0,SEEK_END);
	printf("size=%ld\n", size);
	size = lseek(fp,0,SEEK_END);
        printf("size=%ld\n", size);
	
	fp=open("foo222.jar",O_RDONLY);
        if(fp==-1) {
//                return NULL;
        }
	printf("fp=%d\n", fp);
        size = lseek(4,0,SEEK_END);
        printf("size=%ld\n", size);
        size = lseek(5,0,SEEK_END);
        printf("size=%ld\n", size);
        size = lseek(6,0,SEEK_END);
        printf("size=%ld\n", size);
	return 0;
}
