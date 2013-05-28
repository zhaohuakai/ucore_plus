#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

int main(){
	int t,t1,t2;
	t = open("/dev/zero", 2);
	t1 = open("/dev", 2);
	t2 = open("Foo.java", 2);
	printf("t=%d\n", t);
	printf("t1=%d\n", t1);
	printf("t2=%d\n", t2);
	return 0;
}
