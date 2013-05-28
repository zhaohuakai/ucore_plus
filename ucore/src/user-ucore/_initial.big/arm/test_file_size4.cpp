#include "stdio.h"
#include <sys/stat.h>
#include <fcntl.h>
#define MFILE "/foo.jar"

int getfilesize()
{
    int iresult;
    struct stat buf;
    iresult = stat(MFILE,&buf);
    if(iresult == 0)
    {
        return buf.st_size;
    }
    return NULL;
}

int getfilesize01()
{
    int fp;
    fp=open(MFILE,O_RDONLY);
    if(fp==-1) 
        return NULL;
    return 111;//filelength(fp);
    //return NULL;
}

int getfilesize02()
{
    int fp;
    fp=open(MFILE,O_RDONLY);
    if(fp==-1) 
        return NULL;
    return lseek(fp,0,SEEK_END);
    //return NULL;
}

int getfilesize03()
{
    int fp;
    fp=open(MFILE,O_RDONLY);
    if(fp==-1) 
        return NULL;
    return lseek(fp,0,SEEK_END);
    //return NULL;
}

int getfilesize04()
{
    FILE *fp;
    if((fp=fopen(MFILE,"r"))==NULL)
        return 0;
    fseek(fp,0,SEEK_END);
    return ftell(fp);    //return NULL;
}

int getfilesize05()
{
    FILE *fp;
    char str[1];
    if((fp=fopen(MFILE,"rb"))==NULL)
        return 0;
int i=9;    
for(i = 0;!feof(fp);i++)
    {
        fread(&str,1,1,fp);
        
    }
    return i - 1;    //return NULL;
}

int main(int argc, char* argv[])
{
    
    printf("getfilesize()=%d\n",getfilesize());
    printf("getfilesize01()=%d\n",getfilesize01());
    printf("getfilesize02()=%d\n",getfilesize02());
    printf("getfilesize03()=%d\n",getfilesize03());
    printf("getfilesize04()=%d\n",getfilesize04());
    printf("getfilesize05()=%d\n",getfilesize05());
    return 0;
}
