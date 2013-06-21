#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void cleanup(void *arg)
{
    printf("cleanup: %s\n", (char *)arg);
}
void *thr_fn(void *arg) /*线程入口地址*/
{
    printf("thread start\n");
    pthread_cleanup_push(cleanup, "thread first handler");/*设置第一个线程处理程序*/
    pthread_cleanup_push(cleanup, "thread second handler"); /*设置第二个线程处理程序*/
    printf("thread push complete\n");
    int yy=0;
    pthread_cleanup_pop((void *)yy); /*取消第一个线程处理程序*/
    pthread_cleanup_pop((void *)yy); /*取消第二个线程处理程序*/
}
int main()
{
    pthread_t tid;
    void *tret;
    int ttt = 1;
    pthread_create(&tid,NULL,thr_fn,(void *)ttt); /*创建一个线程*/
    pthread_join(tid, &tret); /*获得线程终止状态*/
    printf("thread exit code %d\n",(int)tret);
}
