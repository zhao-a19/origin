/*******************************************************************************************
*文件: FCThread.h
*描述: 线程封装类
*作者: 王君雷
*日期:
*修改:
*        线程ID使用pthread_t类型,使用zlog                               ------> 2018-08-07
*******************************************************************************************/
#include "FCThread.h"
#include "debugout.h"
#include <stdio.h>

CThread::CThread(void)
{
    th_id = 0;
    pthread_attr_init(&attr);
}

CThread::~CThread(void)
{
    if (th_id > 0) { ThDelete(); }
}

int CThread::ThCreate(void *(*ThreadPro)(void *), void *para)
{
    if (pthread_create(&th_id, &attr, ThreadPro, para) > 0) {
        PRINT_ERR_HEAD
        print_err("create thread error(%s)", strerror(errno));
        return -1;
    }

    if (pthread_detach(th_id) != 0) {
        PRINT_ERR_HEAD
        print_err("detach thread error(%s)", strerror(errno));
        return -1;
    }

    return 1;
}

int CThread::ThDelete(void)
{
    if (th_id > 0) {
        pthread_cancel(th_id);//发终止信号
        //pthread_join(th_id,&p_Return);
        //pthread_exit(p_Return);
    }

    th_id = 0;
    pthread_attr_init(&attr);
    return 1;
}
