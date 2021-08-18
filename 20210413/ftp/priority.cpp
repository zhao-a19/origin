/*******************************************************************************************
*文件:    priority.cpp
*描述:    优先级处理
*
*作者:    张昆鹏
*日期:    2017-06-15
*修改:    创建文件                           ------>  2017-06-15
*修改:    优化优先级处理                     ------>  2017-07-07
*
*******************************************************************************************/
#include "priority.h"
#include "debugout.h"


#define PRIORITYNUM    50
typedef struct _priority {
    pthread_t task_id;                    //线程号
    uint32 task_priority;                 //任务优先级
    uint32 packets;                       //数据包数量
    bool  enable;                         //数据包计数模式  true(计入分配计算中) false(不计入, 直接按优先级分包)
} PRIORITY;

typedef struct _prty {
    PRIORITY priority[PRIORITYNUM];        //优先级
    int32  taskcnt;                        //任务数量
} PRTY;

static PRTY prty;
static int32  off = 0;                    //0开启， 1开启，

static const struct {
    uint32 mode;                          //线程调度模式
    uint32 priority;                      //线程优先级大小
} thread_priority[] = {

    {SCHED_OTHER, 0},                     //默认模式
    {SCHED_FIFO, 5},
    {SCHED_FIFO, 35},
    {SCHED_FIFO, 65},
    {SCHED_FIFO, 95},
    {SCHED_RR, 5},
    {SCHED_RR, 35},
    {SCHED_RR, 65},
    {SCHED_RR, 95}
};

#define TESTOFF  (off==0)

/*******************************************************************************************
*功能:    检测序号是否合法
*参数:    cnt                      ---->  线程号
*         返回值                   ---->  不合法false
*
*注释:
*******************************************************************************************/
static bool priority_check_cnt(int32 cnt)
{
    if ((cnt < 0) || (cnt > PRIORITYNUM)) {              //检测索引号是否合法

        PRINT_ERR_HEAD;
        print_err("PRIORITY The serial number is not within the valid range(%d)!", cnt);
        return false;
    }

    return true;
}

/*******************************************************************************************
*功能:    查找和设置优先级属性
*参数:    enable                   ---->  是否计入分包计算中，true是， false不是
*         返回值                   ---->  查找失败-1   成功索引值
*
*注释:
*******************************************************************************************/
int32 priority_set(bool enable)
{
    if (TESTOFF) return -1;
    pthread_t id = pthread_self();
    int32 i = 0 ;
    int32 k = -1;
    for (i = 0; i <  prty.taskcnt; ++i) {
        if (id == prty.priority[i].task_id) {
            prty.priority[i].enable = enable;
            k = i;
            break;
        }
    }
    return k;
}

/*******************************************************************************************
*功能:    查找和设置优先级属性
*参数:     num                     ---->  优先级属性索引号
*         返回值                   ---->  -1失败   0成功
*
*注释:
*******************************************************************************************/
int32 _priority_set(int32 num)
{
    if (TESTOFF) return -1;
    if (!priority_check_cnt(num)) return -1;

    while ( prty.priority[num].packets == 0) usleep(10000);
    prty.priority[num].packets--;

    return 0;
}

/*******************************************************************************************
*功能:    设置优先级属性不计入分包计算中（自动按优先级分包）
*参数:     num                     ---->  优先级属性索引号
*         返回值                   ---->  -1失败   0成功
*
*注释:
*******************************************************************************************/
int32 priority_end_task(int32 num)
{
    if (TESTOFF) return -1;
    if (!priority_check_cnt(num)) return -1;
    prty.priority[num].enable = false;

    return 0;
}

/*******************************************************************************************
*功能:    优先级数据初始化
*参数:     cnt                  ---->  任务总数
*         返回值                ---->
*
*注释:
*******************************************************************************************/
void priority_init(int32 cnt)
{
    if (!priority_check_cnt(cnt)) {

        PRINT_ERR_HEAD;
        print_err("PRIORITY START FAILED (%d)", cnt);
    } else {
        off = 1;
        prty.taskcnt = cnt;
        for (int32 i = 0; i < prty.taskcnt; i++) {

            prty.priority[i].task_id = (pthread_t)0;
            prty.priority[i].task_priority = 0;
            prty.priority[i].packets = 0;
        }
    }
}

/*******************************************************************************************
*功能:    下载优先级部分数据初始化
*参数:     tid                  ---->  线程ID
*          level                ---->  优先级
*          返回值               ---->
*
*注释:
*******************************************************************************************/
void priority_task_init(pthread_t tid, int32 level)
{
    if (TESTOFF) return;
    for (int32 i = 0; i < prty.taskcnt; i++) {

        if (prty.priority[i].task_id == (pthread_t)0) {

            PRINT_DBG_HEAD;
            print_dbg("PRIORITY TID = %u, LEVEL =%d, PACK=%d", tid, level, prty.priority[i].packets);
            prty.priority[i].task_id = tid;
            if ((level < 0 ) || (level > 8)) prty.priority[i].task_priority = 0;        //优先级范围0-8
            else prty.priority[i].task_priority = (level < 5 ? level : (level - 4));
            prty.priority[i].packets = 0;
            break;
        }
    }
}

/*******************************************************************************************
*功能:     优先级处理逻辑
*参数:     返回值                   ---->
*
*注释:
*******************************************************************************************/
static void _priority_deal(void)
{
    /*通过对每个任务根据优先级进行不同数据包分配，下载时包总量递减，
      当各任务包数量之和为零时，重新分配包数量。*/

    int32 datanum = 0;
    for (int i = 0; i < prty.taskcnt; ++i) {
        if (prty.priority[i].enable)  datanum = datanum + prty.priority[i].packets;
    }
    if (datanum == 0) {
        for (int i = 0; i < prty.taskcnt; ++i) {

            if (prty.priority[i].task_id != (pthread_t)0) {    //检测任务是否还在进行

                //根据优先级分配包
                prty.priority[i].packets = (prty.priority[i].task_priority + 1) * 1000;
            }
        }
    }
}

/*******************************************************************************************
*功能:    下载优先级逻辑处理
*参数:    返回值               ---->
*
*注释:
*******************************************************************************************/
static void *priority_deal(void *arg)
{
    int32 k = 0;

    while (1) {
        _priority_deal();
        usleep(10000);

        k++;
        if (k == 10000) {
            for (int i = 0; i < prty.taskcnt; ++i) {
                PRINT_DBG_HEAD;
                print_dbg("PRIORITY TID = %u, level =%d, PACK=%d", prty.priority[i].task_id,
                          prty.priority[i].task_priority, prty.priority[i].packets);
            }
            k = 0;
        }
    }

    return NULL;
}

/*******************************************************************************************
*功能:    线程退出，数据包数量清零
*参数:    返回值               ---->
*
*注释:
*******************************************************************************************/
void priority_end(pthread_t tid)
{
    if (TESTOFF) return;
    for (int i = 0; i <  prty.taskcnt; ++i) {
        if (tid == prty.priority[i].task_id) {
            prty.priority[i].task_id = (pthread_t)0;
            prty.priority[i].packets = 0;
            break;
        }
    }
}

/*******************************************************************************************
*功能:    创建下载优先级处理线程
*参数:    返回值               ---->
*
*注释:
*******************************************************************************************/
void priority_createpthread(void)
{
    if (TESTOFF) return;
    pthread_t id;
    if (pthread_create(&id, NULL, priority_deal, NULL) != 0) {

        PRINT_ERR_HEAD;
        print_err("PRIORITY Usersrv client failed!");
    }
    usleep(10000);  //等待10ms，确保任务启动
}

/*******************************************************************************************
*功能:    创建线程优先级处理线程
*参数:    attr                    ----> 线程属性
*         level                   ----> 优先级
*         返回值                  ----> 0 改变线程属性，设置优先级
*
*注释:
*******************************************************************************************/
int32 priority_pthread(pthread_attr_t *attr, int32 level)
{
    //zkp 添加线程优先级设置
    struct sched_param param;
    int32 thread_policy;
    int32 status = -1;

    if (level != 0) {
        pthread_attr_init(attr);
        status = pthread_attr_setschedpolicy(attr, thread_priority[level].mode);
        if (status != 0) {
            PRINT_ERR_HEAD;
            print_err("Unable to set SCHED_FIFO policy");
        } else {

            param.sched_priority = thread_priority[level].priority;
            pthread_attr_setschedparam(attr, &param);
            pthread_attr_setinheritsched(attr, PTHREAD_EXPLICIT_SCHED);
        }
    }

    //输出线程属性情况
    pthread_attr_getschedparam(attr, &param);
    pthread_attr_getschedpolicy(attr, &thread_policy);
    PRINT_DBG_HEAD;
    print_dbg("TASK PID = 0x%x, Default policy is %s, priority is %d\n", (uint32)getpid(),
              (thread_policy == SCHED_FIFO ? "FIFO" : (thread_policy == SCHED_RR ? "RR" :
                      (thread_policy == SCHED_OTHER ? "OTHER" : "unknown"))), param.sched_priority);

    return status;
}