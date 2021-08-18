/*******************************************************************************************
*文件:    sysfastq.cpp
*描述:    异步队列以及hash的基础操作
*
*作者:    金美忠
*日期:    2018-12-18
*修改:    创建文件                ------>     2018-12-18
*         队列的收发处理       ------>       2018-12-19
*         重写suwrite,以及分发处理           ------>      2018-12-20
*         丢包处理,任务重建机制              ------>    2018-12-21
*         保证数据内存只有一份，增加释放数据接口   ----->  2019-01-03
*         修复数据分发线程崩溃的bug                -----> 2019-01-27
*         修复清除当前包的前1000包，清除掉当前包的bug                -----> 2019-01-28
*         可以设置线程名称                                         -----> 2021-02-23
*******************************************************************************************/

#include "sysfastq.h"
#include "debugout.h"
#include <errno.h>
#include <sys/time.h>
#include "msgcfg.h"
#include "sysfastq_s.h"

#define log_error(s)    {PRINT_ERR_HEAD; print_err(s);}
#define assert(t)       ((t) ? false : true)
#define TYPE_RING_Q     1
#define TYPE_CONNECT_Q  2
#define TEMP_PKG_SIZE 100
#define NO_DATAS_TO_CREATE_TASK 200
#define RING_Q_IDLE_WAIT_TIME   20

#define CREATE_THREAD_FLAG      1

typedef struct create_flag {
    uint8   thread_flag; //线程标志; 1表示已开辟线程； 0表示未开辟
    uint32  pkg_cnt;    //包统计，现在暂定为200个开辟线程；
} CREATE_FLAG;


/**********************************************************
*异步队列相关操作
*
* *********************************************************/

static int ring_queue_push(ring_queue_t *q, void *data)
{

    if (q->size > 0 && g_async_queue_length(q->queue) >= q->size - 1) {
        return -1;
    }
    g_async_queue_push(q->queue, data);

    return 0;
}

static void *ring_queue_pop(ring_queue_t *q)
{
    return g_async_queue_try_pop(q->queue);
}

static int ring_queue_len(ring_queue_t *q)
{
    return g_async_queue_length(q->queue);
}

static void ring_queue_destroy(ring_queue_t *q)
{

    g_async_queue_unref(q->queue);
    free(q);
}


ring_queue_t *ring_queue_init(int size)
{
    ring_queue_t *q = (ring_queue_t *)calloc(sizeof(ring_queue_t), 1);

    if (q == NULL) {
        PRINT_ERR_HEAD;
        print_err("malloc ring queue falied");
        return NULL;
    }

    q->queue = g_async_queue_new();

    q->size = size;

    q->push = ring_queue_push;
    q->pop = ring_queue_pop;
    q->len = ring_queue_len;
    q->destroy = ring_queue_destroy;

    return q;
}


/*********************************************
*哈希表相关操作
*
* *******************************************/
static void *hashtable_get(hashtable_t *self, uint64 key)
{
    char key_str[128];
    memset(key_str, 0, sizeof(key_str));
    sprintf(key_str, "%llu", key);
    pthread_mutex_lock(&self->lock);
    void *ret = g_hash_table_lookup(self->ht, key_str);
    pthread_mutex_unlock(&self->lock);
    return ret;
}

static int hashtable_is_in(hashtable_t *self, uint64 key)
{
    return hashtable_get(self, key) != NULL;
}

static void *hashtable_insert(hashtable_t *self, uint64 key, void *value)
{
    char  *k = (char *)malloc(128);
    memset(k, 0, 128);

    sprintf(k, "%llu", key);

    void *ret = hashtable_get(self, key);
    pthread_mutex_lock(&self->lock);
    g_hash_table_insert(self->ht, k, value);
    pthread_mutex_unlock(&self->lock);
    return ret;
}


static gboolean node_free(gpointer key, gpointer value, gpointer user_data)
{
    (void)key; (void)user_data;
    free(value);
    return 1;
}

static void hashtable_destroy(hashtable_t *self)
{
    g_hash_table_foreach_remove(self->ht, node_free, NULL);
    g_hash_table_destroy(self->ht);
    free(self);
}

static void *hashtable_pop(hashtable_t *self, uint64 key)
{

    void *ret = hashtable_get(self, key);
    if (ret != NULL) {
        char key_str[128];
        memset(key_str, 0, sizeof(key_str));
        sprintf(key_str, "%llu", key);
        pthread_mutex_lock(&self->lock);
        g_hash_table_remove(self->ht, key_str);
        pthread_mutex_unlock(&self->lock);
    }
    return ret;
}

static inline int hashtable_len(hashtable_t *self)
{
    int ret = 0;
    pthread_mutex_lock(&self->lock);
    ret = g_hash_table_size(self->ht);
    pthread_mutex_unlock(&self->lock);
    return ret;
}

//static void get_distribute_attr(void * data, pkg_t * pkg, uint32 size);

hashtable_t *hashtable_init_glib(uint32 size)
{

    if (assert((size & (size - 1)) == 0))
        return NULL;

    hashtable_t *self = (hashtable_t *)calloc(sizeof(hashtable_t), 1);

    if (self == NULL) {
        log_error("malloc failed for hashtable new");
        return NULL;
    }

    pthread_mutex_init(&(self->lock), NULL);

    self->ht = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
    //self->ht = g_hash_table_new(g_int_hash, g_int_equal);

    self->insert = hashtable_insert;
    self->get = hashtable_get;
    self->pop = hashtable_pop;
    self->destroy = hashtable_destroy;
    self->is_in = hashtable_is_in;
    self->len = hashtable_len;

    return self;
}

/**************************************************************************
* fastq相关操作
*
***************************************************************************/

inline static void _writedly_(int32 delayus)
{
    delayus &= 0xFFFF;
    if (delayus != 0) {
        struct timeval t1, t2;
        gettimeofday (&t1, NULL);
        do {
            gettimeofday (&t2, NULL);
        } while (((t2.tv_sec - t1.tv_sec) * 1000000 + t2.tv_usec - t1.tv_usec) < delayus);
    }
}


/*************************************************
*数据入队处理
*
*
* ************************************************/
/**
 * [get_distribute_attr 添加、获得分发属性]
 * @param data [in--数据]
 * @param size [in--数据长度]
 * @param pkg  [out--数据包]
 */
static void get_distribute_attr(void *data, uint32 size, pkg_t *pkg)
{
    psusocketdata packet = (psusocketdata) data;

    pkg->head_attr.taskid = packet->taskid_connect;
    pkg->head_attr.pkg_num = packet->pkg_num;
    pkg->head_attr.pkg_ctl = packet->data.ctrl;

    memcpy(pkg->m_body_data, (puint8)data, size);
}


/**
 * [_effqueuefunc_ 数据入队]
 * @param  arg [description]
 * @return     [description]
 */
void *_effqueuefunc_(void *arg)
{
    pthread_setself("effqueuefunc");

    CSUSOCKET_FASTQ *self = (CSUSOCKET_FASTQ *)arg;

    SUQUEUE packet;
    PRINT_INFO_HEAD;
    print_info("start _effqueue task !!!");

    ring_queue_t *ring_queue_temp = NULL;

    ring_queue_temp = self->get_ring_q(TYPE_RING_Q);
    if (ring_queue_temp == NULL) {
        PRINT_ERR_HEAD;
        print_err("get ring_q point error");
    }


#ifndef __CYGWIN__
    //CPU绑定
    {
        self->setcpu();
    }
#endif
    int32 i;
    while (1) {
        i = -1;
        if ((i = self->readsocket(packet.mdata, sizeof(packet.mdata))) > 0) {
            pkg_t *pkg = (pkg_t *)malloc(sizeof(pkg_t));
            if (pkg == NULL) {
                PRINT_ERR_HEAD;
                print_err("malloc pkg_t falied ");
            }
            memset(pkg, 0, sizeof(pkg_t));
            pkg->head_attr.pkg_length = i;
            get_distribute_attr(packet.mdata, i, pkg);

            if (ring_queue_temp->push(ring_queue_temp, (void *)pkg) < 0) {
                PRINT_ERR_HEAD;
                print_err("ring queue push falied ");
                free(pkg);
            } else {
#if __DEBUG_MORE__
                PRINT_DBG_HEAD;
                print_dbg("RING_Q: push a pkg, taskid:pkg_no:pkg_ctl = %d:%llu:0x%X", pkg->head_attr.taskid
                          , pkg->head_attr.pkg_num, pkg->head_attr.pkg_ctl);
#endif
            }

        }
    }

    PRINT_ERR_HEAD;
    print_err("_effqueue thread exit");
}


/*************************************************
*分发数据处理
*
*
* ************************************************/

/**
 * [init_task 申请单个任务空间]
 * @return [任务指针]
 */
static su_task_t *init_task()
{
    su_task_t *task = (su_task_t *)calloc(1, sizeof(su_task_t));
    if (task == NULL) {
        PRINT_ERR_HEAD;
        print_err("malloc task failed");
    } else {
        memset(task, 0, sizeof(su_task_t));
    }
    return task;
}


/**
 * [check_pkg 简单判断起始包]  todo--要判断数据包的断线重连，不能简单判断数据包号
 * @param  pkg [数据包]
 * @return     [true： 检验通过]
 */
static bool check_pkg(pkg_t *pkg)
{
    //todo打印日志
    bool ret = true;
    if (pkg->head_attr.pkg_num == 1 ) {
        ret = true;
    }
    return ret;
}

/**
 * [insert_task 将任务插入到任务hash]
 * @param  task_dict     [任务hash]
 * @param  temp_pkg_dict [临时包缓冲hash]
 * @param  pkg           [数据包]
 * @return               [description]
 */
static int insert_task(hashtable_t *task_dict, hashtable_t *temp_pkg_dict, pkg_t *pkg)
{
    su_task_t *task = init_task();

    PRINT_DBG_HEAD;
    print_dbg("insert_task: task start , task addr = %p", task);

    ///验证包正确性
    if (!check_pkg(pkg)) {
        PRINT_ERR_HEAD;
        print_err("check_pkg error");
        free(task);
        return -1;
    }

    task->curr_pkg_no = pkg->head_attr.pkg_num;
    gettimeofday(&(task->timestamp), NULL);
    task->status = pkg->head_attr.pkg_ctl;


    //将temp_pkg_dict里的先来的包，也放进新建的任务列表里
    hashtable_t *pkg_hash = (hashtable_t *)temp_pkg_dict->pop(temp_pkg_dict, pkg->head_attr.taskid);
    PRINT_DBG_HEAD;
    print_dbg("insert_task: pkg_hash start");
    if (pkg_hash == NULL) {
        pkg_hash = hashtable_init_glib(4096);
        if (pkg_hash == NULL) {
            PRINT_ERR_HEAD
            print_err("new dict failed, %s", strerror(errno));
            free(task);
            return -1;
        }
        pkg_hash->insert(pkg_hash, pkg->head_attr.pkg_num, pkg);

    }
    task->pkg_hash = pkg_hash;
    PRINT_DBG_HEAD;
    print_dbg("insert_task: pkg_hash end, pkg_hash addr = %p", task->pkg_hash);

#if __DEBUG_MORE__
    PRINT_DBG_HEAD;
    print_dbg("task_dict: push a task, task addr = %p, key:curr_no = %d:%llu",
              task, pkg->head_attr.taskid, task->curr_pkg_no);
#endif

    task_dict->insert(task_dict, pkg->head_attr.taskid, task);

    return 0;
}


/**
 * [insert_pkg 数据插入到任务的pkg_hash里]
 * @param  task_dict     [任务hash]
 * @param  temp_pkg_dict [临时包hash]
 * @param  pkg_temp      [数据包]
 * @return               [NULL:插入成功; !NULL:重复包]
 */
static void *insert_pkg(hashtable_t *task_dict, hashtable_t *temp_pkg_dict, pkg_t *pkg)
{
    su_task_t *task = (su_task_t *)task_dict->get(task_dict, pkg->head_attr.taskid);

    if (task) {
        if (!task->pkg_hash->is_in(task->pkg_hash, pkg->head_attr.pkg_num)
            && (pkg->head_attr.pkg_num > task->curr_pkg_no)) {

#if __DEBUG_MORE__
            PRINT_DBG_HEAD;
            print_dbg("insert_pkg taskid = %d, dict_len = %d, task addr = %p, pkg addr = %p, pkg_hash addr = %p, pkg_num = %llu, pkg_hash_len = %d,", pkg->head_attr.taskid, task_dict->len(task_dict),
                      task, pkg, task->pkg_hash, pkg->head_attr.pkg_num, task->pkg_hash->len(task->pkg_hash));
#endif
            task->curr_pkg_no = pkg->head_attr.pkg_num;
            pkg = (pkg_t *)task->pkg_hash->insert(task->pkg_hash, pkg->head_attr.pkg_num, pkg);
        }
    } else {
        // 如果数据包早于任务起始包来到，则把数据包扔到临时的数据缓存区中，但只缓存100个数据包
        hashtable_t *pkg_dict = (hashtable_t *)temp_pkg_dict->get(temp_pkg_dict, pkg->head_attr.taskid);
        if (pkg_dict == NULL) {
            pkg_dict = hashtable_init_glib(4096);
            if (pkg_dict == NULL) {
                PRINT_ERR_HEAD
                print_err("new dict failed, %s", strerror(errno));
            } else {
                if (!temp_pkg_dict->is_in(temp_pkg_dict, pkg->head_attr.taskid)) {
                    temp_pkg_dict->insert(temp_pkg_dict, pkg->head_attr.taskid, pkg_dict);
                }
            }
        }
        if ( pkg_dict != NULL && pkg_dict->len(pkg_dict) < TEMP_PKG_SIZE
             && !pkg_dict->is_in(pkg_dict, pkg->head_attr.pkg_num)) {

            pkg = (pkg_t *)pkg_dict->insert(pkg_dict, pkg->head_attr.pkg_num, pkg);
        }
    }

    // 此时pkg大部分情况下都为NULL，如果不为NULL，则为重复的数据包
    return pkg;
}

/**
 * [distribute_data 分发数据处理]
 * @param  arg [description]
 * @return     [description]
 */
void *distribute_data(void *arg)
{
    pthread_setself("distribdata");
    CSUSOCKET_FASTQ *self = (CSUSOCKET_FASTQ *)arg;

    pkg_t *pkg;
    hashtable_t *task_dict = self->get_hash();
    hashtable_t *temp_pkg_dict = self->init_hash();
    ring_queue_t *fastq = self->get_ring_q(TYPE_RING_Q);
    ring_queue_t *connectq = self->get_ring_q(TYPE_CONNECT_Q);
    int32 *ptaskid;

    while (1) {
        //1. 出队
        pkg = (pkg_t *)fastq->pop(fastq);

        if ((pkg == NULL)) {
            usleep(RING_Q_IDLE_WAIT_TIME); //设置时间
            continue;
        }
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("RING_Q: pop a pkg,  taskid:pkg_no:pkg_ctl  %d:%llu:0x%X", pkg->head_attr.taskid
                  , pkg->head_attr.pkg_num, pkg->head_attr.pkg_ctl);
#endif
        //2. 分发数据
        switch (pkg->head_attr.pkg_ctl) {
        case DATA_S:
_create_task:
            if (!task_dict->is_in(task_dict, pkg->head_attr.taskid)) {
                insert_task(task_dict, temp_pkg_dict, pkg);

                self->set_task_flag(pkg);

                ptaskid = (int32 *)malloc(sizeof(int32));
                *ptaskid = pkg->head_attr.taskid;
                connectq->push(connectq, (void *)ptaskid);
            } else {
#if __DEBUG_MORE__
                PRINT_DBG_HEAD;
                print_dbg("distribute_data:level->task repeat pkg, pkg_ctl = 0x%X, pkg_no = %llu, free pkg pkg_addr = %p",
                          pkg->head_attr.pkg_ctl, pkg->head_attr.pkg_num, pkg);
#endif
                free(pkg);
            }
            break;
        default:

            //创建任务当100个包没收到起任务
            if (self->taskid_of_pkgcnt(pkg)) {
                goto _create_task;
            }
            ///usleep(TASK_IDLE_SLEEP_200US);
            // 其余事件都交给任务自行处理
            pkg = (pkg_t *)insert_pkg(task_dict, temp_pkg_dict, pkg);
            if (pkg != NULL) {
#if __DEBUG_MORE__
                PRINT_DBG_HEAD;
                print_dbg("distribute_data:level->pkg repeat pkg, pkg_ctl = 0x%X, pkg_no = %llu, free pkg pkg_addr = %p",
                          pkg->head_attr.pkg_ctl, pkg->head_attr.pkg_num, pkg);
#endif
                free(pkg);
            }
            break;
        }
    }
}

/*************************************************
*CSUSOCKET_FASTQ的实现
*
*
* ************************************************/

CSUSOCKET_FASTQ::CSUSOCKET_FASTQ()
{
    init();
}

CSUSOCKET_FASTQ::CSUSOCKET_FASTQ(const pchar ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp)
    : CSUSOCKET(ip, port, srv_client, tcp_udp)
{

    init();
}

CSUSOCKET_FASTQ::CSUSOCKET_FASTQ(CSUSOCKET_FASTQ &obj): CSUSOCKET(obj)
{
    init();
}

/**
 * [CSUSOCKET_FASTQ::init 初始化]
 */
void CSUSOCKET_FASTQ::init()
{
    //对g_thread_init()判断，有且只能初始化一次， 请调用的时候，放到main函数
    // if (!g_thread_supported())
    //     g_thread_init(NULL);
    m_fastq =  init_ringq();
    m_taskhash  = init_hash();
    m_connect_q = init_ringq();

    m_pkgcnt = init_hash();

}

/**
 * [CSUSOCKET_FASTQ::init_ringq 初始化队列]
 * @return [队列指针]
 */
ring_queue_t *CSUSOCKET_FASTQ::init_ringq(void)
{
    return ring_queue_init(RING_QUEUE_SIZE); //ring_queue_size 可调
}

/**
 * [CSUSOCKET_FASTQ::init_hash 初始化hash]
 * @return [hash指针]
 */
hashtable_t *CSUSOCKET_FASTQ::init_hash(void)
{
    return hashtable_init_glib(256);
}

/**
 * [CSUSOCKET_FASTQ::gettaskfromtaskdict 从任务hash中获取任务]
 * @param  taskid [任务关键字]
 * @return        [任务]
 */
su_task_t *CSUSOCKET_FASTQ::gettaskfromtaskdict(int32 taskid)
{
    su_task_t *ret = NULL;
    if (m_taskhash->len(m_taskhash) > 0) {
        ret = (su_task_t *)m_taskhash->get(m_taskhash, taskid);
        if (ret == NULL) {
            PRINT_ERR_HEAD;
            print_err("get task failed, taskid = %d, taskhash len = %d", taskid, m_taskhash->len(m_taskhash));
        }
    }
    return ret;
}

/**
 * [CSUSOCKET_FASTQ::gettaskcurrno 获取当前任务的最新包号]
 * @param  taskid [任务关键字]
 * @return        [包号]
 */
uint64 CSUSOCKET_FASTQ::gettaskcurrno(int32 taskid)
{
    uint64 ret = 0;
    su_task_t *task = gettaskfromtaskdict(taskid);
    if (task == NULL) {
        PRINT_ERR_HEAD;
        print_err("get task error");
        return ret;
    }

    return task->curr_pkg_no;
}

/**
 * 任务状态, 异常；未找到；丢包；空闲；正常 todo与srvqueue共用
 */
enum {
    TASK_ERR_ABNORMAL = -1, //负值
    TASK_ERR_NOFIND = -2,
    TASK_ERR_PKGLOSS = -3,

    TASK_IDLE = 1, //正常空，异常空
    TASK_NORMAL,
};

/**
 * [CSUSOCKET_FASTQ::delnousepkg 删除pkghash里没用的数据包]
 * @param  task_id [任务关键字]
 * @param  del_s   [删除的起点关键字]
 * @param  del_e   [删除的终点关键字]
 * @return         [description]
 */
int32 CSUSOCKET_FASTQ::delnousepkg(int32 task_id, uint64 del_s, uint64 del_e)
{
    uint64 i;
    pkg_t *pkg;
    su_task_t *task = gettaskfromtaskdict(task_id);
    if (task == NULL) {
        PRINT_ERR_HEAD;
        print_err("get task error");
        return -1;
    }
    for (i = del_s; i < del_e; i++) {
        pkg = (pkg_t *)task->pkg_hash->pop(task->pkg_hash, i);
        if (pkg != NULL) {
#if __DEBUG_MORE__
            PRINT_DBG_HEAD;
            print_dbg("nouse pkg delete, taskid = %d, pkg_no = %llu", pkg->head_attr.taskid
                      , pkg->head_attr.pkg_num);
#endif
            free(pkg);
        }
    }
    return 0;
}

/**
 * [CSUSOCKET_FASTQ::deltask 删除任务]
 * @param  task_id [任务关键字]
 * @return         [description]
 */
int32 CSUSOCKET_FASTQ::deltask(int32 task_id)
{
    su_task_t *task = (su_task_t *)m_taskhash->pop(m_taskhash, task_id);
    if (task == NULL) {
        PRINT_ERR_HEAD;
        print_err("pop task error, free failed");
        return -1;
    }
#if __DEBUG_MORE__
    PRINT_DBG_HEAD;
    print_dbg("task_dict: delete task, taskid = %d, pkg_no = %llu, task addr = %p", task_id, task->curr_pkg_no, task);
#endif
    task->pkg_hash->destroy(task->pkg_hash);
    free(task);
    return 0;
}

/**
 * [CSUSOCKET_FASTQ::set_task_flag 设置任务状态]
 * @param  pkg [数据包]
 * @return     [description]
 */
void CSUSOCKET_FASTQ::set_task_flag(pkg_t *pkg)
{
    CREATE_FLAG *c_flag_tmp  = (CREATE_FLAG *)m_pkgcnt->get(m_pkgcnt, pkg->head_attr.taskid);
    if (c_flag_tmp != NULL) {
        c_flag_tmp->thread_flag = CREATE_THREAD_FLAG;
    } else {
        c_flag_tmp = (CREATE_FLAG *) calloc(1, sizeof(CREATE_FLAG));
        c_flag_tmp->thread_flag = CREATE_THREAD_FLAG;
        m_pkgcnt->insert(m_pkgcnt, pkg->head_attr.taskid, (void *)c_flag_tmp);
    }
}

/**
 * [CSUSOCKET_FASTQ::taskid_of_pkgcnt 是否开辟任务]
 * @param  pkg [数据包]
 * @return     [true： 开辟任务]
 */
bool CSUSOCKET_FASTQ::taskid_of_pkgcnt(pkg_t *pkg)
{
    uint16 temp;
    CREATE_FLAG *c_flag_tmp = (CREATE_FLAG *)m_pkgcnt->get(m_pkgcnt, pkg->head_attr.taskid);
    if (c_flag_tmp != NULL) {
        //判断是否已开辟任务
        if (c_flag_tmp->thread_flag == CREATE_THREAD_FLAG) {
            return false;
        }

#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("taskid_of_pkgcnt , flag = %d, %d:%d", c_flag_tmp->thread_flag, pkg->head_attr.taskid
                  , c_flag_tmp->pkg_cnt);
#endif
        //包号加1
        c_flag_tmp->pkg_cnt++;
        if (c_flag_tmp->pkg_cnt >= NO_DATAS_TO_CREATE_TASK) {
            PRINT_DBG_HEAD;
            print_dbg("reconnect, will create connect thread, task_id = %d", pkg->head_attr.taskid); //重连信息打印
            return true;
        }

    } else {
        c_flag_tmp = (CREATE_FLAG *) calloc(1, sizeof(CREATE_FLAG));
        c_flag_tmp->pkg_cnt = 1;
        m_pkgcnt->insert(m_pkgcnt, pkg->head_attr.taskid, (void *)c_flag_tmp);
    }
    return false;
}

/**
 * [CSUSOCKET_FASTQ::filllosebuf 在丢包的时候填充缓冲区]
 * @param  task_id      [任务ID]
 * @param  curr_pkg_no  [外部包号]
 * @param  back_pkg_no  [当前任务的包号]
 * @param  size         [缓冲区大小]
 * @param  pkg_loss_buf [缓冲区]
 * @return              [存进缓冲区的个数]
 */
int32 CSUSOCKET_FASTQ::filllosebuf(int32 task_id, uint64 curr_pkg_no, uint64 back_pkg_no, int32 size, uint64 *pkg_loss_buf)
{
    pkg_t *pkg;
    //1.获取任务
    su_task_t *task = gettaskfromtaskdict(task_id);

    uint64 dev_pkg = back_pkg_no - curr_pkg_no + 1, i;


    int32 sus_cout = 0;   //查找成功计数

    for (i = 0 ; i < dev_pkg; i++) {
        if ((pkg = (pkg_t *)task->pkg_hash->get(task->pkg_hash, curr_pkg_no)) != NULL) {
            pkg_loss_buf[sus_cout] = curr_pkg_no;
            sus_cout++;
#if __DEBUG_MORE__
            PRINT_DBG_HEAD;
            print_dbg("filllosebuf , sus_cout = %d, curr_pkg_no = %llu", sus_cout, curr_pkg_no);
#endif
            if (sus_cout == size) {
                break;
            }
        } else {
#if __DEBUG_MORE__
            PRINT_DBG_HEAD;
            print_dbg("filllosebuf , loss pkg_no = %llu, dev_pkg = %llu", curr_pkg_no, dev_pkg);
#endif
        }
        curr_pkg_no++;
    }

    return sus_cout;
}

/**
 * [CSUSOCKET_FASTQ::getdatabyid 获取数据]
 * @param  task_id    [任务关键字]
 * @param  pkg_no     [外部的包号]
 * @param  data       [out--数据]
 * @param  ret_pkg_no [异常情况下返回当前任务的包号]
 * @return            [任务状态]
 */
int32 CSUSOCKET_FASTQ::getdatabyid(int32 task_id, uint64 pkg_no, pkg_t **data, uint64 &ret_pkg_no)
{
    int32 ret = TASK_ERR_ABNORMAL;
    pkg_t *pkg;
    //1.获取任务
    su_task_t *task = gettaskfromtaskdict(task_id);
    if (task == NULL) {
        return TASK_ERR_NOFIND;
    }
    //2.根据任务的curr_no取得数据
    pkg = (pkg_t *)task->pkg_hash->pop(task->pkg_hash, pkg_no);
    if (pkg != NULL) {

#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("get data task_id = %d, pkg_no = %llu task addr = %p, pkg_hash = %p", task_id, pkg_no, task, task->pkg_hash);
#endif
        //所有内存留一份
        *data = pkg;
        ret = TASK_NORMAL;
    } else {

        if (task->pkg_hash->len(task->pkg_hash) == 0) {
            return TASK_IDLE;
        }
        //获取当前的任务队列记录的curr_no
        uint64 curr_pkg_no = gettaskcurrno(task_id);
        if (pkg_no == (curr_pkg_no + 1)) {
            return TASK_IDLE; //空闲
        }

        PRINT_DBG_HEAD;
        print_dbg("don't find pkg, taskid = %d, pkg_no = %llu, task cur_pkg_no = %llu", task_id, pkg_no, curr_pkg_no);

        ret_pkg_no = curr_pkg_no;
        ret = TASK_ERR_PKGLOSS; //丢包
    }
    return ret;
}

void CSUSOCKET_FASTQ::pkg_free(pkg_t *pkg)
{
    if ( pkg != NULL) {
        free(pkg);
    }
}

CSUSOCKET_FASTQ::~CSUSOCKET_FASTQ()
{
    if (m_fastq != NULL)
        free(m_fastq);
    if (m_taskhash != NULL)
        free(m_taskhash);
    if (m_connect_q != NULL)
        free(m_connect_q);

    if (m_pkgcnt != NULL)
        free(m_pkgcnt);
}


/**
 * [CSUSOCKET_FASTQ::sustart 创建快速入Q线程]
 * @return  [true:成功]
 */
bool CSUSOCKET_FASTQ::sustart(void)
{
    if ((getsocket() != SOCKET_ERR) && (m_type == SOCKET_UDP)) {

        pthread_t tid;
        pthread_attr_t attr;
        struct sched_param sch;

        //设置优先级
        pthread_attr_init(&attr);
        sch.sched_priority = 80;
        pthread_attr_setschedpolicy(&attr, SCHED_RR) ;
        pthread_attr_setschedparam(&attr, &sch) ;
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) ;       //要使优先级其作用必须要有这句话

        if (pthread_create(&tid, NULL/*&attr*/, _effqueuefunc_, (void *)this) != 0) {
            PRINT_ERR_HEAD;
            print_err("create efficient queue thread failed!");
            return false;
        }

        usleep(10000);
        return true;
    }

    return false;
}

/**
 * [CSUSOCKET_FASTQ::sureadq 创建分发任务线程]
 * @return  [true： 成功]
 */
bool CSUSOCKET_FASTQ::sureadq(void)
{
    //数据合并
    pthread_t tid;
    pthread_attr_t attr;
    struct sched_param sch;

    if (pthread_create(&tid, NULL/*&attr*/, distribute_data, (void *)this) != 0) {
        PRINT_ERR_HEAD;
        print_err("create distribute_data thread  failed!");
        return false;
    }
    return true;
}

/**
 * [CSUSOCKET_FASTQ::sureadq_connect 获取连接Q的连接号]
 * @return  [连接号]
 */
int32 CSUSOCKET_FASTQ::sureadq_connect(void)
{
    int32 ret = -1;

    int32 *taskid_temp = (int32 *)m_connect_q->pop(m_connect_q);

    if (taskid_temp == NULL)
        return ret;

    ret = *taskid_temp;
    PRINT_DBG_HEAD;
    print_dbg("connectq pop taskid, taskid = %d", ret);

    free(taskid_temp);
    return ret;
}


/**
 * [CSUSOCKET_FASTQ::suwrite 数据摆渡发送]
 * @param  data [发送数据]
 * @param  size [数据长度]
 * @return      [description]
 */
int32 CSUSOCKET_FASTQ::suwrite(const void *data, int32 size)
{
    if ((data == NULL) && (size <= 0))  return -1;

    bool berr = true;
    int32 datapos = 0;

    int32 delayus = getdelayus();
    uint8 repeat = getrepeat();

    if ((getsocket() != SOCKET_ERR) && (m_type == SOCKET_UDP)) {
        //延时策略开关
        if ((delayus & 0x10000) == 0) {
            for (uint8 i = 0; i < repeat; i++) {
                if ((i & 1) == 1)   _writedly_(delayus);       //测试用
                berr &= ((datapos = writesocket(data, size)) != size);
            }
            _writedly_(delayus);        //测试用

            PRINT_DBG_HEAD;
            print_dbg("DELAY1 %d", delayus & 0xFFFF);
        }

        if (berr) {

            PRINT_ERR_HEAD;
            print_err("write data size = %d", datapos);
            return -1;
        }

        PRINT_DBG_HEAD;
        print_dbg("write data %d = %d", size, datapos);

        return size;
    }

    return -1;
}



/**
 * [CSUSOCKET_FASTQ::get_ring_q 获取Q]
 * @param  qtype [Q的类型]
 * @return       [Q]
 */
ring_queue_t *CSUSOCKET_FASTQ::get_ring_q(uint8 qtype)
{
    if (qtype == TYPE_RING_Q)
        return m_fastq;
    else if (qtype == TYPE_CONNECT_Q)
        return m_connect_q;
}

/**
 * [CSUSOCKET_FASTQ::get_hash 获取任务hash]
 * @return [任务hash]
 */
hashtable_t *CSUSOCKET_FASTQ::get_hash(void)
{
    return m_taskhash;
}

