/*******************************************************************************************
*文件:    sysfastq.h
*描述:    异步队列封装以及hash接口封装
*
*作者:    金美忠
*日期:    2018-12-18
*修改:    创建文件                            ------>     2018-12-18
*         将map替换为hash                       ----->      2018-12-29
*
*
*******************************************************************************************/
#ifndef _SYSFASTQ_H
#define _SYSFASTQ_H

#include <glib.h>
#include "datatype.h"
#include "syssocket.h"
#include <pthread.h>

#define RING_QUEUE_SIZE          100000

#define PACKETSIZE              (7 * 1024)

//宏开关
#define _FAST_QUEUE_SWITCH_ 1

// 循环FIFO队列
typedef struct ring_queue_t ring_queue_t;
typedef struct ring_queue_t {
    int size;                   // 循环队列元素个数
    pthread_mutex_t lock;       // 锁
    int flag;                   // 标志
    volatile int readp;         // 已读指针
    volatile int writep;        // 可写指针
    void **ring;                // 循环队列区，每个元素是一个void *类型的指针
    GAsyncQueue *queue;

    /**
     * 向队列push一个数据
     * @param q     队列对象
     * @param data  数据
     * @return      返回-1 表示队列满，返回0表示push成功
     */
    int (*push)(ring_queue_t *q, void *data);

    /**
     * 从队列弹出一个元素
     * 当push的对象本身为NULL时，此时返回的也为NULL。如果出现这种情况，由调用者负责。
     * @param q     队列对象
     * @return      返回弹出的元素，NULL表示队列空。
     */
    void * (*pop)(ring_queue_t *q);

    /**
     * 返回队列深度
     * @param q     队列对象
     * @return      队列深度
     */
    int (*len)(ring_queue_t *q);

    /**
     * 释放队列
     * 不负责free队列元素指向的指针
     * @param q
     */
    void (*destroy)(ring_queue_t *q);

} ring_queue_t;

/**
 * 申请一个循环队列
 * @param size      循环队列元素个数, 有效个数等于size-1。如果值小于1表示不限制q大小。
 * @return          返回循环队列对象，NULL表示申请失败
 */
ring_queue_t * ring_queue_init(int size);

/*************************************************
* 哈希表的相关实现
* ************************************************/
enum {
    DICT_WITH_LOCK          = 1 << 0,       // 字典启用互斥锁，创建字典时设置此选项则可以保证线程安全

    HASHTABLE_KEY_NORMAL    = 1 << 1,       // 直接取余法
    HASHTABLE_KEY_RAND      = 1 << 2,       // 平方取中发
};

typedef struct hashtable_t hashtable_t;
typedef struct hashtable_t {

    GHashTable *ht;
    pthread_mutex_t lock;       // 锁

    void *(*insert)(hashtable_t *ht, uint64  key, void *value);
    void *(*get)(hashtable_t *ht, uint64 key);
    void *(*pop)(hashtable_t *ht, uint64 key);
    void (*destroy)(hashtable_t *ht);
    int (*is_in)(hashtable_t *ht, uint64 key);
    int (*len)(hashtable_t *ht);
} hashtable_t;

/**
 * glib版封装的hashtable_init, 速度慢30%，估计是因为key的原因，64位的key每次insert都涉及到malloc空间
 * @param size
 * @return
 */
hashtable_t *hashtable_init_glib(uint32 size);


typedef struct {
    uint32 taskid;
    uint8 pkg_ctl;
    uint64 pkg_num;
    struct timeval timestamp;
    uint16 pkg_length;
} add_head, *padd_head;

typedef struct {
    add_head head_attr;
    uint8 m_body_data[PACKETSIZE];
} pkg_t;

typedef struct su_task_t {
    hashtable_t * pkg_hash;
    uint64 curr_pkg_no;
    uint64 insert_pkg_no;   //插入哈希记录的一个包号
    struct timeval timestamp;
    uint32 timeout_ms;
    uint8 status;
    //task_user_data_t  *user_data;
} su_task_t;


class CSUSOCKET_FASTQ : public CSUSOCKET
{
public:
    CSUSOCKET_FASTQ();
    CSUSOCKET_FASTQ(const pchar ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp);
    CSUSOCKET_FASTQ(CSUSOCKET_FASTQ &obj);
    virtual ~CSUSOCKET_FASTQ();

    //int32 suwrite(const void *data, int32 size, void * add_pkg_head);
    bool sustart(void);      //数据入队列
    bool sureadq(void);         //读Q,组合数据并且分发数据

    int32 sureadq_connect(void); //连接队列，用于开辟线程

    int32 suwrite(const void *data, int32 size); //直接发送

    int32 getdatabyid(int32 task_id, uint64 pkg_no, pkg_t **data, uint64 &ret_pkg_no);
    int32 filllosebuf(int32 task_id, uint64 curr_pkg_no, uint64 back_pkg_no, int32 size, uint64 *pkg_loss_buf);
    int32 delnousepkg(int32 task_id, uint64 del_s, uint64 del_e);
    uint64 gettaskcurrno(int32 taskid);
    su_task_t *  gettaskfromtaskdict(int32 taskid);
    int32 deltask(int32 task_id);
    bool taskid_of_pkgcnt(pkg_t *pkg);
    void set_task_flag(pkg_t *pkg);
    void pkg_free(pkg_t * pkg);

    /*int insert_task(hashtable_t *task_dict, hashtable_t *temp_pkg_dict, pkg_t *pkg);
    void * insert_pkg(hashtable_t *task_dict, hashtable_t *temp_pkg_dict, pkg_t *pkg_temp);*/


private:
    void init(void);
    ring_queue_t * init_ringq(void);
    hashtable_t * init_hash(void);
    ring_queue_t * get_ring_q(uint8 qtype);
    hashtable_t * get_hash(void);


private:
    ring_queue_t * m_fastq;   //数据队列

    hashtable_t * m_taskhash; //任务哈希

    // std::map<int32, uint16> m_pkgcnt;
    hashtable_t * m_pkgcnt;

    ring_queue_t * m_connect_q; //连接Q

    friend void *_effqueuefunc_(void *arg);
    friend void * distribute_data(void *arg);
};

#endif