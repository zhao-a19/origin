/*******************************************************************************************
*文件:  nfqnetlink.cpp
*描述:  nfqnetlink数据处理
*作者:  王君雷
*日期:  2019-01-25
*修改:
*        nfqueue收包大小改为65536                                     ------> 2020-04-02-dzj
*        可以设置线程名称                                             ------> 2021-02-23
*******************************************************************************************/
#include "define.h"

#ifdef USE_NFQUEUE_NETLINK
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>/* for NF_ACCEPT */
#include <errno.h>

#include "libnetfilter_queue/libnetfilter_queue.h"
#include "debugout.h"
#include "FCThread.h"
#include "appmatch.h"

#define MAX_QUEUE_LEN 10240
#define MAX_QUEUE_RECV_LEN 65536

struct nfq_q_handle {
    struct nfq_q_handle *next;
    struct nfq_handle *h;
    uint16_t id;
    nfq_callback *cb;
    void *data;
};

/**
 * [cb 回调函数]
 * @param  qh    [句柄]
 * @param  nfmsg [ nf基本消息结构]
 * @param  nfa   [description]
 * @param  data  [description]
 * @return       [description]
 */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    unsigned char *sdata;
    int id = 0;
    bool bflag = true;
    char cherror[1024] = {0};
    int pktchanged = 0;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph != NULL) {
        id = ntohl(ph->packet_id);
    } else {
        PRINT_ERR_HEAD
        print_err("nfq_get_msg_packet_hdr return null");
    }

    int ret = nfq_get_payload(nfa, &sdata);
    if (ret >= 0) {
        bflag = DoMsg(sdata, ret, cherror, &pktchanged, qh->id);
    } else {
        PRINT_ERR_HEAD
        print_err("nfq_get_payload return %d", ret);
    }

    return nfq_set_verdict(qh, id, bflag ? NF_ACCEPT : NF_DROP, ret, sdata);
}

/**
 * [start_nfqueue 开始循环接收处理一个queue队列]
 * @param  qnum [队列号]
 * @return      [失败返回负值]
 */
int start_nfqueue(int qnum)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    uint32_t queue = qnum;
    char buf[MAX_QUEUE_RECV_LEN] __attribute__ ((aligned));

    PRINT_DBG_HEAD
    print_dbg("opening library handle [%d]", queue);

    h = nfq_open();
    if (h == NULL) {
        PRINT_ERR_HEAD
        print_err("error during nfq_open [%d] errinfo[%d,%s]", queue, errno, strerror(errno));
        return -1;
    }

    //PRINT_INFO_HEAD
    //print_info("unbinding existing nf_queue handler for AF_INET (if any) [%d]", queue);

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        PRINT_ERR_HEAD
        print_err("error during nfq_unbind_pf [%d] errinfo[%d,%s]", queue, errno, strerror(errno));
        nfq_close(h);
        return -1;
    }

    //PRINT_INFO_HEAD
    //print_info("binding nfnetlink_queue as nf_queue handler for AF_INET [%d]", queue);

    if (nfq_bind_pf(h, AF_INET) < 0) {
        PRINT_ERR_HEAD
        print_err("error during nfq_bind_pf [%d] errinfo[%d,%s]", queue, errno, strerror(errno));
        nfq_close(h);
        return -1;
    }

    //PRINT_INFO_HEAD
    //print_info("binding this socket to queue [%d]", queue);

    qh = nfq_create_queue(h, queue, &cb, NULL);
    if (qh == NULL) {
        PRINT_ERR_HEAD
        print_err("error during nfq_create_queue [%d] errinfo[%d,%s]", queue, errno, strerror(errno));
        nfq_close(h);
        return -1;
    }

    //PRINT_INFO_HEAD
    //print_info("setting copy_packet mode [%d]", queue);

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        PRINT_ERR_HEAD
        print_err("can't set packet_copy mode [%d] errinfo[%d,%s]", queue, errno, strerror(errno));
        nfq_close(h);
        return -1;
    }

    //PRINT_INFO_HEAD
    //print_info("setting flags to request UID and GID[%d]", queue);

    if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
        PRINT_DBG_HEAD
        print_dbg("This kernel version does not allow to retrieve process UID/GID.[%d]", queue);
    }

    //PRINT_INFO_HEAD
    //print_info("setting flags to request security context[%d]", queue);

    if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
        fprintf(stderr, "\n");
        PRINT_DBG_HEAD
        print_dbg("This kernel version does not allow to retrieve security context.[%d]", queue);
    }

#if 0
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_GSO, 0)) {
        fprintf(stderr, "\n");

        PRINT_INFO_HEAD
        print_info("This kernel version does not allow to gso.[%d]", queue);
    }
#endif

    if (nfq_set_queue_maxlen(qh, MAX_QUEUE_LEN) < 0) {
        PRINT_ERR_HEAD
        print_err("sen queue maxlen fail [%d]", MAX_QUEUE_LEN);
    }

    PRINT_INFO_HEAD
    print_info("Waiting for packets...[%d]", queue);

    fd = nfq_fd(h);
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if ((rv < 0) && (errno == ENOBUFS)) {
            PRINT_ERR_HEAD
            print_err("losing packets[%d]", queue);
            continue;
        }

        PRINT_ERR_HEAD
        print_err("recv failed[%d][%s]", queue, strerror(errno));
        break;
    }

    PRINT_ERR_HEAD
    print_err("unbinding from queue[%d]", queue);
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    PRINT_ERR_HEAD
    print_err("unbinding from AF_INET");
    nfq_unbind_pf(h, AF_INET);
#endif

    PRINT_ERR_HEAD
    print_err("closing library handle[%d]", queue);
    nfq_close(h);
    return -1;
}

/**
 * [nfq_process 接收处理某一个队列信息的线程函数]
 * @param  arg [队列号指针]
 * @return     [未使用]
 */
void *nfq_process(void *arg)
{
    int queuenum = *(int *)arg;
    PRINT_INFO_HEAD
    print_info("nfq process queuenum[%d]", queuenum);
    char chcmd[64] = {0};
    sprintf(chcmd, "nfq%d", queuenum);
    pthread_setname(chcmd);

    while (1) {
        start_nfqueue(queuenum);
        PRINT_ERR_HEAD
        print_err("nfqueue[%d] error,retry", queuenum);
        sleep(2);
    }

    return NULL;
}

static CThread g_nfqlinkth[MAX_IPTABLES_QUEUE_NUM];

/**
 * [StartNFQueueNetLink 启动处理NFQUEUE队列的线程]
 * @param num [启动处理线程个数]
 */
void StartNFQueueNetLink(int num)
{
    if ((num < 0)  || (num > MAX_IPTABLES_QUEUE_NUM)) {
        PRINT_ERR_HEAD
        print_err("start nfq para err[%d] maxqueuenum[%d]", num, MAX_IPTABLES_QUEUE_NUM);
        return;
    }
    //至少启动一个
    if (num == 0) {
        num = 1;
    }

    PRINT_INFO_HEAD
    print_info("start nfq netlink. total process num[%d]", num);

    for (int i = 0; i < num; i++) {
        PRINT_INFO_HEAD
        print_info("start nfq process[%d]", i);
        g_nfqlinkth[i].ThCreate(nfq_process, &i);
        usleep(10000);
    }

    PRINT_INFO_HEAD
    print_info("start nfq netlink over");
}

#endif
