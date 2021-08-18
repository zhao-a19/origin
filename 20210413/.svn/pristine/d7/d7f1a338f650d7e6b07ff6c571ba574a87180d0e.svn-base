/*******************************************************************************************
*文件:  ipqnetlink.cpp
*描述:  ipqnetlink数据处理
*作者:  王君雷
*日期:  2016-03
*修改:
*         g_icmpapp由指针数组改为单个指针，因为只产生一个对象 ------> 2017-11-24 王君雷
*         OPC按五元组追踪每一个连接;代码改用linux风格utf8编码 ------> 2018-03-30
*         ipqueue收包大小改为65536                            ------> 2020-04-02-dzj
*         可以设置线程名称                                    ------> 2021-02-23
*******************************************************************************************/
#include "define.h"

#ifdef USE_IPQUEUE_NETLINK
#include <errno.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/ip_queue.h>
#include <netinet/ether.h>
#include "ipqnetlink.h"
#include "FCThread.h"
#include "debugout.h"
#include "appmatch.h"

#define IPQ_PACKET_SIZE 65535

typedef struct _link_message {
    struct nlmsghdr head;
    union {
        struct ipq_mode_msg mode;
        struct ipq_verdict_msg verdict;
    } body;
} LINK_MESSAGE, *PLINK_MESSAGE;

/**
 * [ipq_create 创建IPQ使用socket 并绑定地址]
 * @param  sock [描述符 出参]
 * @return      [成功返回true]
 */
bool ipq_create(int &sock)
{
    //SOCK_RAW指明采用原始套接字，也可以采用SOCK_DGRAM
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_FIREWALL);
    if (sock < 0) {
        PRINT_ERR_HEAD
        print_err("socket error(%s). sock = %d", strerror(errno), sock);
        return false;
    }

    struct sockaddr_nl bindaddr;
    BZERO(bindaddr);
    bindaddr.nl_family = AF_NETLINK;
    bindaddr.nl_pid = getpid();         //注意 是进程ID
    bindaddr.nl_groups = 0;
    if (bind(sock, (struct sockaddr *)&bindaddr, sizeof(bindaddr)) < 0) {
        PRINT_ERR_HEAD
        print_err("bind error(%s). sock = %d", strerror(errno), sock);
        return false;
    }
    return true;
}

/**
 * [ipq_set_mode 向内核发送模式请求]
 * @param  sock  [描述符]
 * @param  mode  [模式]
 * @param  range [请求报文长度]
 * @param  addr  [地址结构]
 * @return       [成功返回true]
 */
bool ipq_set_mode(int sock, unsigned char mode, int range, struct sockaddr_nl &addr)
{
    LINK_MESSAGE message;
    BZERO(message);

    message.head.nlmsg_len = sizeof(LINK_MESSAGE);        //消息体的总长度 包含头信息在内
    message.head.nlmsg_type = IPQM_MODE;                  //IPQM_MODE 模式设置消息
    message.head.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;//用来该对消息体进行另外的控制，会被netlink核心代码读取并更新
    message.head.nlmsg_pid = getpid();                    //应用程序用它来跟踪消息
    message.body.mode.value = mode;                       //请求的模式
    message.body.mode.range = range;                      //请求拷贝的报文长度

    if (sendto(sock, &message, sizeof(message), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PRINT_ERR_HEAD
        print_err("sendto error.sock = %d,range = %d,err = %s", sock, range, strerror(errno));
        return false;
    }
    return true;
}

/**
 * [ipq_handle_pack 处理一条从内核收上来的消息 把处理结果保存到后一个参数中]
 * @param  pmsg     [由内核协议栈发给用户态进程的IP Queue消息]
 * @param  plinkmsg [保存处理结果的结构 将来要把它发送到内核]
 * @return          [成功返回true]
 */
bool ipq_handle_pack(struct ipq_packet_msg *pmsg, PLINK_MESSAGE plinkmsg)
{
    char cherror[1024] = {0};
    int pktchanged = 0;

    if ((pmsg == NULL) || (plinkmsg == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    plinkmsg->head.nlmsg_type = IPQM_VERDICT;
    plinkmsg->head.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    plinkmsg->head.nlmsg_pid = getpid();
    plinkmsg->head.nlmsg_seq = 0;
    plinkmsg->body.verdict.id = pmsg->packet_id;

    if (DoMsg(pmsg->payload, pmsg->data_len, cherror, &pktchanged, 0)) {
        plinkmsg->body.verdict.value = NF_ACCEPT;
    } else {
        plinkmsg->body.verdict.value = NF_DROP;
        PRINT_ERR_HEAD
        print_err("NF_DROP.datalen = %d,packetid = %lu,indev = %s,outdev = %s",
                  pmsg->data_len, pmsg->packet_id, pmsg->indev_name, pmsg->outdev_name);
    }
    if (pktchanged == PACKET_CHANGED) {
        plinkmsg->body.verdict.data_len = pmsg->data_len;//data_len指明新报文的长度
        memcpy(plinkmsg->body.verdict.payload, pmsg->payload, pmsg->data_len);
    } else {
        plinkmsg->body.verdict.data_len = 0;
    }
    plinkmsg->head.nlmsg_len = sizeof(LINK_MESSAGE) + plinkmsg->body.verdict.data_len;
    return true;
}

/**
 * [ipq_send_verdict 发送判决结果给内核]
 * @param  sock      [描述符]
 * @param  plinkmsg  [保存处理结果的结构 要把它发送到内核]
 * @param  kernaddr  [地址结构]
 * @return           [description]
 */
bool ipq_send_verdict(int sock, PLINK_MESSAGE plinkmsg, struct sockaddr_nl &kernaddr)
{
    if (plinkmsg == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    if (sendto(sock, plinkmsg, plinkmsg->head.nlmsg_len, 0, (struct sockaddr *)&kernaddr,
               sizeof(kernaddr)) < 0) {
        PRINT_ERR_HEAD
        print_err("sendto err(%s).sock = %d,len = %d", strerror(errno), sock, plinkmsg->head.nlmsg_len);
        return false;
    }
    return true;
}

/**
 * [ipq_process 处理ipqueue的线程函数]
 * @param  param [未使用]
 * @return       [未使用]
 */
void *ipq_process(void *param)
{
    pthread_setname("ipqprocess");
    int rlen = 0;
    int sock = 0;
    unsigned char fromkern_buff[IPQ_PACKET_SIZE] = {0};
    unsigned char tokern_buff[IPQ_PACKET_SIZE] = {0};
    PLINK_MESSAGE p_linkmsg = (PLINK_MESSAGE)tokern_buff;
    struct nlmsghdr *p_nlmsghdr = NULL;
    struct ipq_packet_msg *p_ipq_packet_msg = NULL;

    //向内核发送信息时使用的地址
    struct sockaddr_nl kernaddr;
    BZERO(kernaddr);
    kernaddr.nl_family = AF_NETLINK;
    kernaddr.nl_pid = 0;//注意 必须为0
    kernaddr.nl_groups = 0;

    if (ipq_create(sock) && ipq_set_mode(sock, IPQ_COPY_PACKET, IPQ_PACKET_SIZE, kernaddr)) {
        PRINT_INFO_HEAD
        print_info("ipq create ok. sock = %d,range = %d", sock, IPQ_PACKET_SIZE);
    } else {
        CLOSE(sock);
        return NULL;
    }

    while (1) {
        rlen = recv(sock, fromkern_buff, sizeof(fromkern_buff) - 1, 0);
        if (rlen <= 0) {
            PRINT_ERR_HEAD
            print_err("recv err(%s).sock = %d,rlen = %d", strerror(errno), sock, rlen);
            usleep(10000);
            continue;
        }
        fromkern_buff[rlen] = '\0';
        p_nlmsghdr = (struct nlmsghdr *)fromkern_buff;

        while (NLMSG_OK(p_nlmsghdr, (unsigned int)rlen)) {

            //如果内核通过Netlink队列返回了多个消息，那么队列的最后一条消息的类型为NLMSG_DONE
            if (p_nlmsghdr->nlmsg_type == NLMSG_DONE) {
                PRINT_DBG_HEAD
                print_dbg("sock = %d,NLMSG_DONE", sock);
                break;
            } else if (p_nlmsghdr->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *p_nlmsgerr = (struct nlmsgerr *)NLMSG_DATA(p_nlmsghdr);
                PRINT_ERR_HEAD
                print_err("sock = %d, errno= %d ,NLMSG_ERROR(%s)", sock, -p_nlmsgerr->error,
                          strerror(-p_nlmsgerr->error));
                break;
            } else if (p_nlmsghdr->nlmsg_type == IPQM_PACKET) {

                p_ipq_packet_msg = (struct ipq_packet_msg *)NLMSG_DATA(p_nlmsghdr);
                if (ipq_handle_pack(p_ipq_packet_msg, p_linkmsg)) {
                    ipq_send_verdict(sock, p_linkmsg, kernaddr);
                } else {
                    PRINT_ERR_HEAD
                    print_err("handle pack err.sock = %d,datalen = %d,packetid = %lu,indev = %s,outdev = %s",
                              sock, p_ipq_packet_msg->data_len, p_ipq_packet_msg->packet_id,
                              p_ipq_packet_msg->indev_name, p_ipq_packet_msg->outdev_name);
                }
            }
            p_nlmsghdr = NLMSG_NEXT(p_nlmsghdr, rlen);
        }
    }

    PRINT_ERR_HEAD
    print_err("ipq netlink process will exit.sock = %d", sock);
    ipq_set_mode(sock, IPQ_COPY_NONE, 0, kernaddr);
    CLOSE(sock);
    return NULL;
}

/**
 * [StartIPQueueNetLink 开启处理IP QUEUE的线程]
 */
static CThread g_ipqlinkth;
void StartIPQueueNetLink(void)
{
    PRINT_INFO_HEAD
    print_info("start ipqueue netlink process");

    g_ipqlinkth.ThCreate(ipq_process, NULL);
}

#endif
