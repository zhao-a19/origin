/*******************************************************************************************
*文件:    FCSip.cpp
*描述:    平台级联 基类
*作者:    王君雷
*日期:    2016-02-19
*修改:    可以对命令进行过滤并记录日志                                 ------>   2016-02-19
*         媒体流通道加iptables，只在一端分析，另一端直接转发即可       ------>   2016-03-02
*         兼容SIP消息contact字段没有@符号时替换地址信息                ------>   2016-03-18
*         修改了ClientInfo替换地址后Content-Length计算错误             ------>   2016-04-01
*         修改了ServerInfo替换地址后Content-Length计算错误             ------>   2016-04-05
*         每次INVITE都执行iptables                                     ------>   2016-04-07
*         平台级联处理audio字段                                        ------>   2016-12-28
*         重新设计平台级联，目的侧网闸不需动态添加iptables             ------>   2017-08-30
*         视频厂商宏使用英文翻译,改为UTF8编码,改用linux缩进格式        ------>   2018-01-23
*         修改winsip软件测试发现的问题:
*         1)SIP包源端口有时是随机的端口,检查过于严格了,2017-08-30引入的
*         2)替换客户端发来的呼叫信令中的IP时考虑特殊情况,IP后不是:port ------>   2018-02-28
*         函数命名统一风格                                             ------>   2018-04-23
*         把replaceClientInfo和replaceServerInfo整合到一起，都使用replaceInfo
*         因为他们有太多的重复代码;全文件统一使用zlog                  ------>   2018-05-22
*         兼容Content-Length:和via:后没有空格的情况;修改日志方向有误   ------>   2018-05-24
*         数据包包含0x00时，0x00及之后的内容照搬                       ------>   2018-06-06
*         Content-Length和via，与字段值之间，可以有任意多个空格        ------>   2018-06-08
*         日志中能区分视频的类型                                       ------>   2018-06-22
*         可通过会话ID清空、复用视频通道;支持多节点视频联动            ------>   2018-07-14
*         解析CallID的时候，不包含\r之后的内容，保持zlog日志整洁       ------>   2018-07-24
*         设置内部nat ip的函数返回值类型改为bool                       ------>   2018-08-15
*         添加对东方电子厂商支持；部分厂商可以支持替换from to字段      ------>   2018-11-19
*         socket通信类接口传参顺序有变动                               ------>   2019-03-18
*         delete释放空间格式调整                                       ------>   2019-05-21
*         SIP替换IP代码接口封装，针对厂家接口封装                      ------>   2019-06-03
*         将SIP代码回滚开关放在编辑选项里                              ------>   2019-06-04
*         代码优化，删掉无用变量和日志，字符串操作改为指针操作         ------>   2019-06-24 --dzj
*         代码优化，去掉不必要的数组清零操作                           ------>   2019-06-25 --dzj
*         解决SIP日志导出时乱序问题                                    ------>   2019-06-27 --dzj
*         修改SIP报文结尾无'\n'造成的报文内容丢失无法共享点位问题      ------>   2019-09-28
*         解决SIP替换时出现替换不是SDP消息的问题                       ------>   2019-12-03 --dzj
*         不再串行记录访问日志                                         ------>   2020-01-07 --wjl
*         访问日志支持记录MAC字段,暂设置为空                           ------>   2020-01-16 wjl
*         下级发出的NOTIFY请求，需要替换IP                             ------>   2020-05-21 wjl
*         添加东方网力、数智源、东方网力厂商                             ------>   2020-07-21
*         兼容配置文件中Protocol为SIP和GB28181两种情况                  ------>  2020-08-18 wjl
*         解决TCP传输SIP时，connect失败忘记关闭描述符的BUG；
*         使用select处理TCP连接                                        ------> 2020-11-30
*         修改下级注册包永不替换Via, From, To BUG                       ------> 2021-04-01 LL
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "FCSip.h"
#include "define.h"
#include "quote_global.h"
#include "FCLogContainer.h"
#include "debugout.h"

CSipBase::CSipBase(int taskno)
{
    m_taskno = taskno;
    m_cmdnum = 0;
    BZERO(m_cmd);
}

CSipBase::~CSipBase()
{
    DELETE_N(m_cmd, m_cmdnum);
}

/**
 * [CSipBase::init 任务初始化]
 * @return [成功返回0]
 */
int CSipBase::init()
{
    initChannel();//多态 调用子类的初始化函数

    //创建访问 m_tcpstate 时使用的信号量，当互斥锁用
    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "%s%d", TCP_STATE_MUTEX_PATH, m_taskno);
    sem_unlink(chcmd);
    m_tcp_sem = sem_open(chcmd, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, 1);
    if (m_tcp_sem == SEM_FAILED) {
        PRINT_ERR_HEAD
        print_err("sem_open error[%s]", strerror(errno));
        return -1;
    }
    memset(m_tcpstate, STATUS_FREE, sizeof(m_tcpstate));
    return 0;
}

/**
 * [CSipBase::getTCPThreadID 获取一个TCP线程对应的下标ID]
 * @return [成功返回下标，失败返回-1]
 */
int CSipBase::getTCPThreadID()
{
    sem_wait(m_tcp_sem);
    for (int i = 0; i < (int)ARRAY_SIZE(m_tcpstate); i++) {
        if (m_tcpstate[i] == STATUS_FREE) {
            m_tcpstate[i] = STATUS_INUSE;
            sem_post(m_tcp_sem);
            return i;
        }
    }
    sem_post(m_tcp_sem);
    return -1;
}

/**
 * [CSipBase::findStrByKey 从字符串src偏移spos长度，
 * 查找字符ikey，然后把ikey之前查找到的字符存放到dst里]
 * @param  src  [被查找的字符串]
 * @param  dst  [存放查找出的字符串]
 * @param  spos [开始查找的偏移位置]
 * @param  ikey [分隔字符]
 * @return      [成功返回下一次查找时的偏移量，失败返回-1]
 */
int CSipBase::findStrByKey(const char *src, char *dst, int spos, char ikey)
{
    int slen = strlen(src);

    for (int i = spos; i < slen; i++) {
        if ((i - spos) >= SIP_MAX_LINE_SIZE - 24) {

            PRINT_ERR_HEAD
            print_err("Line too long. More than max support size[%d]", SIP_MAX_LINE_SIZE - 24);
            break;
        }
        *dst++ = *(src + i);
        if (*(src + i) == ikey) {
            return i + 1;
        }
    }

    return -1;
}

/**
 * [CSipBase::regStatusReq 记录下一个动态端口信息 并开通媒体流通道]
 * @param  cinput      [包含动态端口信息的一行内容 示例：m=video 63544 udp 105\r\n]
 * @param  mediarecvip [媒体流接收者IP]
 * @param  ifvideo     [是否为video包，true表示是video包，false表示audio包]
 * @param  callid      [会话ID]
 * @return             [成功时返回媒体流通道的下标，失败返回负值]
 */
int CSipBase::regStatusReq(char *cinput, const char *mediarecvip, bool ifvideo, const char *callid)
{
    if ((cinput == NULL) || (mediarecvip == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    char MVIDEO[20] = "m=video ";
    char MAUDIO[20] = "m=audio ";
    char tmpstr[200] = {0};
    char tmpport[PORT_STR_LEN] = {0};
    char *ptr = NULL;
    int portlen = 0;
    int find = 0;
    int chanid = 0;
    int nodeid = 0;

    ptr = index(cinput + strlen(ifvideo ? MVIDEO : MAUDIO), ' ');
    if (ptr == NULL) {
        PRINT_ERR_HEAD
        print_err("not find Space[%s]", cinput);
        return -1;
    }

    //端口号之后的内容拷贝到变量
    strcpy(tmpstr, ptr);
    //端口号拷贝到变量
    portlen = strlen(cinput) - strlen(tmpstr) - strlen(ifvideo ? MVIDEO : MAUDIO);
    if (portlen < (int)sizeof(tmpport)) {
        strncpy(tmpport, cinput + strlen(ifvideo ? MVIDEO : MAUDIO), portlen);
    } else {
        PRINT_ERR_HEAD
        print_err("port len invalid[%d],[%s]", portlen, cinput);
        return -1;
    }

    chanid = getOneChannelID(mediarecvip, tmpport, find, callid, nodeid);
    if (chanid < 0) {
        PRINT_ERR_HEAD
        print_err("getOneChannelID error[%d]", chanid);
        return -2;
    }

    if (find == 0) {
        addOneChannel(nodeid, chanid); //多态
    }

    sprintf(cinput, "%s%s%s", ifvideo ? MVIDEO : MAUDIO,
            getChannelProxyPort(nodeid, chanid), tmpstr);//多态
    return chanid;
}

/**
 * [CSipBase::clientInfoTask 接收上级平台的请求并转发]
 * @param  para [SOCKTASK指针]
 * @return      [正常情况下不退出，异常时返回NULL并退出]
 */
void *CSipBase::clientInfoTask(void *para)
{
    pthread_setself("clientinfotask");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    SOCKTASK *m_task = (SOCKTASK *)para;
    unsigned char buff[SIP_MAX_PACKET];
    unsigned char buff2[SIP_MAX_PACKET];
    int recvlen = 0;
    int sendlen = 0;
    int replen = 0;
    int recvsock = m_task->recvsock;
    int sendsock = m_task->sendsock;
    CSipBase *psip = m_task->psip;

    DELETE(m_task);

    if (psip == NULL) {
        PRINT_ERR_HEAD
        print_err("psip null");
        return NULL;
    }

    sockaddr_in to_addr;
    to_addr.sin_family = AF_INET;
    to_addr.sin_addr.s_addr = inet_addr(psip->m_tmpip2);
    to_addr.sin_port = htons(atoi(psip->m_downplatport));
    bzero(&(to_addr.sin_zero), 8);

    while (1) {
        BZERO(buff);
        BZERO(buff2);

        //接收上级平台请求
        recvlen = recvfrom(recvsock, buff, sizeof(buff) - SIP_PKT_LEN_CHANGE, 0, NULL, NULL);
        if (recvlen <= 0) {
            PRINT_ERR_HEAD
            print_err("recvfrom error[%s][%d]", strerror(errno), recvlen);
            usleep(1000);
            continue;
        }

        //替换请求信息
        replen = psip->replaceClientInfo((char *)buff, recvlen, (char *)buff2);
        if (replen > 0) {
            //转发请求信息
            sendlen = sendto(sendsock, buff2, replen, 0,
                             (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
            if (sendlen <= 0) {
                PRINT_ERR_HEAD
                print_err("sendto error[%s][%d]", strerror(errno), sendlen);
                continue;
            }

            PRINT_DBG_HEAD
            print_dbg("send[%d]", sendlen);
        } else {
            PRINT_ERR_HEAD
            print_err("replaceClientInfo error[%d]", replen);
            continue;
        }
    }

    PRINT_ERR_HEAD
    print_err("You should never get here");
    close(sendsock);
    close(recvsock);
    return NULL;
}

/**
 * [CSipBase::serverInfoTask 接收下级平台的响应并转发]
 * @param  para [SOCKTASK指针]
 * @return      [正常情况下不退出，异常时返回NULL并退出]
 */
void *CSipBase::serverInfoTask(void *para)
{
    pthread_setself("serverinfotask");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    SOCKTASK *m_task = (SOCKTASK *)para;
    unsigned char buff[SIP_MAX_PACKET];
    unsigned char buff2[SIP_MAX_PACKET];
    int recvlen = 0;
    int sendlen = 0;
    int replen = 0;
    int recvsock = m_task->recvsock;
    int sendsock = m_task->sendsock;
    CSipBase *psip = m_task->psip;

    DELETE(m_task);

    if (psip == NULL) {
        PRINT_ERR_HEAD
        print_err("psip null");
        return NULL;
    }

    //上级平台接收SIP地址结构
    sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr(psip->m_upplatip);
    client_addr.sin_port = htons(atoi(psip->m_upplatport));
    bzero(&(client_addr.sin_zero), 8);

    while (1) {
        BZERO(buff);
        BZERO(buff2);

        recvlen = recvfrom(recvsock, buff, sizeof(buff) - SIP_PKT_LEN_CHANGE, 0, NULL, NULL);
        if (recvlen <= 0) {
            PRINT_ERR_HEAD
            print_err("recvfrom error[%s][%d]", strerror(errno), recvlen);
            usleep(1000);
            continue;
        }

        replen = psip->replaceServerInfo((char *)buff, recvlen, (char *)buff2);
        if (replen > 0) {
            sendlen = sendto(sendsock, buff2, replen, 0,
                             (struct sockaddr *)&client_addr, sizeof(client_addr));
            if (sendlen <= 0) {
                PRINT_ERR_HEAD
                print_err("sendto error[%s][%d]", strerror(errno), sendlen);
                continue;
            }

            PRINT_DBG_HEAD
            print_dbg("send[%d]", sendlen);
        } else {
            PRINT_ERR_HEAD
            print_err("replaceServerInfo error[%d]", replen);
            continue;
        }
    }

    PRINT_ERR_HEAD
    print_err("You should never get here");
    close(sendsock);
    close(recvsock);
    return NULL;
}

/**
 * [CSipBase::doRecv 接收处理TCP SIP数据]
 * @param  sock1 [描述符1]
 * @param  sock2 [描述符2]
 * @param  flag  [标志]
 * @return       [成功返回true]
 */
bool CSipBase::doRecv(int sock1, int sock2, int flag)
{
    unsigned char buff1[SIP_MAX_PACKET] = {0};
    unsigned char buff2[SIP_MAX_PACKET] = {0};
    int recvlen = 0;
    int sendlen = 0;
    int replen = 0;

    recvlen = recv(sock1, buff1, sizeof(buff1) - SIP_PKT_LEN_CHANGE, 0);
    if (recvlen <= 0) {
        PRINT_INFO_HEAD
        print_info("recv fail[%s][%d],may close!", strerror(errno), recvlen);
        return false;
    }

    if ((flag == 5) || (flag == 8)) {
        replen = replaceClientInfo((char *)buff1, recvlen, (char *)buff2);
    } else if ((flag == 6) || (flag == 7)) {
        replen = replaceServerInfo((char *)buff1, recvlen, (char *)buff2);
    } else {
        PRINT_ERR_HEAD
        print_err("unknown flag[%d]", flag);
        return false;
    }

    if (replen > 0) {
        sendlen = send(sock2, buff2, replen, 0);
        if (sendlen <= 0) {
            PRINT_INFO_HEAD
            print_info("send fail[%s][%d]", strerror(errno), sendlen);
            return false;
        }
        PRINT_DBG_HEAD
        print_dbg("send[%d]", sendlen);
    } else {
        PRINT_ERR_HEAD
        print_err("replace error[%d]", replen);
        return false;
    }
    return true;
}

/**
 * [CSipBase::TCPSendAndRecvTask TCP接收和发送线程函数]
 * @param  para [SOCKTASK指针]
 * @return      [无特殊含义]
 */
void *CSipBase::TCPSendAndRecvTask(void *para)
{
    pthread_setself("tcpsendandrecv");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    SOCKTASK *m_task = (SOCKTASK *)para;
    int recvsock = m_task->recvsock;
    int sendsock = m_task->sendsock;
    int thid = m_task->thid;
    int flag = m_task->flag;
    CSipBase *psip = m_task->psip;
    DELETE(m_task);

    if (psip == NULL) {
        PRINT_ERR_HEAD
        print_err("psip null");
        return NULL;
    }

    int maxfd = 0;
    int ret = 0;
    fd_set fds;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(recvsock, &fds);
        FD_SET(sendsock, &fds);
        maxfd = MAX(recvsock, sendsock);

        ret = select(maxfd + 1, &fds, NULL, NULL, NULL);
        if (ret == 0) {
            //timeout
            continue;
        } else if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("select fail(%s) ret[%d]", strerror(errno), ret);
            break;
        }

        if (FD_ISSET(recvsock, &fds)) {
            if (!psip->doRecv(recvsock, sendsock, flag == 1 ? 5 : 6)) {
                PRINT_INFO_HEAD
                print_info("sock[%d] do recv ret false", recvsock);
                break;
            }
        }

        if (FD_ISSET(sendsock, &fds)) {
            if (!psip->doRecv(sendsock, recvsock, flag == 1 ? 7 : 8)) {
                PRINT_INFO_HEAD
                print_info("sock[%d] do recv ret false", sendsock);
                break;
            }
        }
    }

    sem_wait(psip->m_tcp_sem);
    if (psip->m_tcpstate[thid] == STATUS_INUSE) {
        PRINT_DBG_HEAD
        print_dbg("thid[%d] tcp close ssock[%d] rsock[%d]", thid, sendsock, recvsock);
        close(sendsock);
        close(recvsock);
        psip->m_tcpstate[thid] = STATUS_FREE;
    } else {
        PRINT_ERR_HEAD
        print_err("thid[%d] something may error! tcpstate[%d]", thid, psip->m_tcpstate[thid]);
    }
    sem_post(psip->m_tcp_sem);

    PRINT_DBG_HEAD
    print_dbg("thid[%d] exit", thid);
    return NULL;
}

/**
 * [CSipBase::TCPListenTask TCP监听任务]
 * @param  para [SOCKTASK指针]
 * @return      [正常情况下不会退出，异常时返回NULL]
 */
void *CSipBase::TCPListenTask(void *para)
{
    pthread_setself("tcplistentask");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    SOCKTASK *m_task = (SOCKTASK *)para;
    int flag = m_task->flag;
    CSipBase *psip = m_task->psip;

    DELETE(m_task);

    if (psip == NULL) {
        PRINT_ERR_HEAD
        print_err("psip null");
        return NULL;
    }

    //根据flag的不同 绑定监听不同的ip 端口
    CBSTcpSockServer ser;
    if (flag == 1) {
        while (ser.Open(psip->m_gapinip, atoi(psip->m_downplatport)) < 0) {
            PRINT_ERR_HEAD
            print_err("listen[%d][%s] fail, retry", atoi(psip->m_downplatport), psip->m_gapinip);
            sleep(1);
        }
        PRINT_DBG_HEAD
        print_dbg("listen[%d][%s] ok", atoi(psip->m_downplatport), psip->m_gapinip);

    } else if (flag == 2) {
        while (ser.Open(psip->m_tmpip1, atoi(psip->m_upplatport)) < 0) {
            PRINT_ERR_HEAD
            print_err("listen[%d][%s] fail, retry", atoi(psip->m_upplatport), psip->m_tmpip1);
            sleep(1);
        }
        PRINT_DBG_HEAD
        print_dbg("listen[%d][%s] ok", atoi(psip->m_upplatport), psip->m_tmpip1);
    } else {
        PRINT_ERR_HEAD
        print_err("flag error[%d]", flag);
        return NULL;
    }

    int mysock1 = 0;
    int mysock2 = 0;
    int tcpthid = 0;

    while (1) {
        mysock1 = 0;
        mysock2 = 0;
        mysock1 = ser.StartServer();
        if (mysock1 < 0) {
            PRINT_ERR_HEAD
            print_err("accept error[%s]", strerror(errno));
            continue;
        }

        tcpthid = psip->getTCPThreadID();
        if (tcpthid == -1) {
            PRINT_ERR_HEAD
            print_err("LinkNum has reached the maximum [%d], close it", C_MAX_THREAD);
            close(mysock1);
            continue;
        }

        PRINT_DBG_HEAD
        print_dbg("tcpthid[%d] accept sock %d", tcpthid, mysock1);

        //根据flag的不同 去连接不同的ip端口
        if (flag == 1) {
            mysock2 = psip->m_cli[tcpthid].Open(psip->m_tmpip2, atoi(psip->m_downplatport));
            if (mysock2 <= 0) {
                PRINT_ERR_HEAD
                print_err("connect Err! ip[%s]port[%s]flag[%d]", psip->m_tmpip2, psip->m_downplatport, flag);
                close(mysock1);
                psip->m_tcpstate[tcpthid] = STATUS_FREE;
                continue;
            }
        } else if (flag == 2) {
            mysock2 = psip->m_cli[tcpthid].Open(psip->m_upplatip, atoi(psip->m_upplatport));
            if (mysock2 <= 0) {
                PRINT_ERR_HEAD
                print_err("connect Err! ip[%s]port[%s]flag[%d]", psip->m_upplatip, psip->m_upplatport, flag);
                close(mysock1);
                psip->m_tcpstate[tcpthid] = STATUS_FREE;
                continue;
            }
        }

        if (mysock1 == mysock2) {
            PRINT_ERR_HEAD
            print_err("mysock1 == mysock2 %d, thid=%d", mysock1, tcpthid);
        }

        //准备线程参数
        SOCKTASK *psock1 = new SOCKTASK();
        if (psock1 == NULL) {
            PRINT_ERR_HEAD
            print_err("new SOCKTASK error");

            close(mysock1);
            close(mysock2);
            psip->m_tcpstate[tcpthid] = STATUS_FREE;
            continue;
        }
        psock1->recvsock = mysock1;
        psock1->sendsock = mysock2;
        psock1->thid = tcpthid;
        psock1->psip = psip;
        psock1->flag = flag;

        pthread_t pid1 = 0;
        if (pthread_create(&pid1, NULL, TCPSendAndRecvTask, (void *)psock1) != 0) {
            PRINT_ERR_HEAD
            print_err("pthread_create error");

            close(mysock1);
            close(mysock2);
            psip->m_tcpstate[tcpthid] = STATUS_FREE;
            DELETE(psock1);
            continue;
        }
        usleep(1000);
    }

    PRINT_ERR_HEAD
    print_err("You should never get here, flag = %d", flag);
    return NULL;
}

/**
 * [CSipBase::srcStart 靠近上级平台的一端起始函数]
 * @return [成功返回0]
 */
int CSipBase::srcStart()
{
    char chcmd[CMD_BUF_LEN] = {0};

    //FORWARD
    sprintf(chcmd, "%s -I FORWARD -s %s -j ACCEPT", IPTABLES, m_tmpip2);
    SIP_SYSTEM(chcmd);

    //源对象访问控制
    sprintf(chcmd, "%s -A INPUT -p udp -d '%s' --dport '%s' -m iprange ! --src-range '%s' -j DROP",
            IPTABLES, m_gapinip, m_downplatport, m_upplatip);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -A INPUT -p tcp -d '%s' --dport '%s' -m iprange ! --src-range '%s' -j DROP",
            IPTABLES, m_gapinip, m_downplatport, m_upplatip);
    SIP_SYSTEM(chcmd);

    //本机发出的IP数据包都不再转换源地址
    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_gapinip);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s %s -j ACCEPT", IPTABLES, m_tmpip1);
    SIP_SYSTEM(chcmd);

    //去往对端的TCP转换源地址
    sprintf(chcmd, "%s -t nat -I POSTROUTING -d %s -p tcp --dport '%s' -j SNAT --to %s",
            IPTABLES, m_tmpip2, m_downplatport, m_tmpip1);
    SIP_SYSTEM(chcmd);

    //视频流的源地址转换为网闸接口IP
    sprintf(chcmd, "%s -t nat -I POSTROUTING -s %s -j SNAT --to '%s'",
            IPTABLES, m_tmpip2, m_gapinip);
    SIP_SYSTEM(chcmd);

    if (init() < 0) {
        PRINT_ERR_HEAD
        print_err("init error");
        return -1;
    }

    int sockudp1 = 0;
    int sockudp2 = 0;
    CBSUdpSockServer serudp1, serudp2;
    sockudp1 = serudp1.Open(m_gapinip, atoi(m_downplatport));
    if (sockudp1 < 0) {
        PRINT_ERR_HEAD
        print_err("UDP Socket1 is Busy![%s][%s]", m_downplatport, m_gapinip);
        return -1;
    }

    sockudp2 = serudp2.Open(m_tmpip1, atoi(m_upplatport));
    if (sockudp2 < 0) {
        PRINT_ERR_HEAD
        print_err("UDP Socket2 is Busy![%s][%s]", m_upplatport, m_tmpip1);
        close(sockudp1);
        return -1;
    }

    //---------------------------------------------------
    //接收上级平台UDP SIP数据的线程
    SOCKTASK *psock1 = new SOCKTASK();
    if (psock1 == NULL) {
        PRINT_ERR_HEAD
        print_err("new SOCKTASK error");
        return -1;
    }
    psock1->recvsock = sockudp1;
    psock1->sendsock = sockudp2;
    psock1->psip = this;
    pthread_t pid1 = 0;
    if (pthread_create(&pid1, NULL, clientInfoTask, psock1) != 0) {
        PRINT_ERR_HEAD
        print_err("pthread_create error");
        DELETE(psock1);
        return -1;
    }

    //---------------------------------------------------
    //接收下级平台UDP SIP数据的线程
    SOCKTASK *psock2 = new SOCKTASK();
    if (psock2 == NULL) {
        PRINT_ERR_HEAD
        print_err("new SOCKTASK error");
        return -1;
    }

    psock2->recvsock = sockudp2;
    psock2->sendsock = sockudp1;
    psock2->psip = this;
    pthread_t pid2 = 0;
    if (pthread_create(&pid2, NULL, serverInfoTask, psock2) != 0) {
        PRINT_ERR_HEAD
        print_err("pthread_create error");
        DELETE(psock2);
        return -1;
    }
    //---------------------------------------------------
    //接收上级平台TCP SIP数据的线程
    SOCKTASK *psock3 = new SOCKTASK();
    if (psock3 == NULL) {
        PRINT_ERR_HEAD
        print_err("new SOCKTASK error");
        return -1;
    }

    psock3->recvsock = -1;
    psock3->sendsock = -1;
    psock3->psip = this;
    psock3->flag = 1;
    pthread_t pid3 = 0;
    if (pthread_create(&pid3, NULL, TCPListenTask, psock3) != 0) {
        PRINT_ERR_HEAD
        print_err("pthread_create error");
        DELETE(psock3);
        return -1;
    }
    //---------------------------------------------------
    //接收下级平台TCP SIP数据的线程
    SOCKTASK *psock4 = new SOCKTASK();
    if (psock4 == NULL) {
        PRINT_ERR_HEAD
        print_err("new SOCKTASK error");
        return -1;
    }

    psock4->recvsock = -1;
    psock4->sendsock = -1;
    psock4->psip = this;
    psock4->flag = 2;
    pthread_t pid4 = 0;
    if (pthread_create(&pid4, NULL, TCPListenTask, psock4) != 0) {
        PRINT_ERR_HEAD
        print_err("pthread_create error");
        DELETE(psock4);
        return -1;
    }

    usleep(10000);
    return 0;
}

/**
 * [CSipBase::dstStart 网闸靠近下级平台的一端，起始函数]
 * @return [成功返回0]
 */
int CSipBase::dstStart()
{
    dstSipPrepare();
    return 0;
}

/**
 * [CSipBase::dstSipPrepare 网闸靠近下级平台的一端，SIP跳转准备]
 */
void CSipBase::dstSipPrepare()
{
    char chcmd[CMD_BUF_LEN] = {0};

    //上级先发包时的DNAT
    sprintf(chcmd, "%s -t nat -I PREROUTING -s %s -d %s -p udp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_tmpip1, m_tmpip2, m_downplatport, m_downplatip);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s %s -d %s -p tcp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_tmpip1, m_tmpip2, m_downplatport, m_downplatip);
    SIP_SYSTEM(chcmd);

    //下级先发包时的DNAT
    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p udp --dport '%s' -j DNAT --to %s",
            IPTABLES, m_downplatip, m_gapoutip, m_upplatport, m_tmpip1);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p tcp --dport '%s' -j DNAT --to %s",
            IPTABLES, m_downplatip, m_gapoutip, m_upplatport, m_tmpip1);
    SIP_SYSTEM(chcmd);

    //FORWARD
    sprintf(chcmd, "%s -I FORWARD -s %s -d '%s' -p udp --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, m_tmpip1, m_downplatip, m_upplatport, m_downplatport);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s %s -d '%s' -p tcp --dport '%s' -j ACCEPT",
            IPTABLES, m_tmpip1, m_downplatip, m_downplatport);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -I FORWARD -d %s -s '%s' -p udp --dport '%s' --sport '%s' -j ACCEPT",
            IPTABLES, m_tmpip1, m_downplatip, m_upplatport, m_downplatport);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -I FORWARD -d %s -s '%s' -p tcp --dport '%s' -j ACCEPT",
            IPTABLES, m_tmpip1, m_downplatip, m_upplatport);
    SIP_SYSTEM(chcmd);

    //POSTROUTING
    sprintf(chcmd,
            "%s -t nat -I POSTROUTING -s %s -d '%s' -p udp --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_tmpip1, m_downplatip, m_upplatport, m_downplatport, m_gapoutip);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s %s -d '%s' -p tcp --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_tmpip1, m_downplatip, m_downplatport, m_gapoutip);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d %s -p udp --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_downplatip, m_tmpip1, m_upplatport, m_tmpip2);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d %s -p tcp --dport '%s' -j SNAT --to %s",
            IPTABLES, m_downplatip, m_tmpip1, m_upplatport, m_tmpip2);
    SIP_SYSTEM(chcmd);
}

/**
 * [CSipBase::isProtoSIP 是否为SIP协议]
 * @return [是返回true]
 */
bool CSipBase::isProtoSIP()
{
    return (strcmp(m_proto, "SIP") == 0)
           || (strcmp(m_proto, "GB28181") == 0);
}

/**
 * [CSipBase::getCmd 从命令行中取出命令]
 * @param  chcmd   [取出的命令 出参]
 * @param  cmdsize [命令缓冲区大小 入参]
 * @param  cmdline [可能包含命令的数据包 入参]
 * @return         [取命令成功返回true，否则返回false]
 */
bool CSipBase::getCmd(char *chcmd, int cmdsize, const char *cmdline)
{
    //参数检查
    if ((chcmd == NULL) || (cmdline == NULL) || (cmdsize <= 4)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    //是回应
    char response[20] = "SIP/2.0";
    if (IS_TYPE_OF(cmdline, response)) {
        return false;
    }

    //xml行 没有命令
    if (cmdline[0] == '<') {
        return false;
    }

    memset(chcmd, 0, cmdsize);
    char *p = (char *)strchr(cmdline, ' ');
    if (p != NULL) {
        if ((p - cmdline) < cmdsize) {
            memcpy(chcmd, cmdline, p - cmdline);
        } else {
            memcpy(chcmd, cmdline, cmdsize - 4);
            strcat(chcmd, "...");
        }
    } else {
        if ((int)strlen(cmdline) < cmdsize) {
            strcpy(chcmd, cmdline);
        } else {
            memcpy(chcmd, cmdline, cmdsize - 4);
            strcat(chcmd, "...");
        }
    }

    //如果命令第一个字符不是字母，不记录日志
    if (!isalpha(chcmd[0])) {
        PRINT_DBG_HEAD
        print_dbg("cmd[0] is not alpha,cmd[%s]", chcmd);
        return false;
    }

    PRINT_DBG_HEAD
    print_dbg("find cmd[%s],pack len[%d]", chcmd, (int)strlen(cmdline));
    return true;
}

/**
 * [CSipBase::filterSipCmd 过滤信令]
 * @param  chcmd      [信令]
 * @param  fromUpplat [是否来自上级平台]
 * @return            [允许通过返回true]
 */
bool CSipBase::filterSipCmd(const char *chcmd, bool fromUpplat)
{
    if (chcmd == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    bool flag = m_ifexec;
    for (int i = 0; i < m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_cmd[i]->m_cmd) == 0) {
            flag = m_cmd[i]->m_action;
            break;
        }
    }
    recordCallLog(chcmd, flag, fromUpplat);
    return flag;
}

/**
 * [CSipBase::recordCallLog 记录访问日志]
 * @param chcmd      [信令]
 * @param result     [是否放行]
 * @param fromUpplat [是否来自上级平台]
 */
void CSipBase::recordCallLog(const char *chcmd, bool result, bool fromUpplat)
{
    if (g_iflog || g_syslog) {
        CallLogPara *p = new CallLogPara;
        if (p != NULL) {
            if (p->SetValues("", fromUpplat ? m_upplatip : m_downplatip,
                             fromUpplat ? m_downplatip : m_upplatip,
                             fromUpplat ? m_upplatport : m_downplatport,
                             fromUpplat ? m_downplatport : m_upplatport,
                             "", "",
                             getTypeDesc(), chcmd, "", result ? D_SUCCESS : D_REFUSE,
                             result ? "" : LOG_CONTENT_REFUSE)) {
                LogContainer &s1 = LogContainer::GetInstance();
                s1.PutPara(p);
            } else {
                PRINT_ERR_HEAD
                print_err("set values fail[sip %s, dip %s, sport %s, dport %s, %s:%s]",
                          fromUpplat ? m_upplatip : m_downplatip,
                          fromUpplat ? m_downplatip : m_upplatip,
                          fromUpplat ? m_upplatport : m_downplatport,
                          fromUpplat ? m_downplatport : m_upplatport,
                          getTypeDesc(), chcmd);
                delete p;
            }
        }
    }
    return;
}

/**
 * [CSipBase::recordSysLog 记录系统日志]
 * @param logtype [日志类型]
 * @param result  [结果]
 * @param remark  [备注信息]
 */
void CSipBase::recordSysLog(const char *logtype, const char *result, const char *remark)
{
    if ((logtype != NULL) && (result != NULL) && (remark != NULL)) {
        CLOGMANAGE mlog;
        if (mlog.Init() != E_OK) {
            PRINT_ERR_HEAD
            print_err("mlog init err");
            return ;
        }
        if (mlog.WriteSysLog(logtype, result, remark) != E_OK) {
            PRINT_ERR_HEAD
            print_err("WriteSysLog error[%s][%s][%s]", logtype, result, remark);
        }
        mlog.DisConnect();
    }
}

/**
 * [CSipBase::replaceCall 替换呼叫信令中的IP信息]
 * @param line [包含信令的一行信息]
 * 最常见的：
 *     INVITE sip:33078200001320000004@10.73.192.204:5511 SIP/2.0
 *     BYE sip:32011501001320000155@172.18.13.192:5060 SIP/2.0
 * 特殊情况:
 *     INVITE sip:10002@192.168.2.100;transport=UDP SIP/2.0
 *     INVITE sip:32011501001320000155@172.18.13.192 SIP/2.0
 * @param ip   [替换之后的IP]
 */
void CSipBase::replaceCall(char *line, const char *ip)
{
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *pat = index(line, '@');

    if (pat != NULL) {
        //把@以及之前的内容保存到tmpstr
        memcpy(tmpstr, line, pat - line + 1);
        //把替换后的IP追加到tmpstr
        strcat(tmpstr, ip);

        char *pcolon = index(pat, ':');
        if (pcolon != NULL) {
            //把冒号及之后的内容追加到变量
            strcat(tmpstr, pcolon);
            memset(line, 0x00, SIP_MAX_LINE_SIZE);
            memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
        } else {

            //处理特殊情况
            PRINT_DBG_HEAD
            print_dbg("not find :,[%s]", line);
            char *psem = index(pat, ';');
            if (psem != NULL) {
                strcat(tmpstr, psem);
                memset(line, 0x00, SIP_MAX_LINE_SIZE);
                memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
            } else {
                char *pspace = index(pat, ' ');
                if (pspace != NULL) {
                    strcat(tmpstr, pspace);
                    memset(line, 0x00, SIP_MAX_LINE_SIZE);
                    memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
                }
            }
        }
    } else {
        PRINT_DBG_HEAD
        print_dbg("not find @[%s]", line);
    }

    return ;
}

const char *CSipBase::getUpPlatIp()
{
    return m_upplatip;
}

const char *CSipBase::getDownPlatIp()
{
    return m_downplatip;
}

int CSipBase::getArea()
{
    return m_secway.getarea();
}

const char *CSipBase::getGapInIp()
{
    return m_gapinip;
}

const char *CSipBase::getGapOutIp()
{
    return m_gapoutip;
}

const char *CSipBase::getDownPlatPort()
{
    return m_downplatport;
}

/**
 * [CSipBase::setTmpIp2 为tmpip2赋值]
 * @param ip [description]
 */
bool CSipBase::setTmpIp2(const char *ip)
{
    if (ip != NULL) {
        if (strlen(ip) < sizeof(m_tmpip2)) {
            strcpy(m_tmpip2, ip);
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("ip[%s] too long ,sizeof(m_tmpip2) is %d", ip, (int)sizeof(m_tmpip2));
        }
    } else {
        PRINT_ERR_HEAD
        print_err("ip null");
    }
    return false;
}

/**
 * [CSipBase::setTmpIp1 为tmpip1赋值]
 * @param ip [description]
 */
bool CSipBase::setTmpIp1(const char *ip)
{
    if (ip != NULL) {
        if (strlen(ip) < sizeof(m_tmpip1)) {
            strcpy(m_tmpip1, ip);
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("ip[%s] too long ,sizeof(m_tmpip1) is %d", ip, (int)sizeof(m_tmpip1));
        }
    } else {
        PRINT_ERR_HEAD
        print_err("ip null");
    }
    return false;
}

/**
 * [CSipBase::swapGapIp 交换m_gapinip和m_gapoutip的内容]
 * 读取的配置文件中 m_gapinip为内网侧网闸IP，经swap后表示靠近上级平台一侧的网闸的IP
 * 读取的配置文件中 m_gapoutip为外网侧网闸IP，经swap后表示靠近下级平台一侧的网闸的IP
 */
void CSipBase::swapGapIp()
{
    char tmpip[IP_STR_LEN] = {0};
    strcpy(tmpip, m_gapinip);
    strcpy(m_gapinip, m_gapoutip);
    strcpy(m_gapoutip, tmpip);
}

/**
 * [CSipBase::getCallID 从一行内容中获取callid值]
 * @param  line      [一行内容，已经把Call-id偏移过去了]
 * @param  callidbuf [存放callid值的buf]
 * @param  buflen    [buf长度]
 * @return           [成功返回true]
 */
bool CSipBase::getCallID(const char *line, char *callidbuf, int buflen)
{
    int i = 0, j = 0;
    if ((line != NULL) && (callidbuf != NULL) && (buflen > 0)) {
        while ((line[i] != '\0') && (line[i] != '\r') && (j < buflen)) {
            if (line[i] == ' ' || line[i] == ':') {
                i++;
            } else {
                callidbuf[j++] = line[i++];
            }
        }
    }

    return (j > 0);
}

#ifdef RESEAL_SIP_INTERFACE
/**
 * [CSipBase::replaceContact 替换Contact字段]
 * @param line       [一行内容]
 * @param fromUpplat [是否由上级发出]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *    //Contact: <sip:2001$37060200081320000014@37.48.8.61:5060>\r\n
 */
void CSipBase::replaceContact(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};

    char *pat = index(recvstr + strlen(SIP_CONTACT_VALUE), '@');
    if (pat != NULL) {
        if (index(pat, ':') != NULL) {
            memcpy(tmpstr, recvstr, pat - recvstr + 1);
            strcat(tmpstr, sip_info->fromUpplat ? m_gapoutip : m_gapinip);
            strcat(tmpstr, index(pat, ':'));
            memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
            memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
        } else {

            PRINT_DBG_HEAD
            print_dbg("no find [:],[%s]", recvstr);

            //如果发现了@,没发现:,@后正好是X级平台IP,就替换下
            if (IS_TYPE_OF(pat + 1, sip_info->fromUpplat ? m_upplatip : m_downplatip)) {
                memcpy(tmpstr, recvstr, pat - recvstr + 1);
                strcat(tmpstr, sip_info->fromUpplat ? sip_info->m_gapoutip : m_gapinip);
                strcat(tmpstr, pat + 1 + strlen(sip_info->fromUpplat ? m_upplatip : m_downplatip));
                memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
                memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
            } else {
                PRINT_ERR_HEAD
                print_err("contact replace nothing[%s]", recvstr);
            }
        }
    } else {
        PRINT_DBG_HEAD
        print_dbg("contact not find @,[%s]", recvstr);

        //e.g  Contact: <sip:172.20.20.86:5061>
        char *p1 = index(recvstr + strlen(SIP_CONTACT_VALUE) + 1, ':');
        if (p1 != NULL) {
            char *p2 = index(p1 + 1, ':');
            if (p2 != NULL) {
                memcpy(tmpstr, recvstr, p1 - recvstr + 1);
                strcat(tmpstr, sip_info->fromUpplat ? m_gapoutip : m_gapinip);
                strcat(tmpstr, p2);
                memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
                memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
            }
        }
    }
}

/**
 * [CSipBase::replaceContentLen 替换Content-Length字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *  Content-Length:1114\r\n
 *  Content-Length: 1114\r\n
 *  Content-Length : 1114\r\n
 */
void CSipBase::replaceContentLen(char *line, struct SIP_INFO *sip_info)
{
    int contlen_offset = 0;

    if ((line == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    contlen_offset = strlen(SIP_CONTENTLEN_VALUE);
    while ((*(line + contlen_offset) == ' ')
           || (*(line + contlen_offset) == ':')) {
        contlen_offset++;
    }

    sip_info->contlen = atoi(line + contlen_offset);
    if (sip_info->contlen) {
        sprintf(line, "%s: %s", SIP_CONTENTLEN_VALUE, "%d\r\n");
    } else {
        PRINT_DBG_HEAD
        print_dbg("not replcae content_len, [%s]", line);
    }

}

/**
 * [CSipBase::replaceCinip6 替换c=IN IP6字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 */
void CSipBase::replaceCinip6(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *p = index(recvstr, '\r');
    if (p != NULL) {
        memcpy(sip_info->ctmpip, recvstr + strlen(SIP_CINIP6_VALUE),
               (strlen(recvstr) - strlen(SIP_CINIP6_VALUE) - strlen(p)));
        memcpy(tmpstr, recvstr, strlen(SIP_CINIP6_VALUE));
        strcat(tmpstr, sip_info->fromUpplat ? getChannelProxyIP(sip_info->callid_str) : getChannelOutIP(sip_info->callid_str));
        strcat(tmpstr, "\r\n");
        sip_info->contlen += strlen(tmpstr) - strlen(recvstr);
        memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
        memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
    } else {
        PRINT_ERR_HEAD
        print_err("not fine CINIP6[\\r],[%s]", recvstr);
    }

}

/**
 * [CSipBase::replaceCinip4 替换c=IN IP4字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *    //c=IN IP4 37.48.8.38\r\n
 */
void CSipBase::replaceCinip4(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *p = index(recvstr, '\r');
    if (p != NULL) {
        memcpy(sip_info->ctmpip, recvstr + strlen(SIP_CINIP4_VALUE),
               (strlen(recvstr) - strlen(SIP_CINIP4_VALUE) - strlen(p)));
        memcpy(tmpstr, recvstr, strlen(SIP_CINIP4_VALUE));
        strcat(tmpstr, sip_info->fromUpplat ? getChannelProxyIP(sip_info->callid_str) : getChannelOutIP(sip_info->callid_str));
        strcat(tmpstr, "\r\n");
        sip_info->contlen += strlen(tmpstr) - strlen(recvstr);
        memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
        memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
    } else {
        PRINT_ERR_HEAD
        print_err("not fine CINIP4 [\\r],[%s]", recvstr);
    }

}

/**
 * [CSipBase::replaceOinip4 替换o=字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *    //o=H3C 0 0 IN IP4 37.48.8.38\r\n
 */
void CSipBase::replaceOinip4(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};

    char *ptr = strstr(recvstr, "IN IP4 ");
    if (ptr != NULL) {
        //IP之前的内容拷贝到tmpstr
        memcpy(tmpstr, recvstr, ptr - recvstr + strlen("IN IP4 "));
        strcat(tmpstr, sip_info->fromUpplat ? getChannelProxyIP(sip_info->callid_str) : getChannelOutIP(sip_info->callid_str));
        strcat(tmpstr, "\r\n");
        sip_info->contlen += strlen(tmpstr) - strlen(recvstr);
        memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
        memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
    } else {
        PRINT_ERR_HEAD
        print_err("not fine OINIP,[%s]", recvstr);
    }

}

/**
 * [CSipBase::replaceMaudio 替换m=audio字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *    //m=audio 63545 udp 105\r\n
 */
void CSipBase::replaceMaudio(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    sip_info->contlen -= strlen(recvstr);
    regStatusReq(recvstr, sip_info->ctmpip, false, sip_info->callid_str);
    sip_info->contlen += strlen(recvstr);
}

/**
 * [CSipBase::replaceMvedio 替换m=vedio字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *    //m=video 63544 udp 105\r\n
 */
void CSipBase::replaceMvedio(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    sip_info->contlen -= strlen(recvstr);
    regStatusReq(recvstr, sip_info->ctmpip, true, sip_info->callid_str);
    sip_info->contlen += strlen(recvstr);
}

/**
 * [CSipReplaceInterface::replaceFrom 替换from字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 */
void CSipReplaceInterface::replaceFrom(char *line, struct SIP_INFO *sip_info)
{
    if ((line == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return ;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *pat = index(line + strlen(SIP_FROM_VALUE), '@');
    if (pat != NULL) {
        if (index(pat, ':') != NULL) {
            memcpy(tmpstr, line, pat - line + 1);
            strcat(tmpstr, sip_info->fromUpplat ? sip_info->m_gapoutip : sip_info->m_gapinip);
            strcat(tmpstr, index(line + strlen(SIP_FROM_VALUE) + 20, ':'));
            memset(line, 0x00, SIP_MAX_LINE_SIZE);
            memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
        } else {
            PRINT_DBG_HEAD
            print_dbg("not find colon[%s]", line);
            //如果发现了@,没发现:
            if (sip_info->fromUpplat && (memcmp(pat + 1, sip_info->m_upplatip, strlen(sip_info->m_upplatip)) == 0)) {
                memcpy(tmpstr, line, pat - line + 1);
                strcat(tmpstr, sip_info->m_gapoutip);
                strcat(tmpstr, pat + 1 + strlen(sip_info->m_upplatip));
                memset(line, 0x00, SIP_MAX_LINE_SIZE);
                memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
            } else if (!sip_info->fromUpplat && (memcmp(pat + 1, sip_info->m_downplatip, strlen(sip_info->m_downplatip)) == 0)) {
                memcpy(tmpstr, line, pat - line + 1);
                strcat(tmpstr, sip_info->m_gapinip);
                strcat(tmpstr, pat + 1 + strlen(sip_info->m_downplatip));
                memset(line, 0x00, SIP_MAX_LINE_SIZE);
                memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
            }
        }
    }
}

/**
 * [CSipReplaceInterface::replaceTo 替换to字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 */
void CSipReplaceInterface::replaceTo(char *line, struct SIP_INFO *sip_info)
{
    if ((line == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *pat = index(line + strlen(SIP_TO_VALUE), '@');
    if (pat != NULL) {
        if (index(pat, ':') != NULL) {
            memcpy(tmpstr, line, pat - line + 1);
            strcat(tmpstr, sip_info->fromUpplat ? sip_info->m_downplatip : sip_info->m_upplatip);
            strcat(tmpstr, index(line + strlen(SIP_TO_VALUE) + 20, ':'));
            memset(line, 0x00, SIP_MAX_LINE_SIZE);
            memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
        } else {
            PRINT_DBG_HEAD
            print_dbg("not find colon[%s]", line);
            //如果发现了@,没发现:
            if (sip_info->fromUpplat && (memcmp(pat + 1, sip_info->m_gapinip, strlen(sip_info->m_gapinip)) == 0)) {
                memcpy(tmpstr, line, pat - line + 1);
                strcat(tmpstr, sip_info->m_downplatip);
                strcat(tmpstr, pat + 1 + strlen(sip_info->m_gapinip));
                memset(line, 0x00, SIP_MAX_LINE_SIZE);
                memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
            } else if (!sip_info->fromUpplat && (memcmp(pat + 1, sip_info->m_gapoutip, strlen(sip_info->m_gapoutip)) == 0)) {
                memcpy(tmpstr, line, pat - line + 1);
                strcat(tmpstr, sip_info->m_upplatip);
                strcat(tmpstr, pat + 1 + strlen(sip_info->m_gapoutip));
                memset(line, 0x00, SIP_MAX_LINE_SIZE);
                memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
            }
        }
    }
}



/**
 * [CSipReplaceInterface::replaceVia 替换VIA字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *    //Via: SIP/2.0/UDP 20.95.4.103:6689;branch=z9hG4bK108764931853145314531420180523110753
 *    //Via:SIP/2.0/UDP 20.95.4.103:6689;branch=z9hG4bK108764931853145314531420180523110753
 */
void CSipReplaceInterface::replaceVia(char *line, struct SIP_INFO *sip_info)
{
    if ((line == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};

    char *psip20 = strstr(line, "SIP/2.0/");
    if (psip20 != NULL) {
        char *pcolon = index(psip20, ':');
        if (pcolon != NULL) {
            memcpy(tmpstr, line, psip20 - line + strlen("SIP/2.0/UDP "));
            strcat(tmpstr, sip_info->fromUpplat ? sip_info->m_gapoutip : sip_info->m_gapinip);
            strcat(tmpstr, pcolon);
            memset(line, 0x00, SIP_MAX_LINE_SIZE);
            memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
        } else {
            PRINT_ERR_HEAD
            print_err("Via not fine [:], [%s]", line);
        }

    } else {
        PRINT_ERR_HEAD
        print_err("Via not find [SIP/2.0/UDP ], [%s]", line);
    }
}

/**
 * [CSipVendorsHandleInterface::handleHikvision 处理海康所必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleHikvision(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    switch (sip_info->key_flag) {
    case SIP_VIA_KEY:
        replaceInterface.replaceVia(recvstr, sip_info);
        break;
    case SIP_FROM_KEY:
        replaceInterface.replaceFrom(recvstr, sip_info);
        break;
    case SIP_TO_KEY:
        replaceInterface.replaceTo(recvstr, sip_info);
        break;
    default:
        break;
    }

    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleDahua 处理大华所必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleDahua(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleH3c 处理华3所必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleH3c(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}


/**
 * [CSipVendorsHandleInterface::handleHuawei 处理华为所必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleHuawei(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}

/**
 * [CSipVendorsHandleInterface::handlePublic 处理公安一所必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handlePublic(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleTiandy 处理天地伟业所必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleTiandy(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleTsd 处理天视达必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleTsd(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleUniview 处理宇视必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleUniview(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    switch (sip_info->key_flag) {
    case SIP_VIA_KEY:
        replaceInterface.replaceVia(recvstr, sip_info);
        break;
    default:
        break;
    }

    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleKedacom 处理科达必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleKedacom(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    switch (sip_info->key_flag) {
    case SIP_VIA_KEY:
        replaceInterface.replaceVia(recvstr, sip_info);
        break;
    default:
        break;
    }

    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleSumavision 处理数码视讯所必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleSumavision(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleSharpwisdom 处理藏愚必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleSharpwisdom(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleUnimas 处理合众必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleUnimas(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleHanbanggaoke 处理汉邦高科所必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字的转换和标志]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleHanbanggaoke(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleDongfang 处理东方电子必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleDongfang(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    switch (sip_info->key_flag) {
    case SIP_VIA_KEY:
        replaceInterface.replaceVia(recvstr, sip_info);
        break;
    case SIP_FROM_KEY:
        replaceInterface.replaceFrom(recvstr, sip_info);
        break;
    case SIP_TO_KEY:
        replaceInterface.replaceTo(recvstr, sip_info);
        break;
    default:
        break;
    }

    return 0;
}

/**
 * [CSipVendorsHandleInterface::handleVitechViss 处理中兴必需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字的转换和标志]
 * @return            [0位正确，出错为负值]
 */
int CSipVendorsHandleInterface::handleVitechViss(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }
    return 0;
}


/**
 * [CSipBase::handleDiffVendors 处理不同厂家所需替换的sip信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [true位正确，出错为false]
 */
bool CSipBase::handleDiffVendors(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    switch (m_brandID) {
    case ID_HIKVISION:
        handelInterface.handleHikvision(recvstr, sip_info);
        break;
    case ID_DAHUA_GROUP:
        handelInterface.handleDahua(recvstr, sip_info);
        break;
    case ID_H3C:
        handelInterface.handleH3c(recvstr, sip_info);
        break;
    case ID_HUAWEI:
        handelInterface.handleHuawei(recvstr, sip_info);
        break;
    case ID_PUBLIC_SECURITY:
        handelInterface.handlePublic(recvstr, sip_info);
        break;
    case ID_TIANDY:
        handelInterface.handleTiandy(recvstr, sip_info);
        break;
    case ID_TSD:
        handelInterface.handleTsd(recvstr, sip_info);
        break;
    case ID_UNIVIEW:
        handelInterface.handleUniview(recvstr, sip_info);
        break;
    case ID_KEDACOM:
        handelInterface.handleKedacom(recvstr, sip_info);
        break;
    case ID_SUMAVISION:
        handelInterface.handleSumavision(recvstr, sip_info);
        break;
    case ID_SHARPWISDOM:
        handelInterface.handleSharpwisdom(recvstr, sip_info);
        break;
    case ID_UNIMAS:
        handelInterface.handleUnimas(recvstr, sip_info);
        break;
    case ID_HANBANGGAOKE:
        handelInterface.handleHanbanggaoke(recvstr, sip_info);
        break;
    case ID_DONGFANG:
        handelInterface.handleDongfang(recvstr, sip_info);
        break;
    case ID_VITECH_VISS:
        handelInterface.handleVitechViss(recvstr, sip_info);
        break;
    case ID_NETPOSA:
        break;
    case ID_SOYUAN:
        break;
    case ID_ALI:
        break;
    default:
        break;
    }

    return true;
}

/**
 * [CSipBase::replaceSipReqInfo 替换SIP请求的IP等信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  dst        [替换之后的数据包]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [正常返回recvstr长度，出错为负值]
 */
int CSipBase::replaceSipReqInfo(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    switch (sip_info->key_flag) {
    case SIP_BYE_KEY:
        sip_info->b_bye = true;
        replaceCall(recvstr, sip_info->m_downplatip);
        break;
    case SIP_INVITE_KEY:
    case SIP_ACK_KEY:
    case SIP_UPDATE_KEY:
    case SIP_PRACK_KEY:
    case SIP_CANCEL_KEY:
        replaceCall(recvstr, sip_info->m_downplatip);
        break;
    case SIP_CONTACT_KEY:
        replaceContact(recvstr, sip_info);
        break;
    case SIP_CINIP4_KEY:
        replaceCinip4(recvstr, sip_info);
        break;
    case SIP_OINIP4_KEY://不必须替换
        replaceOinip4(recvstr, sip_info);
        break;
    case SIP_MVIDEO_KEY:
        replaceMvedio(recvstr, sip_info);
        break;
    case SIP_MAUDIO_KEY:
        replaceMaudio(recvstr, sip_info);
        break;
    case SIP_CONTENTLEN_KEY:
        replaceContentLen(recvstr, sip_info);
        break;
    case SIP_CALLID_KEY:
        if (getCallID(recvstr + strlen(SIP_CALLID_VALUE), sip_info->callid_str, sizeof(sip_info->callid_str))) {
            if (sip_info->b_bye) {
                delChannelByCallID(sip_info->callid_str);//多态
            }
        }
        break;
    case SIP_VIA_KEY:
    case SIP_FROM_KEY:
    case SIP_TO_KEY:
        handleDiffVendors(recvstr, sip_info);
        break;
    default:
        break;
    }

    return strlen(recvstr);
}

/**
 * [CSipBase::replaceSipReqInfo 替换SIP响应包的IP等信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  dst        [替换之后的数据包]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [正常返回recvstr长度，出错为负值]
 */
int CSipBase::replaceSipResInfo(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    switch (sip_info->key_flag) {
    case SIP_BYE_KEY:
        sip_info->b_bye = true;
        replaceCall(recvstr, sip_info->m_upplatip);
        break;
    case SIP_CONTACT_KEY:
        replaceContact(recvstr, sip_info);
        break;
    case SIP_CINIP4_KEY:
        replaceCinip4(recvstr, sip_info);
        break;
    case SIP_CINIP6_KEY:
        replaceCinip6(recvstr, sip_info);
        break;
    case SIP_OINIP4_KEY://不必须替换
        replaceOinip4(recvstr, sip_info);
        break;
    case SIP_CONTENTLEN_KEY:
        replaceContentLen(recvstr, sip_info);
        break;
    case SIP_NOTIFY_KEY:
        replaceCall(recvstr, sip_info->m_upplatip);
        break;
    case SIP_CALLID_KEY:
        if (getCallID(recvstr + strlen(SIP_CALLID_VALUE), sip_info->callid_str, sizeof(sip_info->callid_str))) {
            if (sip_info->b_bye) {
                delChannelByCallID(sip_info->callid_str);//多态
            }
        }
        break;
    case SIP_VIA_KEY:
    case SIP_FROM_KEY:
    case SIP_TO_KEY:
        handleDiffVendors(recvstr, sip_info);
        break;
    default:
        break;
    }

    return strlen(recvstr);
}

/**
 * [CSipBase::sipKeywordHandle 将sip每行的关键字标志转换为数字]
 * @param  recvstr        [需要被替换的数据包]
 * @param sip_info        [包含SIP报文每行关键字标志和IP信息]
 * @return                [返回空值]
 */
void CSipBase::sipKeywordHandle(const char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    if (IS_TYPE_OF(recvstr, SIP_INVITE_VALUE)) {
        sip_info->key_flag = SIP_INVITE_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_UPDATE_VALUE)) {
        sip_info->key_flag = SIP_UPDATE_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_ACK_VALUE)) {
        sip_info->key_flag = SIP_ACK_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_PRACK_VALUE)) {
        sip_info->key_flag = SIP_PRACK_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_BYE_VALUE)) {
        sip_info->key_flag = SIP_BYE_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_REGISTER_VALUE)) {
        sip_info->key_flag = SIP_REGISTER_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CANCEL_VALUE)) {
        sip_info->key_flag = SIP_CANCEL_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_VIA_VALUE)) {
        sip_info->key_flag = SIP_VIA_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CONTACT_VALUE)) {
        sip_info->key_flag = SIP_CONTACT_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_OINIP4_VALUE)) {
        sip_info->key_flag = SIP_OINIP4_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CINIP4_VALUE)) {
        sip_info->key_flag = SIP_CINIP4_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CINIP6_VALUE)) {
        sip_info->key_flag = SIP_CINIP6_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CONTENTLEN_VALUE)) {
        sip_info->key_flag = SIP_CONTENTLEN_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_VIDEO_VALUE)) {
        sip_info->key_flag = SIP_MVIDEO_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_AUDIO_VALUE)) {
        sip_info->key_flag = SIP_MAUDIO_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CALLID_VALUE)) {
        sip_info->key_flag = SIP_CALLID_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_FROM_VALUE)) {
        sip_info->key_flag = SIP_FROM_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_TO_VALUE)) {
        sip_info->key_flag = SIP_TO_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_NOTIFY_VALUE)) {
        sip_info->key_flag = SIP_NOTIFY_KEY;
    }
    return;
}

/**
 * [CSipBase::replaceClientInfo 替换来自上级平台的请求应用层中的IP等信息]
 * @param  src        [需要被替换的数据包]
 * @param  ilen       [src的长度]
 * @param  dst        [替换之后的数据包]
 * @return            [正确情况下为dst的长度 出错返回负值]
 */
int CSipBase::replaceClientInfo(const char *src, int ilen, char *dst)
{
    PRINT_DBG_HEAD
    print_dbg("replace SIP Client info begin ...src info [%s]\n", src);

    if ((src == NULL) || (ilen < 0) || (dst == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    int ipos = 0;
    int res = 0;
    int dstlen = 0;
    char recvstr[SIP_MAX_LINE_SIZE] = {0};
    char tmpdst[SIP_MAX_PACKET] = {0};
    char chcmd[C_SIP_KEY_WORLD_LEN] = {0};
    struct SIP_INFO sip_info;
    char *p = NULL;

    memset(&sip_info, 0x00, sizeof(struct SIP_INFO));
    sip_info.fromUpplat = true;
    sip_info.m_downplatip = m_downplatip;
    sip_info.m_upplatip = m_upplatip;
    sip_info.m_gapinip = m_gapinip;
    sip_info.m_gapoutip = m_gapoutip;

    //过滤命令，取SIP请求命令并记日志
    if (getCmd(chcmd, C_SIP_KEY_WORLD_LEN, src)) {
        if (!filterSipCmd(chcmd, true)) {
            PRINT_ERR_HEAD
            print_err("filterSipCmd fail");
            return -1;
        }
    }

    //将收到的SIP报文分行并处理
    while (1) {
        BZERO(recvstr);
        res = findStrByKey(src, recvstr, ipos, '\n');
        if (res == -1) {
            //未找到\n,也要把内容写入
            memcpy(tmpdst + dstlen, recvstr, strlen(recvstr));
            dstlen += (int)strlen(recvstr);
            break;
        }

        ipos = res;
        sip_info.key_flag = 0;

        //每行关键字段匹配转换标志
        sipKeywordHandle(recvstr, &sip_info);

        //替换请求
        res = replaceSipReqInfo(recvstr, &sip_info);
        if (res < 0) {
            PRINT_ERR_HEAD
            print_err("error res replaceSipReqInfo [%d]\n", res);
            return -1;
        }

        //替换后的行写入dst
        memcpy(tmpdst + dstlen, recvstr, res);
        dstlen += res;
    }

    //将替换后的SDP长度写入，否则SIP会报错
    if (sip_info.contlen) {
        BZERO(recvstr);
        p = strstr(tmpdst, "\r\n\r\n");
        if (NULL != p) {
            memcpy(recvstr, tmpdst, p - tmpdst);
            sprintf(dst, recvstr, sip_info.contlen);
            strcat(dst, p);
        } else {
            sprintf(dst, tmpdst, sip_info.contlen);
        }
    } else {
        memcpy(dst, tmpdst, dstlen);
    }

    //当数据包包含0x00时，0x00之后的内容原封转发
    dstlen = strlen(dst);
    int srclen = (int)strlen(src);
    if (srclen < ilen) {
        memcpy(dst + dstlen, src + srclen, ilen - srclen);
        dstlen += ilen - srclen;
    }

    PRINT_DBG_HEAD
    print_dbg("replace SIP Client info over ...dst info [%s]\n", dst);

    return dstlen;
}

/**
 * [CSipBase::replaceServerInfo 替换来自下级平台的请求应用层中的IP等信息]
 * @param  src        [需要被替换的数据包]
 * @param  ilen       [src的长度]
 * @param  dst        [替换之后的数据包]
 * @return            [正确情况下为dst的长度 出错返回负值]
 */
int CSipBase::replaceServerInfo(const char *src, int ilen, char *dst)
{
    PRINT_DBG_HEAD
    print_dbg("replace SIP server info begin ...info src [%s]\n", src);

    if ((src == NULL) || (ilen < 0) || (dst == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    int ipos = 0;
    int res = 0;
    int dstlen = 0;
    char recvstr[SIP_MAX_LINE_SIZE] = {0};
    char chcmd[C_SIP_KEY_WORLD_LEN] = {0};
    char tmpdst[SIP_MAX_PACKET] = {0};
    struct SIP_INFO sip_info;
    char *p = NULL;

    memset(&sip_info, 0x00, sizeof(struct SIP_INFO));
    sip_info.m_downplatip = m_downplatip;
    sip_info.m_upplatip = m_upplatip;
    sip_info.m_gapinip = m_gapinip;
    sip_info.m_gapoutip = m_gapoutip;

    //过滤命令，取SIP请求命令并记日志
    if (getCmd(chcmd, C_SIP_KEY_WORLD_LEN, src)) {
        if (!filterSipCmd(chcmd, false)) {
            PRINT_ERR_HEAD
            print_err("filterSipCmd fail");
            return -1;
        }
    }

    //将收到的SIP报文按行处理
    while (1) {
        BZERO(recvstr);
        res = findStrByKey(src, recvstr, ipos, '\n');
        if (res == -1) {
            //未找到\n,也要把内容写入
            memcpy(tmpdst + dstlen, recvstr, strlen(recvstr));
            dstlen += (int)strlen(recvstr);
            break;
        }

        ipos = res;
        sip_info.key_flag = 0;

        //每行关键字段匹配转换标志
        sipKeywordHandle(recvstr, &sip_info);

        //替换响应
        res = replaceSipResInfo(recvstr, &sip_info);
        if (res < 0) {
            PRINT_ERR_HEAD
            print_err("error res replaceSipResInfo [%d]\n", res);
            return -1;
        }
        //替换后的行写入dst
        memcpy(tmpdst + dstlen, recvstr, res);
        dstlen += res;
    }

    //将替换后的SDP长度写入，否则SIP会报错
    if (sip_info.contlen) {
        BZERO(recvstr);
        p = strstr(tmpdst, "\r\n\r\n");
        if (NULL != p) {
            memcpy(recvstr, tmpdst, p - tmpdst);
            sprintf(dst, recvstr, sip_info.contlen);
            strcat(dst, p);
        } else {
            sprintf(dst, tmpdst, sip_info.contlen);
        }
    } else {
        memcpy(dst, tmpdst, dstlen);
    }

    //当数据包包含0x00时，0x00之后的内容原封转发
    dstlen = strlen(dst);
    int srclen = (int)strlen(src);
    if (srclen < ilen) {
        memcpy(dst + dstlen, src + srclen, ilen - srclen);
        dstlen += ilen - srclen;
    }

    PRINT_DBG_HEAD
    print_dbg("replace SIP server info over ...dst [%s]\n", dst);

    return dstlen;
}


#else
/**
 * [CSipBase::replaceFrom 替换from字段]
 * @param line       [一行内容]
 * @param fromUpplat [是否由上级发出]
 */
void CSipBase::replaceFrom(char *line, bool fromUpplat)
{
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char FROM[20] = "From:";

    char *pat = index(line + strlen(FROM), '@');
    if (pat != NULL) {
        if (index(pat, ':') != NULL) {
            strncpy(tmpstr, line, pat - line + 1);
            strcat(tmpstr, fromUpplat ? m_gapoutip : m_gapinip);
            strcat(tmpstr, index(line + strlen(FROM) + 20, ':'));
            strcpy(line, tmpstr);
        } else {
            PRINT_DBG_HEAD
            print_dbg("not find colon[%s]", line);
            //如果发现了@,没发现:
            if (memcmp(pat + 1, fromUpplat ? m_upplatip : m_downplatip,
                       strlen(fromUpplat ? m_upplatip : m_downplatip)) == 0) {
                strncpy(tmpstr, line, pat - line + 1);
                strcat(tmpstr, fromUpplat ? m_gapoutip : m_gapinip);
                strcat(tmpstr, pat + 1 + strlen(fromUpplat ? m_upplatip : m_downplatip));
                strcpy(line, tmpstr);
            }
        }
    }
}

/**
 * [CSipBase::replaceTo 替换to字段]
 * @param line       [一行内容]
 * @param fromUpplat [是否由上级发出]
 */
void CSipBase::replaceTo(char *line, bool fromUpplat)
{
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char TO[20] = "To:";

    char *pat = index(line + strlen(TO), '@');
    if (pat != NULL) {
        if (index(pat, ':') != NULL) {
            strncpy(tmpstr, line, pat - line + 1);
            strcat(tmpstr, fromUpplat ? m_downplatip : m_upplatip);
            strcat(tmpstr, index(line + strlen(TO) + 20, ':'));
            strcpy(line, tmpstr);
        } else {
            PRINT_DBG_HEAD
            print_dbg("not find colon[%s]", line);
            //如果发现了@,没发现:
            if (memcmp(pat + 1, fromUpplat ? m_gapinip : m_gapoutip,
                       strlen(fromUpplat ? m_gapinip : m_gapoutip)) == 0) {
                strncpy(tmpstr, line, pat - line + 1);
                strcat(tmpstr, fromUpplat ? m_downplatip : m_upplatip);
                strcat(tmpstr, pat + 1 + strlen(fromUpplat ? m_gapinip : m_gapoutip));
                strcpy(line, tmpstr);
            }
        }
    }
}

/**
 * [CSipBase::replaceInfo 替换应用层中的IP等信息]
 * @param  src        [需要被替换的数据包]
 * @param  ilen       [src的长度]
 * @param  dst        [替换之后的数据包]
 * @param  fromUpplat [是否为上级发给下级的]
 * @return            [正确情况下为dst的长度 出错返回负值]
 */
int CSipBase::replaceInfo(const char *src, int ilen, char *dst, bool fromUpplat)
{
    PRINT_DBG_HEAD
    print_dbg("replace SIP info begin ...info len[%s]", src);

    if ((src == NULL) || (ilen < 0) || (dst == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    //取命令
    char chcmd[24] = {0};
    if (getCmd(chcmd, sizeof(chcmd), src)) {
        if (!filterSipCmd(chcmd, fromUpplat)) {
            PRINT_ERR_HEAD
            print_err("filterSipCmd fail");
            return -1;
        }
    }

    char INVITE[10] = "INVITE";
    char UPDATE[10] = "UPDATE";
    char ACK[10] = "ACK";
    char PRACK[10] = "PRACK";
    char BYE[10] = "BYE";
    char REGISTER[10] = "REGISTER";
    char CANCEL[10] = "CANCEL";
    char VIA[20] = "via";
    char SIP20UDP[20] = "SIP/2.0/UDP ";
    char CONTACT[20] = "CONTACT:";
    char OINIP4[10] = "IN IP4 ";
    char INIPV4[10] = "c=IN IP4 ";
    char CONTENTLEN[20] = "Content-Length";
    char MVIDEO[20] = "m=video ";
    char MAUDIO[20] = "m=audio ";
    char STATUS[20] = "SIP/2.0 ";
    char CALLID[20] = "Call-ID";
    char FROM[20] = "From:";
    char TO[20] = "To:";

    int contlen = 0;
    int contlenid = -1;
    int contlen_offset = 0;//Content-Length中的数字，相对行首的偏移量
    bool b_invite = false;
    char ctmpip[20] = {0};
    int part = 0;
    int ipos = 0;
    int res = 0;
    char *recvstr[SIP_MAX_LINE_NUM];
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char callid_str[SIP_CALL_ID_LEN] = {0};

    while (1) {
        recvstr[part] = new char[SIP_MAX_LINE_SIZE];
        if (recvstr[part] == NULL) {
            PRINT_ERR_HEAD
            print_err("new char fail");
            usleep(100000);
            continue;
        }
        memset(recvstr[part], 0, SIP_MAX_LINE_SIZE);
        BZERO(tmpstr);
        res = findStrByKey(src, tmpstr, ipos, '\n');
        strcpy(recvstr[part], tmpstr);
        part++;
        if (res == -1) {
            break;
        }
        ipos = res;
        if (part >= SIP_MAX_LINE_NUM) {
            PRINT_ERR_HEAD
            print_err("part[%d] should be less than %d", part, SIP_MAX_LINE_NUM);
            break;
        }
    }

    for (int i = 0; i < part; i++) {

        BZERO(tmpstr);
        if (IS_TYPE_OF(recvstr[i], REGISTER)) {

        } else if (IS_TYPE_OF(recvstr[i], INVITE)
                   || IS_TYPE_OF(recvstr[i], ACK)
                   || IS_TYPE_OF(recvstr[i], BYE)
                   || IS_TYPE_OF(recvstr[i], CANCEL)
                   || IS_TYPE_OF(recvstr[i], UPDATE)
                   || IS_TYPE_OF(recvstr[i], PRACK)) {
            if (IS_TYPE_OF(recvstr[0], INVITE)) {
                b_invite = true;
            }
            replaceCall(recvstr[i], fromUpplat ? m_downplatip : m_upplatip);

        } else if (IS_TYPE_OF(recvstr[i], CONTACT)) {
            //Contact: <sip:2001$37060200081320000014@37.48.8.61:5060>\r\n
            char *pat = index(recvstr[i] + strlen(CONTACT), '@');
            if (pat != NULL) {
                if (index(pat, ':') != NULL) {
                    strncpy(tmpstr, recvstr[i], pat - recvstr[i] + 1);
                    strcat(tmpstr, fromUpplat ? m_gapoutip : m_gapinip);
                    strcat(tmpstr, index(pat, ':'));
                    strcpy(recvstr[i], tmpstr);
                } else {

                    PRINT_DBG_HEAD
                    print_dbg("no find [:],[%s]", recvstr[i]);

                    //如果发现了@,没发现:,@后正好是X级平台IP,就替换下
                    if (IS_TYPE_OF(pat + 1, fromUpplat ? m_upplatip : m_downplatip)) {
                        strncpy(tmpstr, recvstr[i], pat - recvstr[i] + 1);
                        strcat(tmpstr, fromUpplat ? m_gapoutip : m_gapinip);
                        strcat(tmpstr, pat + 1 + strlen(fromUpplat ? m_upplatip : m_downplatip));
                        strcpy(recvstr[i], tmpstr);
                    } else {
                        PRINT_ERR_HEAD
                        print_err("contact replace nothing[%s]", recvstr[i]);
                    }
                }
            } else {
                PRINT_DBG_HEAD
                print_dbg("contact not find @,[%s]", recvstr[i]);

                //e.g  Contact: <sip:172.20.20.86:5061>
                char *p1 = index(recvstr[i] + strlen(CONTACT) + 1, ':');
                if (p1 != NULL) {
                    char *p2 = index(p1 + 1, ':');
                    if (p2 != NULL) {
                        strncpy(tmpstr, recvstr[i], p1 - recvstr[i] + 1);
                        strcat(tmpstr, fromUpplat ? m_gapoutip : m_gapinip);
                        strcat(tmpstr, p2);
                        strcpy(recvstr[i], tmpstr);
                    }
                }
            }
        } else if (IS_TYPE_OF(recvstr[i], VIA)) {
            //Via: SIP/2.0/UDP 20.95.4.103:6689;branch=z9hG4bK108764931853145314531420180523110753
            //Via:SIP/2.0/UDP 20.95.4.103:6689;branch=z9hG4bK108764931853145314531420180523110753
            if (needReplaceVIA()) {
                if (IS_TYPE_OF(recvstr[0], STATUS)) {
                    continue;
                }

                char *psip20udp = strstr(recvstr[i], SIP20UDP);
                if (psip20udp == NULL) {
                    PRINT_ERR_HEAD
                    print_err("not find SIP20UDP[%s]", recvstr[i]);
                    continue;
                }

                char *pcolon = index(psip20udp, ':');
                if (pcolon == NULL) {
                    PRINT_ERR_HEAD
                    print_err("not fine :,[%s]", recvstr[i]);
                    continue;
                }
                strncpy(tmpstr, recvstr[i], psip20udp - recvstr[i] + strlen(SIP20UDP));
                strcat(tmpstr, fromUpplat ? m_gapoutip : m_gapinip);
                strcat(tmpstr, pcolon);
                strcpy(recvstr[i], tmpstr);
            }
        } else if (IS_TYPE_OF(recvstr[i], FROM)) {
            //From: <sip:3706000000200000004@37.51.128.2:5060>;tag=e937aa50
            if (needReplaceFromTo() && (strncasecmp(recvstr[0], STATUS, strlen(STATUS)) != 0)) {
                replaceFrom(recvstr[i], fromUpplat);
            }
        } else if (IS_TYPE_OF(recvstr[i], TO)) {
            //To: <sip:37068500002000000004@37.51.128.111:5060>
            if (needReplaceFromTo() && (strncasecmp(recvstr[0], STATUS, strlen(STATUS)) != 0)) {
                replaceTo(recvstr[i], fromUpplat);
            }
        } else if (IS_TYPE_OF(recvstr[i], INIPV4)) {
            //c=IN IP4 37.48.8.38\r\n
            if (index(recvstr[i], '\r') == NULL) {
                PRINT_ERR_HEAD
                print_err("not fine [\\r],[%s]", recvstr[i]);
                continue;
            }

            BZERO(ctmpip);
            strncpy(ctmpip, recvstr[i] + strlen(INIPV4),
                    (strlen(recvstr[i]) - strlen(INIPV4) - strlen(index(recvstr[i], '\r'))));
            strncpy(tmpstr, recvstr[i], strlen(INIPV4));
            strcat(tmpstr, fromUpplat ?
                   getChannelProxyIP(callid_str) : getChannelOutIP(callid_str));
            strcat(tmpstr, "\r\n");
            contlen += strlen(tmpstr) - strlen(recvstr[i]);
            strcpy(recvstr[i], tmpstr);
        } else if (IS_TYPE_OF(recvstr[i], MVIDEO)) {
            //m=video 63544 udp 105\r\n
            if (b_invite && fromUpplat) {
                contlen -= strlen(recvstr[i]);
                regStatusReq(recvstr[i], ctmpip, true, callid_str);
                contlen += strlen(recvstr[i]);
            }
        } else if (IS_TYPE_OF(recvstr[i], MAUDIO)) {
            //m=audio 63545 udp 105\r\n
            if (b_invite && fromUpplat) {
                contlen -= strlen(recvstr[i]);
                regStatusReq(recvstr[i], ctmpip, false, callid_str);
                contlen += strlen(recvstr[i]);
            }
        } else if (IS_TYPE_OF(recvstr[i], "o=")) {
            //o=H3C 0 0 IN IP4 37.48.8.38\r\n
            char *ptr = strstr(recvstr[i], OINIP4);
            if (ptr == NULL) {
                PRINT_ERR_HEAD
                print_err("not fine OINIP4,[%s]", recvstr[i]);
                continue;
            }

            //IP之前的内容拷贝到tmpstr
            strncpy(tmpstr, recvstr[i], ptr - recvstr[i] + strlen(OINIP4));
            strcat(tmpstr, fromUpplat ?
                   getChannelProxyIP(callid_str) : getChannelOutIP(callid_str));
            strcat(tmpstr, "\r\n");
            contlen += strlen(tmpstr) - strlen(recvstr[i]);
            strcpy(recvstr[i], tmpstr);
        } else if (IS_TYPE_OF(recvstr[i], CONTENTLEN)) {
            //Content-Length:1114\r\n
            //Content-Length: 1114\r\n
            //Content-Length : 1114\r\n

            contlen_offset = strlen(CONTENTLEN);
            while ((*(recvstr[i] + contlen_offset) == ' ')
                   || (*(recvstr[i] + contlen_offset) == ':')) {
                contlen_offset++;
            }

            if (atoi(recvstr[i] + contlen_offset) != 0) {
                contlenid = i;
                contlen = atoi(recvstr[i] + contlen_offset);
            }
        } else if (IS_TYPE_OF(recvstr[i], CALLID)) {
            if (getCallID(recvstr[i] + strlen(CALLID), callid_str, sizeof(callid_str))) {
                if (IS_TYPE_OF(recvstr[0], BYE)) {
                    delChannelByCallID(callid_str);//多态
                }
            }
        }
    }

    if (contlen != 0) {
        if (contlenid >= 0) {
            sprintf(recvstr[contlenid] + contlen_offset, "%d\r\n", contlen);
        } else {
            PRINT_ERR_HEAD
            print_err("contlen=[%d], contlenid=[%d]", contlen, contlenid);
        }
    }
    strcpy(dst, "");
    for (int i = 0; i < part; i++) {
        strcat(dst, recvstr[i]);
        //DELETE(recvstr[i]);
        delete [](recvstr[i]);
    }

    //当数据包包含0x00时，0x00之后的内容原封转发
    int dstlen = strlen(dst);
    int remainlen = ilen - (int)strlen(src);
    if (remainlen > 0) {
        PRINT_DBG_HEAD
        print_dbg("warn strlen(src)[%d] != ilen[%d]", (int)strlen(src), ilen);

        memcpy(dst + dstlen, src + strlen(src), remainlen);
        dstlen += remainlen;
    }

    PRINT_DBG_HEAD
    print_dbg("replace info over ...dstlen len[%d]", dstlen);

    return dstlen;
}

/**
 * [CSipBase::needReplaceVIA 是否需要替换VIA字段]
 * @return [是则返回true]
 */
bool CSipBase::needReplaceVIA()
{
    return ((ID_UNIVIEW == m_brandID) || (ID_KEDACOM == m_brandID) || (ID_DONGFANG == m_brandID));
}

/**
 * [CSipBase::needReplaceFromTo 是否需要替换from to字段]
 * @return [是则返回true]
 */
bool CSipBase::needReplaceFromTo()
{
#if 0
    return true;
#else
    return (ID_DONGFANG == m_brandID);
#endif
}

/**
 * [CSipBase::replaceClientInfo 替换来自上级平台的请求应用层中的IP等信息]
 * @param  src        [需要被替换的数据包]
 * @param  ilen       [src的长度]
 * @param  dst        [替换之后的数据包]
 * @return            [正确情况下为dst的长度 出错返回负值]
 */
int CSipBase::replaceClientInfo(const char *src, int ilen, char *dst)
{
    return replaceInfo(src, ilen, dst, true);
}

/**
 * [CSipBase::replaceServerInfo 替换来自下级平台的请求应用层中的IP等信息]
 * @param  src        [需要被替换的数据包]
 * @param  ilen       [src的长度]
 * @param  dst        [替换之后的数据包]
 * @return            [正确情况下为dst的长度 出错返回负值]
 */
int CSipBase::replaceServerInfo(const char *src, int ilen, char *dst)
{
    return replaceInfo(src, ilen, dst, false);
}

#endif
