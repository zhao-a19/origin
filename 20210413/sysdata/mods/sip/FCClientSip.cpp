/*******************************************************************************************
*文件:    FCClientSip.cpp
*描述:    视频代理
*作者:    王君雷
*日期:    2015-12-04
*修改:    整理文件，规范代码                                            ------>   2015-12-04
*         兼容SIP消息contact字段没有@符号时替换地址信息                 ------>   2016-03-18
*         重新设计视频代理，修改不断创建线程的BUG，可复用不受路数的限制 ------>   2017-08-09
*         达到最大支持点播数后，清空复用最早的一个通道                  ------>   2017-08-16
*         重新设计视频代理，靠近平台的一端完全使用iptables转发          ------>   2017-08-25
*         视频厂商宏使用英文翻译,改为UTF8编码,改用linux缩进格式         ------>   2018-01-23
*         替换客户端发来的呼叫信令中的IP时考虑特殊情况,IP后不是:port    ------>   2018-03-07
*         视频相关函数命名统一风格                                      ------>   2018-04-23
*         使用zlog;使用多态支持视频代理联动                             ------>   2018-06-06
*         日志中能区分视频的类型                                        ------>   2018-06-22
*         可通过会话ID清空、复用视频通道;支持多节点视频联动             ------>   2018-07-14
*         解析CallID的时候，不包含\r之后的内容，保持zlog日志整洁        ------>   2018-07-24
*         MY_BZERO、MY_DELETE等宏改名,去掉前面的MY_                     ------>   2018-08-05
*         设置内部nat ip的函数返回值类型改为bool                        ------>   2018-08-15
*         socket通信类接口传参顺序有变动                                ------>   2019-03-18
*         修改替换客户端发来的请求时，把c=替换为了大写的C=的BUG         ------>   2019-05-15
*         delete释放空间格式调整                                        ------>   2019-05-21
*         SIP替换IP代码接口封装，针对厂家接口封装                       ------>   2019-06-03
*         将SIP代码回滚开关放在编辑选项里                               ------>   2019-06-04
*         代码优化，删掉无用变量和日志，字符串操作改为指针操作          ------>   2019-06-24 --dzj
*         代码优化，去掉不必要的数组清零操作                            ------>   2019-06-25 --dzj
*         解决SIP日志导出时乱序问题                                     ------>   2019-06-27 --dzj
*         代理模式客户端登记时长宏移动到共用.h文件中                    ------>   2019-08-14 --dzj
*         修改SIP报文结尾无'\n'造成的报文内容丢失无法共享点位问题       ------>   2019-09-28 --dzj
*         解决SIP替换时出现替换不是SDP消息的问题                        ------>   2019-12-03 --dzj
*         不再串行记录访问日志                                          ------>   2020-01-07 --wjl
*         访问日志支持记录MAC字段,暂设置为空                            ------>   2020-01-16 wjl
*         兼容配置文件中Protocol为SIP和GB28181两种情况                  ------>   2020-08-18 wjl
*         SIP注册包添加 replaceFrom, replaceTo, replaceVia  函数        ------>   2021-04-01 LL
*         删除replaceFrom, replaceTo函数,客户IP可能是个范围,暂不处理    ------>   2021-04-02 LL
********************************************************************************************/
#include "FCClientSip.h"
#include "define.h"
#include "quote_global.h"
#include "FCLogContainer.h"
#include "debugout.h"

CClientSipBase::CClientSipBase(int taskno)
{
    m_taskno = taskno;
    m_cmdnum = 0;
    BZERO(m_cmd);

}

CClientSipBase::~CClientSipBase()
{
    DELETE_N(m_cmd, m_cmdnum);
}

/**
 * [CClientSipBase::是否为SIP协议]
 * @return [是返回true]
 */
bool CClientSipBase::isProtoSIP()
{
    return (strcmp(m_proto, "SIP") == 0)
           || (strcmp(m_proto, "GB28181") == 0);
}

/**
 * [CClientSipBase::靠近客户端的一端起始函数]
 * @return [成功返回0]
 */
int CClientSipBase::srcStart()
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "%s -I FORWARD -s %s -j ACCEPT", IPTABLES, m_tmpip2);
    system(chcmd);
    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);

    //源对象访问控制
    if (!ALL_OBJ(m_cliip)) {
        sprintf(chcmd, "%s -A INPUT -p udp -d '%s' --dport '%s' -m iprange ! --src-range '%s' -j DROP",
                IPTABLES, m_gapinip, m_port, m_cliip);
        system_safe(chcmd);
        PRINT_DBG_HEAD
        print_dbg("%s", chcmd);
    }

    //本机发出的IP数据包都不再转换源地址
    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_gapinip);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s %s -j ACCEPT", IPTABLES, m_tmpip1);
    system(chcmd);
    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);

    //视频流的源地址转换为网闸接口IP
    sprintf(chcmd, "%s -t nat -I POSTROUTING -s %s -j SNAT --to '%s'",
            IPTABLES, m_tmpip2, m_gapinip);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);

    if (init() < 0) {
        PRINT_ERR_HEAD
        print_err("init error");
        return -1;
    }

    CLISOCKTASK *psock1 = NULL;
    CBSUdpSockServer ser;

    //绑定地址和端口
    int newsock = ser.Open(m_gapinip, atoi(m_port));
    if (newsock < 0) {
        PRINT_ERR_HEAD
        print_err("Socket Busy![%s][%s]", m_port, m_gapinip);
        return -1;
    }

    //为线程参数申请空间
    psock1 = new CLISOCKTASK();
    if (psock1 == NULL) {
        PRINT_ERR_HEAD
        print_err("new CLISOCKTASK fail");
        ser.Close();
        return -1;
    }

    //为线程参数赋值
    psock1->recvsock = newsock;
    psock1->sendsock = -1;
    psock1->psip = this;
    psock1->regid = -1;

    //开启接收客户端数据线程
    pthread_t pid = 0;
    if (pthread_create(&pid, NULL, fromClientInfoTask, psock1) != 0) {
        PRINT_ERR_HEAD
        print_err("pthread_create error");
        DELETE(psock1);
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("start ok");

    usleep(10000);
    return 0;
}

/**
 * [CClientSipBase::任务初始化]
 * @return [成功返回0]
 */
int CClientSipBase::init()
{
    initChannel();//多态 调用子类的初始化函数

    //登记表初始化
    BZERO(m_regtable);
    for (int i = 0; i < (int)ARRAY_SIZE(m_regtable); i++) {
        m_regtable[i].bindport = C_CLI_SIPDYNAMICPORT + i;
    }

    return 0;
}

/**
 * [CClientSipBase::网闸靠近客户端的一侧，接收客户端请求的线程函数]
 * @param  para [地址端口信息]
 * @return      [无特殊含义]
 */
void *CClientSipBase::fromClientInfoTask(void *para)
{
    pthread_setself("fromclientinfo");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    int recvlen = 0;
    int replen = 0;//替换之后的长度
    int sendlen = 0;
    unsigned char buff[SIP_MAX_PACKET];
    unsigned char buff2[SIP_MAX_PACKET];

    CLISOCKTASK *m_task = (CLISOCKTASK *)para;
    CClientSipBase *psip = m_task->psip;
    int recvsock = m_task->recvsock;
    int sendsock = m_task->sendsock;

    DELETE(m_task);
    if (psip == NULL) {
        PRINT_ERR_HEAD
        print_err("psip null");
        return NULL;
    }

    //网闸内部通信口地址  接收的数据要转发到这里
    sockaddr_in to_addr;
    BZERO(to_addr);
    to_addr.sin_family = AF_INET;
    to_addr.sin_port = htons(atoi(psip->m_port));
    to_addr.sin_addr.s_addr = inet_addr(psip->m_tmpip2);

    //存放客户端地址信息
    sockaddr_in from_addr;
    BZERO(from_addr);
    socklen_t fromaddrlen = 0;

    int regid = 0;

    while (1) {
        BZERO(buff);
        BZERO(buff2);

        //防止替换之后变长溢出
        fromaddrlen = sizeof(from_addr);
        recvlen = recvfrom(recvsock, buff, sizeof(buff) - SIP_PKT_LEN_CHANGE,
                           0, (sockaddr *)&from_addr, &fromaddrlen);
        if (recvlen <= 0) {
            PRINT_ERR_HEAD
            print_err("recvfrom error[%s][%d]", strerror(errno), recvlen);
            continue;
        }

        //客户端登记
        regid = psip->regClient(from_addr, recvsock, sendsock);
        if (regid < 0) {
            PRINT_ERR_HEAD
            print_err("register fail, may too many clients");
            continue;
        }

        //替换信息
        replen = psip->replaceClientInfo((const char *)buff, recvlen, (char *)buff2, regid);
        if (replen > 0) {
            sendlen = sendto(sendsock, buff2, replen, 0,
                             (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
            if (sendlen <= 0) {
                PRINT_ERR_HEAD
                print_err("sendto error[%s][%d]", strerror(errno), sendlen);
                continue;
            }
        } else {
            PRINT_ERR_HEAD
            print_err("repalace error");
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
 * [CClientSipBase::SIP客户端登记]
 *注释:    对于已经登记过的客户端，用fd2返回已建socket描述符
 *         对于未登记的客户端
 *            如果还有空余的登记空间，就创建socket，起线程接收该socket，登记，描述符返回
 *            如果没有空余的登记空间
 *                检查是否有超过1个小时未使用的空间
 *                    如果有超时的就复用空间 描述符返回
 *                    如果没有超时的，就返回登记失败，丢弃客户端信息
 * @param  addr [客户端地址信息]
 * @param  fd1  [接收客户端请求的时候 使用的描述符]
 * @param  fd2  [新创建的socket描述符 出参]
 * @return      [成功返回下标值（登记编号） 失败返回负值]
 */
int CClientSipBase::regClient(sockaddr_in &addr, int fd1, int &fd2)
{
    int maxreg = ARRAY_SIZE(m_regtable);

    //是否已经登记过
    for (int i = 0; i < maxreg; i++) {
        if (m_regtable[i].inuse == 1) {
            if (memcmp(&(m_regtable[i].cliaddr), &addr, sizeof(m_regtable[i].cliaddr)) == 0) {
                m_regtable[i].updatetime = time(NULL);
                fd2 = m_regtable[i].fd;
                return i;
            }
        }
    }

    //是否有空闲的
    for (int i = 0; i < maxreg; i++) {
        if (m_regtable[i].inuse == 0) {
            //创建socket
            int myfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (myfd < 0) {
                PRINT_ERR_HEAD
                print_err("socket error[%s]", strerror(errno));
                return -1;
            }

            //setsockopt
            int yes = 1;
            setsockopt(myfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

            //地址结构
            struct sockaddr_in inneraddr;
            BZERO(inneraddr);
            inneraddr.sin_family = AF_INET;
            inneraddr.sin_port = htons(m_regtable[i].bindport);
            if (inet_pton(AF_INET, m_tmpip1, (void *)&inneraddr.sin_addr) <= 0) {
                PRINT_ERR_HEAD
                print_err("inet_pton error[%s],m_tmpip1[%s]", strerror(errno), m_tmpip1);
                close(myfd);
                return -1;
            }

            //bind
            if (bind(myfd, (struct sockaddr *)&inneraddr, sizeof(inneraddr)) < 0) {
                PRINT_ERR_HEAD
                print_err("bind error[%s],m_tmpip1[%s],port[%d]",
                          strerror(errno), m_tmpip1, m_regtable[i].bindport);
                close(myfd);
                return -1;
            }

            //准备线程参数
            CLISOCKTASK *psock1 = new CLISOCKTASK();
            if (psock1 == NULL) {
                PRINT_ERR_HEAD
                print_err("new CLISOCKTASK fail");
                close(myfd);
                return -1;
            }
            psock1->recvsock = myfd;
            psock1->sendsock = fd1;
            psock1->psip = this;
            psock1->regid = i;

            //启动接收线程
            pthread_t pid = 0;
            if (pthread_create(&pid, NULL, recvServerThread, (void *)psock1) != 0) {
                PRINT_ERR_HEAD
                print_err("pthread_create error");
                close(myfd);
                return -1;
            }

            memcpy(&(m_regtable[i].cliaddr), &addr, sizeof(m_regtable[i].cliaddr));
            m_regtable[i].inuse = 1;
            m_regtable[i].updatetime = time(NULL);
            m_regtable[i].fd = myfd;
            fd2 = m_regtable[i].fd;
            usleep(10000);//防止线程参数失效
            return i;
        }
    }

    //是否有超时的  (超时1小时)
    for (int i = 0; i < maxreg; i++) {
        if ((time(NULL) - m_regtable[i].updatetime) > SECONDS_PER_HOUR) {
            memcpy(&(m_regtable[i].cliaddr), &addr, sizeof(m_regtable[i].cliaddr));
            m_regtable[i].updatetime = time(NULL);
            fd2 = m_regtable[i].fd;
            return i;
        }
    }

    return -1;
}

/**
 * [CClientSipBase::网闸靠近客户端的一侧，接收平台方向数据的线程函数]
 * @param  para [地址端口信息]
 * @return      [无特殊含义]
 */
void *CClientSipBase::recvServerThread(void *para)
{
    pthread_setself("siprecvserver");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    CLISOCKTASK *m_task = (CLISOCKTASK *)para;
    CClientSipBase *psip = m_task->psip;
    int recvsock = m_task->recvsock;
    int sendsock = m_task->sendsock;
    int regid = m_task->regid;

    DELETE(m_task);

    if (psip == NULL) {
        PRINT_ERR_HEAD
        print_err("psip null");
        return NULL;
    }

    int recvlen = 0;
    int replen = 0;
    int sendlen = 0;
    unsigned char buff[SIP_MAX_LINE_SIZE];
    unsigned char buff2[SIP_MAX_LINE_SIZE];

    while (1) {
        BZERO(buff);
        BZERO(buff2);

        recvlen = recvfrom(recvsock, buff, sizeof(buff) - SIP_PKT_LEN_CHANGE, 0, NULL, NULL);
        if (recvlen <= 0) {
            PRINT_ERR_HEAD
            print_err("recvfrom error[%s][%d]", strerror(errno), recvlen);
            continue;
        }

        psip->m_regtable[regid].updatetime = time(NULL);
        replen = psip->replaceServerInfo((char *)buff, recvlen, (char *)buff2, regid);
        if (replen > 0) {
            sendlen = sendto(sendsock, buff2, replen, 0,
                             (struct sockaddr *) & (psip->m_regtable[regid].cliaddr),
                             sizeof(struct sockaddr));
            if (sendlen <= 0) {
                PRINT_ERR_HEAD
                print_err("sendto error[%s][%d]", strerror(errno), sendlen);
            }
        } else {
            PRINT_ERR_HEAD
            print_err("repalace error");
        }
    }

    PRINT_ERR_HEAD
    print_err("You should never get here");
    close(sendsock);
    close(recvsock);
    return NULL;
}

/**
 * [CClientSipBase::getCmd 从命令行中取出命令]
 * @param  chcmd   [取出的命令 出参]
 * @param  cmdsize [命令缓冲区大小 入参]
 * @param  cmdline [可能包含命令的数据包 入参]
 * @return         [取命令成功返回true，否则返回false]
 */
bool CClientSipBase::getCmd(char *chcmd, int cmdsize, const char *cmdline)
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
 * [CClientSipBase::filterCliSipCmd 过滤命令]
 * @param  chcmd   [待检查的命令]
 * @param  fromCli [是否来自客户端]
 * @param  regid   [登记编号]
 * @return         [允许通过返回true]
 */
bool CClientSipBase::filterCliSipCmd(const char *chcmd, bool fromCli, int regid)
{
    bool flag = m_ifexec;
    for (int i = 0; i < m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_cmd[i]->m_cmd) == 0) {
            flag = m_cmd[i]->m_action;
            break;
        }
    }
    recordCallLog(chcmd, flag, fromCli, regid);
    return flag;
}

/**
 * [CClientSipBase::recordCallLog 记录日志函数]
 * @param chcmd   [命令]
 * @param result  [结果]
 * @param fromCli [是否来自客户端]
 * @param regid   [登记编号]
 */
void CClientSipBase::recordCallLog(const char *chcmd, bool result, bool fromCli, int regid)
{
    if (g_iflog || g_syslog) {
        char cliip[IP_STR_LEN] = {0};
        char cliport[PORT_STR_LEN] = {0};
        strcpy(cliip, inet_ntoa(m_regtable[regid].cliaddr.sin_addr));
        sprintf(cliport, "%d", ntohs(m_regtable[regid].cliaddr.sin_port));

        CallLogPara *p = new CallLogPara;
        if (p != NULL) {
            if (p->SetValues("", fromCli ? cliip : m_videoip,
                             fromCli ? m_videoip : cliip,
                             fromCli ? cliport : m_port,
                             fromCli ? m_port : cliport,
                             "", "",
                             getTypeDesc(), chcmd, "", result ? D_SUCCESS : D_REFUSE,
                             result ? "" : LOG_CONTENT_REFUSE)) {
                LogContainer &s1 = LogContainer::GetInstance();
                s1.PutPara(p);
            } else {
                PRINT_ERR_HEAD
                print_err("set values fail[sip %s, dip %s, sport %s, dport %s, %s:%s]",
                          fromCli ? cliip : m_videoip,
                          fromCli ? m_videoip : cliip,
                          fromCli ? cliport : m_port,
                          fromCli ? m_port : cliport,
                          getTypeDesc(), chcmd);
                delete p;
            }
        }
    }
    return;
}

/**
 * [CClientSipBase::findStrByKey 从字符串src偏移spos长度，查找字符ikey
 * 然后把ikey之前查找到的字符存放到dst里]
 * @param  src  [被查找的字符串]
 * @param  dst  [存放查找出的字符串]
 * @param  spos [开始查找的偏移位置]
 * @param  ikey [分隔字符]
 * @return      [成功返回下一次查找时的偏移量，失败返回-1]
 */
int CClientSipBase::findStrByKey(const char *src, char *dst, int spos, char ikey)
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
 * [CClientSipBase::regStatusReq 记录下一个动态端口信息 并开通媒体流通道]
 * @param  cinput      [包含动态端口信息的一行内容 示例：m=video 63544 udp 105\r\n]
 * @param  mediarecvip [媒体流接收者IP]
 * @param  ifvideo     [是否为video包，true表示是video包，false表示audio包]
 * @param  callid      [会话ID]
 * @return             [成功时返回媒体流通道的下标，失败返回负值]
 */
int CClientSipBase::regStatusReq(char *cinput, const char *mediarecvip,
                                 bool ifvideo, const char *callid)
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

    chanid = getOneChannelID(mediarecvip, tmpport, find, callid, nodeid);//多态
    if (chanid < 0) {
        PRINT_ERR_HEAD
        print_err("getOneChannelID error[%d]", chanid);
        return -2;
    }

    if (find == 0) {
        addOneChannel(nodeid, chanid);//多态
    }

    sprintf(cinput, "%s%s%s", ifvideo ? MVIDEO : MAUDIO,
            getChannelProxyPort(nodeid, chanid), tmpstr);//多态
    return chanid;
}

/**
 * [CClientSipBase::dstStart 网闸靠近平台的一端，起始函数]
 * @return [成功返回0]
 */
int CClientSipBase::dstStart()
{
    dstSipPrepare();
    return 0;
}

/**
 * [CSipBase::dstSipPrepare 网闸靠近平台的一端，SIP跳转准备]
 */
void CClientSipBase::dstSipPrepare()
{
    char chcmd[CMD_BUF_LEN] = {0};

    //PREROUTING DNAT
    sprintf(chcmd,
            "%s -t nat -I PREROUTING -s %s -d %s -p udp --sport %d:%d --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_tmpip1, m_tmpip2, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1, m_port, m_videoip);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);

    //FORWARD
    sprintf(chcmd, "%s -I FORWARD -s %s -d '%s' -p udp --sport %d:%d --dport '%s' -j ACCEPT",
            IPTABLES, m_tmpip1, m_videoip, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1, m_port);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);

    sprintf(chcmd, "%s -I FORWARD -d %s -s '%s' -p udp --dport %d:%d --sport '%s' -j ACCEPT",
            IPTABLES, m_tmpip1, m_videoip, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1, m_port);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);

    //POSTROUTING
    sprintf(chcmd,
            "%s -t nat -I POSTROUTING -s %s -d '%s' -p udp --sport %d:%d --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_tmpip1, m_videoip, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1, m_port, m_gapoutip);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);
}

/**
 * [CClientSipBase::replaceClientCall 替换客户端发来的呼叫信令中的IP信息]
 * @param line [包含信令的一行信息]
 * 最常见的：
 *     INVITE sip:33078200001320000004@10.73.192.204:5511 SIP/2.0
 *     BYE sip:32011501001320000155@172.18.13.192:5060 SIP/2.0
 * 特殊情况:
 *     INVITE sip:10002@192.168.2.100;transport=UDP SIP/2.0
 *     INVITE sip:32011501001320000155@172.18.13.192 SIP/2.0
 */
void CClientSipBase::replaceClientCall(char *line)
{
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};

    char *pat = index(line, '@');
    if (pat != NULL) {
        //把@以及之前的内容保存到tmpstr
        memcpy(tmpstr, line, pat - line + 1);
        //把替换后的IP追加到tmpstr
        strcat(tmpstr, m_videoip);

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

const char *CClientSipBase::getVideoIp()
{
    return m_videoip;
}

int CClientSipBase::getArea()
{
    return m_secway.getarea();
}

void CClientSipBase::swapGapIp()
{
    char tmpip[IP_STR_LEN] = {0};
    strcpy(tmpip, m_gapinip);
    strcpy(m_gapinip, m_gapoutip);
    strcpy(m_gapoutip, tmpip);
}

const char *CClientSipBase::getGapInIp()
{
    return m_gapinip;
}

const char *CClientSipBase::getGapOutIp()
{
    return m_gapoutip;
}

bool CClientSipBase::setTmpIp2(const char *ip)
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

bool CClientSipBase::setTmpIp1(const char *ip)
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

const char *CClientSipBase::getPort()
{
    return m_port;
}

/**
 * [CClientSipBase::getCallID 从一行内容中获取callid值]
 * @param  line      [一行内容，已经把Call-id偏移过去了]
 * @param  callidbuf [存放callid值的buf]
 * @param  buflen    [buf长度]
 * @return           [成功返回true]
 */
bool CClientSipBase::getCallID(const char *line, char *callidbuf, int buflen)
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

/**
 * [CClientSipBase::recordSysLog 记录系统日志]
 * @param logtype [日志类型]
 * @param result  [结果]
 * @param remark  [备注信息]
 */
void CClientSipBase::recordSysLog(const char *logtype, const char *result, const char *remark)
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
#ifdef RESEAL_SIP_INTERFACE
/**
 * [CClientSipBase::replaceClientMessage 替换Message字段]
 * @param line       [一行内容]
 * @param fromUpplat [是否由上级发出]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 * //MESSAGE sip:wiscomCallerID@172.18.13.188:5062 SIP/2.0\r\n
 * //MESSAGE sip:wiscomCallerID@172.18.13.188 SIP/2.0\r\n
 */
void CClientSipBase::replaceClientMessage(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *pat = rindex(recvstr, '@');
    if (pat != NULL) {
        //@及之前的内容拷贝到tmpstr
        memcpy(tmpstr, recvstr, pat - recvstr + 1);
        strcat(tmpstr, m_videoip);
        if (index(pat, ':') != NULL) {
            strcat(tmpstr, index(pat, ':'));
            memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
            memcpy(recvstr, tmpstr, strlen(tmpstr) + 1);
        } else if (index(pat, ' ') != NULL) {
            strcat(tmpstr, index(pat, ' '));
            memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
            memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
        } else {
            PRINT_ERR_HEAD
            print_err("warn: MESSAGE format err[%s]", recvstr);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("warn: MESSAGE not find @[%s]", recvstr);
    }
}

/**
 * [CClientSipBase::replaceClientContact 替换Contact字段]
 * @param line       [一行内容]
 * @param fromUpplat [是否由上级发出]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式举例
 * //contact，可能是客户端的IP和端口，也可能是服务器的IP和端口
 * //如果是服务器的IP和端口，此处替换，存在错误的风险
 * //Contact: <sip:2001$37060200081320000014@37.48.8.61:5060>\r\n
 */
void CClientSipBase::replaceClientContact(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *pat = index(recvstr, '@');
    if (pat != NULL) {
        char *p1 = index(pat, ':');
        if (NULL != p1) {
            memcpy(tmpstr, recvstr, pat - recvstr + 1);
            strcat(tmpstr, sip_info->fromUpplat ? m_gapoutip : m_gapinip);
            strcat(tmpstr, p1);
            memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
            memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
        } else {
            PRINT_ERR_HEAD
            print_err("warn: Contact find @,but not find : [%s]", recvstr);
        }
    } else {
        //e.g
        //Contact: <sip:172.20.20.86:5061>\r\n
        //Contact: *\r\n
        char *p1 = index(recvstr + strlen(SIP_CONTACT_VALUE) + 1, ':');
        if (p1 != NULL) {
            char *p2 = index(p1 + 1, ':');
            if (p2 != NULL) {
                memcpy(tmpstr, recvstr, p1 - recvstr + 1);
                strcat(tmpstr, sip_info->fromUpplat ? m_gapoutip : m_gapinip);
                strcat(tmpstr, p2);
                memset(recvstr, 0x00, SIP_MAX_LINE_SIZE);
                memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
            } else {
                PRINT_ERR_HEAD
                print_err("warn: Contact format err[%s]", recvstr);
            }
        }
    }
}

/**
 * [CClientSipBase::replaceClientContentLen 替换Content-Length字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 * Content-Length:1114\r\n
 * Content-Length: 1114\r\n
 * Content-Length : 1114\r\n
 */
void CClientSipBase::replaceClientContentLen(char *line, struct SIP_INFO *sip_info)
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
 * [CClientSipBase::replaceClientCinip6 替换c=IN IP6字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 */
void CClientSipBase::replaceClientCinip6(char *recvstr, struct SIP_INFO *sip_info)
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
        print_err("not fine [\\r],[%s]", recvstr);
    }

}

/**
 * [CClientSipBase::replaceClientCinip4 替换c=IN IP4字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 * //c=IN IP4 37.48.8.38\r\n
 */
void CClientSipBase::replaceClientCinip4(char *recvstr, struct SIP_INFO *sip_info)
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
        print_err("not fine [\\r],[%s]", recvstr);
    }

}

/**
 * [CClientSipBase::replaceClientOinip4 替换o=字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 * //o=H3C 0 0 IN IP4 37.48.8.38\r\n
 */
void CClientSipBase::replaceClientOinip4(char *recvstr, struct SIP_INFO *sip_info)
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
        print_err("not fine OINIP4,[%s]", recvstr);
    }

}

/**
 * [CClientSipBase::replaceClientMaudio 替换m=audio字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 * //m=audio 63545 udp 105\r\n
 */
void CClientSipBase::replaceClientMaudio(char *recvstr, struct SIP_INFO *sip_info)
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
 * [CClientSipBase::replaceMvedio 替换m=vedio字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 * //m=video 63544 udp 105\r\n
 */
void CClientSipBase::replaceClientMvedio(char *recvstr, struct SIP_INFO *sip_info)
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
 * [CClientSipBase::sipKeywordHandle 将sip每行的关键字标志转换为数字]
 * @param  recvstr        [需要被替换的数据包]
 * @param sip_info        [包含SIP报文每行关键字标志和IP信息]
 * @return                [返回空值]
 */
void CClientSipBase::sipKeywordHandle(const char *recvstr, struct SIP_INFO *sip_info)
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
    } else if (IS_TYPE_OF(recvstr, SIP_MESSAGE_VALUE)) {
        sip_info->key_flag = SIP_MESSAGE_KEY;
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
    }
    return;
}

/**
 * [CClientSipBase::replaceClientResInfo 替换SIP响应的IP等信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  dst        [替换之后的数据包]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [正确为recvstr长度，出错为负值]
 */
int CClientSipBase::replaceClientResInfo(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    switch (sip_info->key_flag) {
    case SIP_BYE_KEY:
        sip_info->b_bye = true;
        replaceClientCall(recvstr);
        break;
    case SIP_CONTACT_KEY:
        replaceClientContact(recvstr, sip_info);
        break;
    case SIP_CINIP4_KEY:
        replaceClientCinip4(recvstr, sip_info);
        break;
    case SIP_OINIP4_KEY: //不必须替换
        replaceClientOinip4(recvstr, sip_info);
        break;
    case SIP_CONTENTLEN_KEY:
        replaceClientContentLen(recvstr, sip_info);
        break;
    case SIP_CALLID_KEY:
        if (getCallID(recvstr + strlen(SIP_CALLID_VALUE), sip_info->callid_str, sizeof(sip_info->callid_str))) {
            if (sip_info->b_bye) {
                delChannelByCallID(sip_info->callid_str);//多态
            }
        }
        break;
    default:
        break;
    }

    return strlen(recvstr);
}

/**
 * [CClientSipBase::replaceClientReqInfo 替换SIP请求的IP等信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  dst        [替换之后的数据包]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [正确为recvstr长度，出错为负值]
 */
int CClientSipBase::replaceClientReqInfo(char *recvstr, struct SIP_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    switch (sip_info->key_flag) {
    case SIP_MESSAGE_KEY:
        replaceClientMessage(recvstr, sip_info);
        break;
    case SIP_BYE_KEY:
        sip_info->b_bye = true;
        replaceClientCall(recvstr);
        break;
    case SIP_INVITE_KEY:
    case SIP_ACK_KEY:
    case SIP_UPDATE_KEY:
    case SIP_PRACK_KEY:
    case SIP_CANCEL_KEY:
        replaceClientCall(recvstr);
        break;
    case SIP_CONTACT_KEY:
        replaceClientContact(recvstr, sip_info);
        break;
    case SIP_CINIP4_KEY:
        replaceClientCinip4(recvstr, sip_info);
        break;
    case SIP_CINIP6_KEY:
        replaceClientCinip6(recvstr, sip_info);
        break;
    case SIP_OINIP4_KEY: //不必须替换
        replaceClientOinip4(recvstr, sip_info);
        break;
    case SIP_MVIDEO_KEY:
        replaceClientMvedio(recvstr, sip_info);
        break;
    case SIP_MAUDIO_KEY:
        replaceClientMaudio(recvstr, sip_info);
        break;
    case SIP_CONTENTLEN_KEY:
        replaceClientContentLen(recvstr, sip_info);
        break;
    case SIP_CALLID_KEY:
        if (getCallID(recvstr + strlen(SIP_CALLID_VALUE), sip_info->callid_str, sizeof(sip_info->callid_str))) {
            if (sip_info->b_bye) {
                delChannelByCallID(sip_info->callid_str);//多态
            }
        }
        break;
    case SIP_VIA_KEY:
        replaceVia(recvstr, sip_info);
        break;
    /* 视频代理没有上下级概念，且客户端IP 可以是个范围，先不处理From, To 字段 */
    case SIP_FROM_KEY:
        //replaceFrom(recvstr, sip_info);
        break;
    case SIP_TO_KEY:
        //replaceTo(recvstr, sip_info);
        break;
    default:
        break;
    }

    return strlen(recvstr);
}

/**
 * [CClientSipBase::replaceClientInfo 替换客户端发来的信息]
 * @param  src   [客户端发来的数据包]
 * @param  ilen  [数据包长度]
 * @param  dst   [出参，替换后的数据包存放在里面]
 * @param  regid [登记编号]
 * @return       [成功时返回替换后数据包的长度 失败返回负值]
 */
int CClientSipBase::replaceClientInfo(const char *src, int ilen, char *dst, int regid)
{
    PRINT_DBG_HEAD
    print_dbg("replace sip Client info begin ...src info [%s]\n", src);

    if ((src == NULL) || (ilen < 0) || (dst == NULL)) {
        PRINT_ERR_HEAD
        print_err("para err");
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

    //过滤命令，取SIP请求命令并记日志
    if (getCmd(chcmd, C_SIP_KEY_WORLD_LEN, src)) {
        if (!filterCliSipCmd(chcmd, true, regid)) {
            PRINT_ERR_HEAD
            print_err("filter Cmd fail");
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

        sip_info.key_flag = 0;
        ipos = res;

        //每行关键字段匹配转换标志
        sipKeywordHandle(recvstr, &sip_info);

        //替换SIP请求IP
        res = replaceClientReqInfo(recvstr, &sip_info);
        if (res < 0) {
            PRINT_ERR_HEAD
            print_err("error res replaceClientReqInfo [%d]\n", res);
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
        memcpy(recvstr, tmpdst, p - tmpdst);
        sprintf(dst, recvstr, sip_info.contlen);
        strcat(dst, p);
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
    print_dbg("replace sip Client info over ...dst info [%s]\n", dst);

    return dstlen;
}

/**
 * [CClientSipBase::replaceServerInfo 替换平台发给客户端的数据包内容]
 * @param  src   [数据包]
 * @param  ilen  [数据包长度]
 * @param  dst   [替换之后的数据包，出参]
 * @param  regid [登记编号]
 * @return       [成功时返回dst的长度 失败返回负值]
 */
int CClientSipBase::replaceServerInfo(const char *src, int ilen, char *dst, int regid)
{
    PRINT_DBG_HEAD
    print_dbg("replace sip Server info begin ...src info [%s]\n", src);

    int maxreg = ARRAY_SIZE(m_regtable);
    if ((src == NULL) || (dst == NULL) || (ilen < 0) || (regid < 0) || (regid >= maxreg)) {
        PRINT_ERR_HEAD
        print_err("para error");
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
    //过滤命令，取SIP请求命令并记日志
    if (getCmd(chcmd, C_SIP_KEY_WORLD_LEN, src)) {
        if (!filterCliSipCmd(chcmd, false, regid)) {
            PRINT_ERR_HEAD
            print_err("filter Cmd fail");
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

        sip_info.key_flag = 0;
        ipos = res;

        //每行关键字段匹配转换标志
        sipKeywordHandle(recvstr, &sip_info);

        //替换SIP响应
        res = replaceClientResInfo(recvstr, &sip_info);
        if (res < 0) {
            PRINT_ERR_HEAD
            print_err("error res replaceClientResInfo [%d]\n", res);
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
        memcpy(recvstr, tmpdst, p - tmpdst);
        sprintf(dst, recvstr, sip_info.contlen);
        strcat(dst, p);
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
    print_dbg("replace Server info over ...dst info [%s]\n", dst);

    return dstlen;
}

/* 视频代理没有上下级概念，且客户端IP 可以是个范围，先不处理From, To 字段 */
#if 0

/**
 * [CClientSipBase::replaceFrom 替换from字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 */
void CClientSipBase::replaceFrom(char *line, struct SIP_INFO *sip_info)
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
 * [CClientSipBase::replaceTo 替换to字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 */
void CClientSipBase::replaceTo(char *line, struct SIP_INFO *sip_info)
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

#endif


/**
 * [CClientSipBase::replaceVia 替换VIA字段]
 * @param line       [一行内容]
 * @param sip_info [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *    //Via: SIP/2.0/UDP 20.95.4.103:6689;branch=z9hG4bK108764931853145314531420180523110753
 *    //Via:SIP/2.0/UDP 20.95.4.103:6689;branch=z9hG4bK108764931853145314531420180523110753
 */
void CClientSipBase::replaceVia(char *line, struct SIP_INFO *sip_info)
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
            strcat(tmpstr, sip_info->fromUpplat ? m_gapoutip : m_gapinip);
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


#else
/**
 * [CClientSipBase::replaceClientInfo 替换客户端发来的信息]
 * @param  src   [客户端发来的数据包]
 * @param  ilen  [数据包长度]
 * @param  dst   [出参，替换后的数据包存放在里面]
 * @param  regid [登记编号]
 * @return       [成功时返回替换后数据包的长度 失败返回负值]
 */
int CClientSipBase::replaceClientInfo(const char *src, int ilen, char *dst, int regid)
{
    PRINT_DBG_HEAD
    print_dbg("replace sip Client begin ...src info [%s]\n", src);

    if ((src == NULL) || (ilen < 0) || (dst == NULL)) {
        PRINT_ERR_HEAD
        print_err("para err");
        return -1;
    }

    char MESSAGE[10] = "MESSAGE";
    char INVITE[10] = "INVITE";
    char UPDATE[10] = "UPDATE";
    char ACK[10] = "ACK";
    char PRACK[10] = "PRACK";
    char BYE[10] = "BYE";
    char CANCEL[10] = "CANCEL";
    char CONTACT[20] = "CONTACT:";
    char OINIP4[10] = "IN IP4 ";
    char INIPV4[10] = "c=IN IP4 ";
    char CONTENTLEN[20] = "Content-Length";
    char MVIDEO[20] = "m=video ";
    char MAUDIO[20] = "m=audio ";
    char CALLID[20] = "Call-ID";
    //char REGISTER[10] = "REGISTER";
    //char VIAUDP[20] = "via: SIP/2.0/UDP ";
    //char SIP2[20] = "SIP/2.0";
    //char FROM[10] = "FROM";
    //char TO[10] = "TO";

    int part = 0;//行数计数
    int ipos = 0;//当前位置
    int res = 0;//返回结果
    int contlen = 0;//内容长度
    int contlenid = -1;//内容长度所在行号
    char chcmd[24] = {0};//信令
    char ctmpip[20];//真正的媒体接收者IP
    char tmpstr[SIP_MAX_LINE_SIZE];
    char *recvstr[SIP_MAX_LINE_NUM];
    int contlen_offset = 0;//Content-Length中的数字，相对行首的偏移量
    char callid_str[SIP_CALL_ID_LEN] = {0};
    BZERO(recvstr);

    //取命令
    if (getCmd(chcmd, sizeof(chcmd), src)) {
        if (!filterCliSipCmd(chcmd, true, regid)) {
            PRINT_ERR_HEAD
            print_err("filter Cmd fail");
            return -1;
        }
    }

    //分行
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
        if (IS_TYPE_OF(recvstr[i], MESSAGE)) {
            //MESSAGE sip:wiscomCallerID@172.18.13.188:5062 SIP/2.0\r\n
            //MESSAGE sip:wiscomCallerID@172.18.13.188 SIP/2.0\r\n
            char *pat = rindex(recvstr[i], '@');
            if (pat != NULL) {
                //@及之前的内容拷贝到tmpstr
                strncpy(tmpstr, recvstr[i], pat - recvstr[i] + 1);
                strcat(tmpstr, m_videoip);
                if (index(pat, ':') != NULL) {
                    strcat(tmpstr, index(pat, ':'));
                    strcpy(recvstr[i], tmpstr);
                } else if (index(pat, ' ') != NULL) {
                    strcat(tmpstr, index(pat, ' '));
                    strcpy(recvstr[i], tmpstr);
                } else {
                    PRINT_ERR_HEAD
                    print_err("warn: MESSAGE format err[%s]", recvstr[i]);
                }
            } else {
                PRINT_ERR_HEAD
                print_err("warn: MESSAGE not find @[%s]", recvstr[i]);
            }
        } else if (IS_TYPE_OF(recvstr[i], INVITE)
                   || IS_TYPE_OF(recvstr[i], ACK)
                   || IS_TYPE_OF(recvstr[i], BYE)
                   || IS_TYPE_OF(recvstr[i], CANCEL)
                   || IS_TYPE_OF(recvstr[i], UPDATE)
                   || IS_TYPE_OF(recvstr[i], PRACK)) {
            //INVITE sip:32011501001320000155@172.18.13.192 SIP/2.0\r\n
            //INVITE sip:2001$94893020170728162857+XP&01101@37.48.8.38:7001 SIP/2.0\r\n
            replaceClientCall(recvstr[i]);
        } else if (IS_TYPE_OF(recvstr[i], CONTACT)) {
            //contact，可能是客户端的IP和端口，也可能是服务器的IP和端口
            //如果是服务器的IP和端口，此处替换，存在错误的风险
            //Contact: <sip:2001$37060200081320000014@37.48.8.61:5060>\r\n
            char *pat = index(recvstr[i], '@');
            if (pat != NULL) {
                if (index(pat, ':') != NULL) {
                    strncpy(tmpstr, recvstr[i], pat - recvstr[i] + 1);
                    strcat(tmpstr, m_gapoutip);
                    strcat(tmpstr, index(pat, ':'));
                    strcpy(recvstr[i], tmpstr);
                } else {
                    PRINT_ERR_HEAD
                    print_err("warn: Contact find @,but not find : [%s]", recvstr[i]);
                }
            } else {
                //e.g
                //Contact: <sip:172.20.20.86:5061>\r\n
                //Contact: *\r\n
                char *p1 = index(recvstr[i] + strlen(CONTACT) + 1, ':');
                if (p1 != NULL) {
                    char *p2 = index(p1 + 1, ':');
                    if (p2 != NULL) {
                        strncpy(tmpstr, recvstr[i], p1 - recvstr[i] + 1);
                        strcat(tmpstr, m_gapoutip);
                        strcat(tmpstr, p2);
                        strcpy(recvstr[i], tmpstr);
                    } else {
                        PRINT_ERR_HEAD
                        print_err("warn: Contact format err[%s]", recvstr[i]);
                    }
                }
            }
        } else if (IS_TYPE_OF(recvstr[i], INIPV4)) {
            //c=IN IP4 37.48.8.38\r\n
            if (index(recvstr[i], '\r') == NULL) {
                PRINT_ERR_HEAD
                print_err("INIPV4 not find [\\r][%s]", recvstr[i]);
                continue;
            }

            //取出IP
            BZERO(ctmpip);
            strncpy(ctmpip, recvstr[i] + strlen(INIPV4),
                    (strlen(recvstr[i]) - strlen(INIPV4) - strlen(index(recvstr[i], '\r'))));
            strncpy(tmpstr, recvstr[i], strlen(INIPV4));
            strcat(tmpstr, getChannelProxyIP(callid_str));
            strcat(tmpstr, index(recvstr[i], '\r'));
            contlen += strlen(tmpstr) - strlen(recvstr[i]);
            strcpy(recvstr[i], tmpstr);
        } else if (IS_TYPE_OF(recvstr[i], MVIDEO)) {
            //m=video 63544 udp 105\r\n
            contlen -= strlen(recvstr[i]);
            regStatusReq(recvstr[i], ctmpip, true, callid_str);
            contlen += strlen(recvstr[i]);
        } else if (IS_TYPE_OF(recvstr[i], MAUDIO)) {
            //m=audio 63544 udp 8\r\n
            contlen -= strlen(recvstr[i]);
            regStatusReq(recvstr[i], ctmpip, false, callid_str);
            contlen += strlen(recvstr[i]);
        } else if (IS_TYPE_OF(recvstr[i], "o=")) {
            //o=H3C 0 0 IN IP4 37.48.8.38\r\n
            char *ptr = strstr(recvstr[i], OINIP4);
            if (ptr == NULL) {
                PRINT_ERR_HEAD
                print_err("not find OINIP4[%s]", recvstr[i]);
                continue;
            }

            //IP之前的内容拷贝到tmpstr
            strncpy(tmpstr, recvstr[i], ptr - recvstr[i] + strlen(OINIP4));
            strcat(tmpstr, getChannelProxyIP(callid_str));
            strcat(tmpstr, "\r\n");
            contlen += strlen(tmpstr) - strlen(recvstr[i]);
            strcpy(recvstr[i], tmpstr);
        } else if (IS_TYPE_OF(recvstr[i], CONTENTLEN)) {
            //Content-Length:1114\r\n
            //Content-Length: 1114\r\n
            //Content-Length :1114\r\n
            //Content-Length  :   1114\r\n
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

    PRINT_DBG_HEAD
    print_dbg("replace sip Client over ...dst info [%s]\n", dst);

    return strlen(dst);
}

/**
 * [CClientSipBase::replaceServerInfo 替换平台发给客户端的数据包内容]
 * @param  src   [数据包]
 * @param  ilen  [数据包长度]
 * @param  dst   [替换之后的数据包，出参]
 * @param  regid [登记编号]
 * @return       [成功时返回dst的长度 失败返回负值]
 */
int CClientSipBase::replaceServerInfo(const char *src, int ilen, char *dst, int regid)
{
    PRINT_DBG_HEAD
    print_dbg("replace sip Server begin ...src info [%s]\n", src);

    int maxreg = ARRAY_SIZE(m_regtable);
    if ((src == NULL) || (dst == NULL) || (ilen < 0) || (regid < 0) || (regid >= maxreg)) {
        PRINT_ERR_HEAD
        print_err("para error");
        return -1;
    }

    //取命令
    char chcmd[24] = {0};
    if (getCmd(chcmd, sizeof(chcmd), src)) {
        if (!filterCliSipCmd(chcmd, false, regid)) {
            PRINT_ERR_HEAD
            print_err("filter cmd fail");
            return -1;
        }
    }

    //char INVITE[10]="INVITE";
    //char UPDATE[10]="UPDATE";
    //char ACK[10]="ACK";
    //char PRACK[10]="PRACK";
    //char REGISTER[10]="REGISTER";
    //char CANCEL[10]="CANCEL";
    //char VIAUDP[20]="via: SIP/2.0/UDP ";
    //char FROM[10] = "FROM";
    //char TO[10] = "TO";
    //char MVIDEO[20] = "m=video ";
    //char SIP2[20] = "SIP/2.0";
    char CONTACT[20] = "CONTACT:";
    char OINIP4[10] = "IN IP4 ";
    char INIPV4[10] = "c=IN IP4 ";
    char CONTENTLEN[20] = "Content-Length";
    char CALLID[20] = "Call-ID";
    char BYE[10] = "BYE";
    int part = 0;
    int ipos = 0;
    int res = 0;
    int contlen = 0;
    int contlenid = -1;
    int contlen_offset = 0;//Content-Length中的数字，相对行首的偏移量
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *recvstr[SIP_MAX_LINE_NUM];
    char callid_str[SIP_CALL_ID_LEN] = {0};
    BZERO(recvstr);

    //分行
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
        if (IS_TYPE_OF(recvstr[i], CONTACT)) {
            //Contact: <sip:32011501003000000001@172.18.13.188:5062>\r\n
            //Contact: <sip:2001$37060200081320000014@37.48.8.61:5060>\r\n
            char *pat = index(recvstr[i] + strlen(CONTACT), '@');
            if (pat != NULL) {
                if (index(pat, ':') != NULL) {
                    strncpy(tmpstr, recvstr[i], pat - recvstr[i] + 1);
                    strcat(tmpstr, m_gapinip);
                    strcat(tmpstr, index(pat, ':'));
                    strcpy(recvstr[i], tmpstr);
                } else {
                    PRINT_ERR_HEAD
                    print_err("no find [:][%s]", recvstr[i]);
                }
            } else {
                //Contact: <sip:172.20.20.86:5061>
                char *p1 = index(recvstr[i] + strlen(CONTACT) + 1, ':');
                if (p1 != NULL) {
                    char *p2 = index(p1 + 1, ':');
                    if (p2 != NULL) {
                        strncpy(tmpstr, recvstr[i], p1 - recvstr[i] + 1);
                        strcat(tmpstr, m_gapinip);
                        strcat(tmpstr, p2);
                        strcpy(recvstr[i], tmpstr);
                    }
                }
            }
        } else if (IS_TYPE_OF(recvstr[i], INIPV4)) {
            //c=IN IP4 37.48.8.38\r\n
            strncpy(tmpstr, recvstr[i], strlen(INIPV4));
            strcat(tmpstr, getChannelOutIP(callid_str));
            strcat(tmpstr, "\r\n");
            contlen += strlen(tmpstr) - strlen(recvstr[i]);
            strcpy(recvstr[i], tmpstr);
        } else if (IS_TYPE_OF(recvstr[i], "o=")) {
            //o=H3C 0 0 IN IP4 37.48.8.38\r\n
            char *ptr = strstr(recvstr[i], OINIP4);
            if (ptr == NULL) {
                PRINT_ERR_HEAD
                print_err("not find OINIP4[%s]", recvstr[i]);
                continue;
            }
            strncpy(tmpstr, recvstr[i], strlen(recvstr[i]) - strlen(ptr) + strlen(OINIP4));
            strcat(tmpstr, getChannelOutIP(callid_str));
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

    PRINT_DBG_HEAD
    print_dbg("replace Sip Server over ...dst info [%s]\n", dst);

    return strlen(dst);
}
#endif
