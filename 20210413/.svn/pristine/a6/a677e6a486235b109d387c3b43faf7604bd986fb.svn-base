/*******************************************************************************************
*文件:  StartRTSPInst.cpp
*描述:  开启RTSP任务实例
*作者:  王君雷
*日期:  2017-03
*修改:
*   线程ID统一使用pthread_t类型,解决64位系统段错误问题                 ------> 2018-08-07
*   不再串行的记录访问日志;使用zlog                                    ------> 2020-01-07
*   访问日志支持记录MAC字段,暂设置为空                                 ------> 2020-01-16 wjl
*******************************************************************************************/
#include <pthread.h>
#include <errno.h>
#include <netinet/tcp.h>
#include "StartRTSPInst.h"
#include "simple.h"
#include "define.h"
#include "common.h"
#include "quote_global.h"
#include "FCLogContainer.h"
#include "debugout.h"

/**
 * [StartRTSPInst 启动RTSP处理实例]
 * @param  rule  [规则指针]
 * @param  tip   [代理IP]
 * @param  midip [中间跳转IP]
 * @param  dip   [目的服务器IP]
 * @param  appno [应用编号]
 * @return       [成功返回0]
 */
int StartRTSPInst(CSYSRULES *rule, char *tip, char *midip, char *dip, int appno)
{
    if ((rule == NULL) || (tip == NULL) || (midip == NULL) || (dip == NULL) ) {
        PRINT_ERR_HEAD
        print_err("start rtsp para null[%s:%s:%s:%d]", tip, midip, dip, appno);
        return -1;
    }

    RTSPPara *ppara = (RTSPPara *)malloc(sizeof(RTSPPara));
    if (ppara == NULL) {
        PRINT_ERR_HEAD
        print_err("rtsp malloc fail %s", strerror(errno));
        return -1;
    }
    memset(ppara, 0, sizeof(RTSPPara));
    ppara->rule = rule;
    strcpy(ppara->tip, tip);
    strcpy(ppara->midip, midip);
    strcpy(ppara->dip, dip);
    ppara->appno = appno;
    strcpy(ppara->tport, rule->m_service[appno]->m_tport);

    //创建监听线程
    pthread_t thid = 0;
    int ret = pthread_create(&thid, NULL, &RTSPListenThread, (void *)ppara);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("rtsp craete thread fail %d", ret);
        free(ppara);
        return -1;
    }
    return 0;
}

/**
 * [RTSPListenThread 监听线程函数]
 * @param  arg [RTSPPara参数]
 * @return     [未使用]
 */
void *RTSPListenThread(void *arg)
{
    pthread_setself("rtsplisten");

    RTSPPara inpara = *(RTSPPara *)arg;
    free(arg);

    int fd = create_and_bind_tcp(inpara.tip, atoi(inpara.tport));
    if (fd == -1) {
        PRINT_ERR_HEAD
        print_err("rtsp bind tcp fail[%s:%s]", inpara.tip, inpara.tport);
        return NULL;
    }

    if (listen(fd, 100) == -1) {
        PRINT_ERR_HEAD
        print_err("rtst listen fail %s", strerror(errno));
        close(fd);
        return NULL;
    }
    PRINT_DBG_HEAD
    print_dbg("rtsp listen ok[%s:%s]", inpara.tip, inpara.tport);

    int seq = 0;
    struct sockaddr_in addr;
    socklen_t addrlen;
    int infd = 0;
    bool insrcflag = false;
    char authname[AUTH_NAME_LEN] = {0};
    char srcip[IP_STR_LEN] = {0};
    char srcport[PORT_STR_LEN] = {0};

    while (1) {
        BZERO(addr);
        BZERO(authname);
        addrlen = sizeof(addr);
        infd = 0;
        insrcflag = false;

        infd = accept(fd, (struct sockaddr *)&addr, &addrlen);
        if (infd <= 0) {
            PRINT_ERR_HEAD
            print_err("rtsp accept fail %d,%s", infd, strerror(errno));
            continue;
        }

        int yes = 1;
        setsockopt(infd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));
        if (g_ckauth) {
            if (GetAuthName(inet_ntoa(addr.sin_addr), authname, sizeof(authname)) < 0) {
                close(infd);
                continue;
            }
        }

        for (int i = 0; i < inpara.rule->m_sobjectnum; i++) {
            if (IPInRange(inpara.rule->m_sobject[i]->m_ipaddress, inet_ntoa(addr.sin_addr))) {
                insrcflag = true;
                break;
            }
        }
        if (!insrcflag) {
            BZERO(srcip);
            BZERO(srcport);
            strcpy(srcip, inet_ntoa(addr.sin_addr));
            sprintf(srcport, "%d", ntohs(addr.sin_port));

            CLOGMANAGE log_mng;
            if (log_mng.Init(g_iflog && inpara.rule->m_service[inpara.appno]->m_cklog) == E_OK) {
                log_mng.WriteLinkLog(srcip, inpara.tip, srcport, inpara.tport,
                                     LOG_CONTENT_RTSP_REFUSE, "", "");
                log_mng.DisConnect();
            }
            PRINT_ERR_HEAD
            print_err("rtsp src obj[%s] not in sobjs", srcip);
            close(infd);
            continue;
        }
        //时间模式由网闸另一端去处理即可
        //传递给线程的参数
        RTSPPara *ppara = (RTSPPara *)malloc(sizeof(RTSPPara));
        if (ppara == NULL) {
            PRINT_ERR_HEAD
            print_err("rtsp malloc fail %s", strerror(errno));
            close(infd);
            continue;
        }
        memset(ppara, 0, sizeof(RTSPPara));
        ppara->infd = infd;
        strcpy(ppara->tip, inpara.tip);
        strcpy(ppara->midip, inpara.midip);
        strcpy(ppara->dip, inpara.dip);
        strcpy(ppara->tport, inpara.tport);
        ppara->appno = inpara.appno;
        ppara->rule = inpara.rule;
        strcpy(ppara->authname, authname);
        ppara->seqno = ++seq;

        pthread_t thid = 0;
        int ret = pthread_create(&thid, NULL, &RTSPCliProcess, (void *)ppara);
        if (ret != 0) {
            PRINT_ERR_HEAD
            print_err("rtsp craete cli thread fail %d", ret);
            close(infd);
            free(ppara);
            continue;
        }
        usleep(1000);
    }

    PRINT_ERR_HEAD
    print_err("rtsp listen thread will exit");
    close(fd);
    return NULL;
}

/**
 * [RTSPCliProcess RTSP客户端处理函数]
 * @param  arg [TRSPPara结构指针]
 * @return     [未收用]
 */
void *RTSPCliProcess(void *arg)
{
    pthread_setself("rtspcliprocess");

    RTSPPara para = *(RTSPPara *)arg;
    free(arg);
    int midfd = socket(AF_INET, SOCK_STREAM, 0);
    if (midfd < 0) {
        PRINT_ERR_HEAD
        print_err("rtsp socket fail[%s]", strerror(errno));
        close(para.infd);
        return NULL;
    }

    int yes = 1;
    setsockopt(midfd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

    struct sockaddr_in addrmid;
    BZERO(addrmid);
    addrmid.sin_family = AF_INET;
    addrmid.sin_port = htons(atoi(para.tport));
    int ret = inet_pton(AF_INET, para.midip, (void *)&addrmid.sin_addr);
    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("rtsp inet_pton fail[%d,%s,%s]", ret, para.midip, strerror(errno));
        close(para.infd);
        close(midfd);
        return NULL;
    }

    ret = connect(midfd, (struct sockaddr *)&addrmid, sizeof(addrmid));
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("rtsp connect fail[%d,%s,%s]", ret, para.midip, strerror(errno));
        close(para.infd);
        close(midfd);
        return NULL;
    }

    fd_set fds;
    int maxfd = 0;
    unsigned char buff[MAX_BUF_LEN] = {0};
    unsigned char bufftmp[MAX_BUF_LEN] = {0};
    char cherror[1024] = {0};
    char proxyipbuff[IP_STR_LEN] = {0};
    char destipbuff[IP_STR_LEN] = {0};
    sprintf(proxyipbuff, "rtsp://%s:", para.tip);
    sprintf(destipbuff, "rtsp://%s:", para.dip);

    while (1) {
        BZERO(cherror);
        FD_ZERO(&fds);
        FD_SET(para.infd, &fds);
        FD_SET(midfd, &fds);
        maxfd = MAX(para.infd , midfd);

        ret = select(maxfd + 1, &fds, NULL, NULL, NULL);
        if (ret == 0) {
            continue;//timeout
        } else if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("rtsp select error[%d,%s]", ret, strerror(errno));
            close(para.infd);
            close(midfd);
            return NULL;
        }

        if (FD_ISSET(para.infd, &fds)) {
            BZERO(buff);
            int n = read(para.infd, buff, sizeof(buff) - 8);
            if (n <= 0) {
                PRINT_ERR_HEAD
                print_err("rtsp read error[%d,%s]", n, strerror(errno));
                close(para.infd);
                close(midfd);
                return NULL;
            }

            if (DecodeRequest(buff, n, cherror, &para)) {
                if (AnalyseCmdRule(para.ch_cmd, para.ch_url, cherror, &para)) {
                    RecordCallLog(&para, cherror, true);
                    if (strstr(para.ch_url, proxyipbuff) != NULL) {//替换IP
                        for (int i = 0; i < n - (int)strlen(proxyipbuff); i++) {
                            if (memcmp(buff + i, proxyipbuff, strlen(proxyipbuff)) == 0) {
                                memcpy(bufftmp, buff, i);
                                memcpy(bufftmp + i, destipbuff, strlen(destipbuff));
                                memcpy(bufftmp + i + strlen(destipbuff),
                                       buff + i + strlen(proxyipbuff), n - strlen(proxyipbuff) - i);
                                n += strlen(destipbuff) - strlen(proxyipbuff);
                                memcpy(buff, bufftmp, n);
                                break;
                            }
                        }
                    }
                } else {
                    RecordCallLog(&para, cherror, false);
                    close(para.infd);
                    close(midfd);
                    return NULL;
                }
            }
            int m = write(midfd, buff, n);
            if (m != n) {
                PRINT_ERR_HEAD
                print_err("rtsp write error[%d,%s]", m, strerror(errno));
                close(para.infd);
                close(midfd);
                return NULL;
            }
        }

        if (FD_ISSET(midfd, &fds)) {
            BZERO(buff);
            int n = read(midfd, buff, sizeof(buff));
            if (n <= 0) {
                PRINT_ERR_HEAD
                print_err("rtsp read error[%d,%s]", n, strerror(errno));
                close(para.infd);
                close(midfd);
                return NULL;
            }

            int m = write(para.infd, buff, n);
            if (m != n) {
                PRINT_ERR_HEAD
                print_err("rtsp write error[%d,%s]", m, strerror(errno));
                close(para.infd);
                close(midfd);
                return NULL;
            }
        }
    }
    close(para.infd);
    close(midfd);
    return NULL;
}

/**
 * [DecodeRequest 解析请求]
 * @param  data         [应用层数据包]
 * @param  datasize     [数据包长度]
 * @param  error_reason [出错原因 出参]
 * @param  ppara        [RTSPPara指针]
 * @return              [解析成功返回true]
 */
bool DecodeRequest(unsigned char *data, int datasize, char *error_reason, RTSPPara *ppara)
{
    unsigned char ucflag[2] = {0x0d, 0x0a};//回车换行
    unsigned char tucflag[1] = {0x20};//空格
    int offset_0d0a = 0;
    int cmd_len = 0;
    int url_len = 0;
    BZERO(ppara->ch_cmd);
    BZERO(ppara->ch_url);

    if (data == NULL || datasize <= 0) {
        return false;
    }
    //查找第一个0d0a的偏移量
    for (offset_0d0a = 0; offset_0d0a < datasize - 1; offset_0d0a++) {
        if (memcmp(data + offset_0d0a, ucflag, 2) == 0) {
            break;
        }
    }
    if (offset_0d0a == datasize - 1) {
        strcpy(error_reason, RTSP_PROTO_ERROR);
        return false;
    }

    //取出命令
    for (cmd_len = 0; cmd_len < offset_0d0a; cmd_len++) {
        if (data[cmd_len] == tucflag[0]) {
            break;
        }
    }
    if (cmd_len == offset_0d0a) {
        strcpy(error_reason, RTSP_PROTO_ERROR);
        return false;
    }
    memcpy(ppara->ch_cmd, data, MIN(cmd_len, (int)sizeof(ppara->ch_cmd) - 1));

    //取URL
    for (url_len = cmd_len + 1; url_len < offset_0d0a; url_len++) {
        if (data[url_len] == tucflag[0]) {
            break;
        }
    }
    if (url_len == offset_0d0a) {
        strcpy(error_reason, RTSP_PROTO_ERROR);
        return false;
    }
    memcpy(ppara->ch_url, data + cmd_len + 1, MIN((url_len - cmd_len - 1), (int)sizeof(ppara->ch_url) - 1));

    //如果url中有单引号,替换为空格 否则后面组装sql语句时可能会出错
    for (int i = 0; i < (int)strlen(ppara->ch_url); i++) {
        if (ppara->ch_url[i] == '\'') {
            ppara->ch_url[i] = ' ';
        }
    }
    return true;
}

/**
 * [AnalyseCmdRule 过滤命令参数]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @param  ppara   [RTSPPara指针]
 * @return         [允许通过返回true]
 */
bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror, RTSPPara *ppara)
{
    PRINT_DBG_HEAD
    print_dbg("rtsp analyse cmd[%s] para[%s]", chcmd, chpara);

    CCommon m_common;
    CSERVICECONF *service = ppara->rule->m_service[ppara->appno];
    bool bflag = service->m_IfExec;

    for (int i = 0; i < service->m_cmdnum; i++) {
        if (strcasecmp(chcmd, service->m_cmd[i]->m_cmd) == 0) {
            if (m_common.casestrstr((const unsigned char *)chpara,
                                    (const unsigned char *)service->m_cmd[i]->m_parameter, 0,
                                    strlen(chpara)) == E_COMM_OK) {
                bflag = service->m_cmd[i]->m_action;
                break;
            }
        }
    }
    if (!bflag) {
        PRINT_ERR_HEAD
        print_err("rtsp analyse cmd result, forbid[%s:%s]", chcmd, chpara);
        sprintf(cherror, "%s", RTSP_PERM_FORBID);
    }
    return bflag;
}

/**
 * [RecordCallLog 记录访问日志]
 * @param ppara   [TRSPPara指针]
 * @param cherror [出错信息]
 * @param result  [日志结果]
 */
void RecordCallLog(RTSPPara *ppara, const char *cherror, bool result)
{
    PRINT_DBG_HEAD
    print_dbg("rtsp record log.[%s,%s,%s]", ppara->ch_cmd, ppara->ch_url, result ? "pass" : "forbid");

    if ((g_iflog && ppara->rule->m_service[ppara->appno]->m_cklog) || g_syslog) {
        char src_ip[IP_STR_LEN] = {0};
        char src_port[PORT_STR_LEN] = {0};
        char gap_ip[IP_STR_LEN] = {0};
        char gap_port[PORT_STR_LEN] = {0};
        struct sockaddr_in addr;
        socklen_t socklen = sizeof(addr);

        if (getpeername(ppara->infd, (struct sockaddr *)&addr, &socklen) == 0) {
            strcpy(src_ip, inet_ntoa(addr.sin_addr));
            sprintf(src_port, "%d", ntohs(addr.sin_port));
        }
        if (getsockname(ppara->infd, (struct sockaddr *)&addr, &socklen) == 0) {
            strcpy(gap_ip, inet_ntoa(addr.sin_addr));
            sprintf(gap_port, "%d", ntohs(addr.sin_port));
        }

        CallLogPara *p = new CallLogPara;
        if (p != NULL) {
            if (p->SetValues(ppara->authname, src_ip, gap_ip, src_port, gap_port, "", "",
                             ppara->rule->m_service[ppara->appno]->m_asservice,
                             ppara->ch_cmd, ppara->ch_url, result ? D_SUCCESS : D_REFUSE, cherror)) {
                LogContainer &s1 = LogContainer::GetInstance();
                s1.PutPara(p);
            } else {
                PRINT_ERR_HEAD
                print_err("set values fail[authname %s, sip %s, dip %s, sport %s, dport %s, %s:%s:%s:%s:%s]",
                          ppara->authname, src_ip, gap_ip, src_port, gap_port,
                          ppara->rule->m_service[ppara->appno]->m_asservice,
                          ppara->ch_cmd,
                          ppara->ch_url,
                          result ? "pass" : "forbid",
                          cherror);
                delete p;
            }
        }
    }
}
