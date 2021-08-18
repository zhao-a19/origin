/*******************************************************************************************
*文件:  StartOracleInst.cpp
*描述:  开启oracle任务实例
*作者:  王君雷
*日期:  2016-03
*修改:
*   线程ID统一使用pthread_t类型,解决64位系统段错误问题，使用zlog、utf8编码------> 2018-08-07
*   增加收发包缓冲区大小;修改误判为重定向包时，没有把包发出去的BUG        ------> 2019-06-08
*   不再阻塞串行写日志                                                    ------> 2020-01-07
*   访问日志支持记录MAC字段,暂设置为空                                    ------> 2020-01-16 wjl
*   优化改包部分逻辑                                                      ------> 2020-10 ll
*   oracle访问模块，添加英文的中括号为合法的表名组成部分                     ------> 2020-12-30 wjl
*   删除GetTableName函数，共用FCSingle.cpp中定义的函数                     ------> 2020-12-31 wjl
*******************************************************************************************/
#include <pthread.h>
#include <netinet/tcp.h>
#include "StartOracleInst.h"
#include "simple.h"
#include "define.h"
#include "common.h"
#include "quote_global.h"
#include "FCPeerExecuteCMD.h"
#include "FCLogContainer.h"
#include "debugout.h"

/* 缓存最大长度 */
#define ORCL_MAX_BUF_LEN 102400
/* 请求语句首字符串最大查找距离 */
#define MAX_LOOKUP_LEN_REQ         0x200

/*
 * 参考wireshark源码
 * https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-tns.c
 */

/* Packet Types */
#define TNS_TYPE_CONNECT        1
#define TNS_TYPE_ACCEPT         2
#define TNS_TYPE_ACK            3
#define TNS_TYPE_REFUSE         4
#define TNS_TYPE_REDIRECT       5
#define TNS_TYPE_DATA           6
#define TNS_TYPE_NULL           7
#define TNS_TYPE_ABORT          9
#define TNS_TYPE_RESEND         11
#define TNS_TYPE_MARKER         12
#define TNS_TYPE_ATTENTION      13
#define TNS_TYPE_CONTROL        14
#define TNS_TYPE_MAX            19

#define TNS_HEADER_LEN          8
#define TNS_CONN_LEN_OFFSET     0x18
#define TNS_CONN_OFFSET_OFFSET  0x1a

static const char *m_DefSqlOper[C_MAX_SQLOPER] = {
    "SELECT",
    "INSERT",
    "DELETE",
    "UPDATE",
    "DROP",
    "CREATE",
    "ALTER",
    "GRANT",
    "REVOKE",
    "COMMIT",
    "ROLLBACK"
};

bool GetTableName(const char *ch, int len, char *param);

/**
 * [StartOracleInst 运行一个ORACLE处理线程]
 * @param  rule  [规则指针]
 * @param  tip   [代理IP]
 * @param  midip [内部跳转IP]
 * @param  dip   [目的IP]
 * @param  appno [应用编号]
 * @return       [成功返回0]
 */
int StartOracleInst(CSYSRULES *rule, char *tip, char *midip, char *dip, int appno)
{
    PRINT_DBG_HEAD
    print_dbg("start oracle inst begin");

    int ret = 0;
    pthread_t thid = 0;
    OraclePara *ppara = NULL;

    if ((rule == NULL) || (tip == NULL) || (midip == NULL) || (dip == NULL) ) {
        PRINT_ERR_HEAD
        print_err("start orcl inst para null");
        ret = -1;
        goto _out;
    }

    ppara = (OraclePara *)malloc(sizeof(OraclePara));
    if (ppara == NULL) {
        PRINT_ERR_HEAD
        print_err("orcl para malloc fail");
        ret = -1;
        goto _out;
    }
    memset(ppara, 0, sizeof(OraclePara));

    PRINT_DBG_HEAD
    print_dbg("tip[%s] midip[%s] dip[%s] appno[%d]", tip, midip, dip, appno);

    ppara->rule = rule;
    strcpy(ppara->tip, tip);
    strcpy(ppara->midip, midip);
    strcpy(ppara->dip, dip);
    ppara->appno = appno;
    strcpy(ppara->tport, rule->m_service[appno]->m_tport);

    ret = pthread_create(&thid, NULL, OracleListenThread, (void *)ppara);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("create thread fail");
        free(ppara);
        ret = -1;
        goto _out;
    }

_out:
    PRINT_DBG_HEAD
    print_dbg("start oracle inst over[%d]", ret);
    return ret;
}

/**
 * [OracleListenThread oracle监听端口线程]
 * @param  arg [description]
 * @return     [description]
 */
void *OracleListenThread(void *arg)
{
    pthread_setself("oraclelisten");

    char err_buf[256] = {0};

    PRINT_DBG_HEAD
    print_dbg("listen thread begin");

    OraclePara inpara = *(OraclePara *)arg;
    free(arg);

    int fd = 0;
    while ((fd = create_and_bind_tcp(inpara.tip, atoi(inpara.tport))) < 0) {
        PRINT_ERR_HEAD
        print_err("bind[%s]:%s fail,retry", inpara.tip, inpara.tport);
        sleep(1);
    }

    while (listen(fd, 100) == -1) {
        PRINT_ERR_HEAD
        print_err("listen[%s]:%s fail[%s],retry", inpara.tip, inpara.tport, strerror_r(errno, err_buf, sizeof(err_buf)));
        sleep(1);
    }

    PRINT_DBG_HEAD
    print_dbg("orcl listen[%s]:%s ok", inpara.tip, inpara.tport);

    int seq = 0;
    struct sockaddr_in addr;
    socklen_t addrlen;
    int infd = 0;
    bool insrcflag = false;
    char authname[AUTH_NAME_LEN];
    char srcip[IP_STR_LEN];
    char srcport[PORT_STR_LEN];

    while (1) {
        BZERO(addr);
        BZERO(authname);
        addrlen = sizeof(addr);
        infd = 0;
        insrcflag = false;

        infd = accept(fd, (struct sockaddr *)&addr, &addrlen);
        if (infd <= 0) {
            PRINT_ERR_HEAD
            print_err("orcl accept fail fd[%d] errinfo[%s]", infd, strerror_r(errno, err_buf, sizeof(err_buf)));
            continue;
        }

        int yes = 1;
        setsockopt(infd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

        strcpy(srcip, inet_ntoa(addr.sin_addr));
        sprintf(srcport, "%d", ntohs(addr.sin_port));

        if (g_ckauth && (GetAuthName(srcip, authname, sizeof(authname)) < 0)) {
            close(infd);
            PRINT_ERR_HEAD
            print_err("orcl get authname fail[%s]", srcip);
            continue;
        }

        //检查IP是否在源对象内
        for (int i = 0; i < inpara.rule->m_sobjectnum; i++) {
            if (IPInRange(inpara.rule->m_sobject[i]->m_ipaddress, srcip)) {
                insrcflag = true;
                break;
            }
        }
        if (!insrcflag) {
            if (g_iflog && inpara.rule->m_service[inpara.appno]->m_cklog) {
                CLOGMANAGE log_mng;
                if (log_mng.Init() == E_OK) {
                    log_mng.WriteLinkLog(srcip, inpara.tip, srcport, inpara.tport,
                                         LOG_CONTENT_ORCL_REFUSE, "", "");
                    log_mng.DisConnect();
                }
            }
            close(infd);
            PRINT_INFO_HEAD
            print_info("not in srcobjs[%s]", srcip);
            continue;
        }

        //时间模式由网闸另一端去处理即可

        //传递给线程的参数
        OraclePara *ppara = (OraclePara *)malloc(sizeof(OraclePara));
        if (ppara == NULL) {
            PRINT_ERR_HEAD
            print_err("orcl malloc fail");
            close(infd);
            continue;
        }
        memset(ppara, 0, sizeof(OraclePara));
        ppara->infd = infd;
        strcpy(ppara->tip, inpara.tip);
        strcpy(ppara->midip, inpara.midip);
        strcpy(ppara->dip, inpara.dip);
        strcpy(ppara->tport, inpara.tport);
        ppara->appno = inpara.appno;
        ppara->rule = inpara.rule;
        strcpy(ppara->authname, authname);
        ppara->seqno = ++seq;

        //创建新线程
        pthread_t thid = 0;
        int ret = pthread_create(&thid, NULL, OracleCliProcess, (void *)ppara);
        if (ret != 0) {
            PRINT_ERR_HEAD
            print_err("create orcl cli thread fail");
            close(infd);
            free(ppara);
            continue;
        }
        usleep(1000);
    }

    close(fd);
    PRINT_ERR_HEAD
    print_err("listen thread over");
    return NULL;
}

/*
 * (参考wireshark)
 * In some messages (observed in Oracle12c) packet length has 4 bytes
 * instead of 2.
 *
 * If packet length has 2 bytes, length and checksum equals two unsigned
 * 16-bit numbers. Packet checksum is generally unused (equal zero),
 * but 10g client may set 2nd byte to 4.
 *
 * Else, Oracle 12c combine these two 16-bit numbers into one 32-bit.
 * This number represents the packet length. Checksum is omitted.
 */

/**
 * [get_pdu_len  获取tns包长]
 * @param  data  [payload 指针]
 * @return       [成功返回长度, 失败-1]
 */
static int get_pdu_len(unsigned char *data)
{
    int chksum;
    int length;
    unsigned char *p = data;

    chksum = (p[2] << 8) | p[3];

    if (chksum == 0 || chksum == 4) {
        length = (p[0] << 8) | p[1];
    } else {
        length = (p[2] << 8) | p[3];

        if (p[0] != 0x00 || p[1] != 0x00) {
            PRINT_ERR_HEAD
            print_err("tns len error [%02x][%02x][%02x][%02x]", p[0], p[1], p[2], p[3]);
            /* 解析失败 */
            length = -1;
        }
    }

    return length > 0 ? length : -1;
}

/**
 * [set_pdu_len  设置tns头部长度]
 * @param  data  [payload 指针]
 * @param  len   [包长]
 * @return       [成功返回0]
 */
static int set_pdu_len(unsigned char *data, int len)
{
    int chksum;
    unsigned char *p = data;

    chksum = (p[2] << 8) | p[3];

    if (chksum == 0 || chksum == 4) {
        p[0] = len / 256;
        p[1] = len % 256;
    } else {
        p[2] = len / 256;
        p[3] = len % 256;
    }

    return 0;
}

/**
 * [do_conn_str          处理connect 包]
 * @param  pktBuf        [缓冲结构体指针]
 * @param  pkt1_len      [第一个包长]
 * @param  pkt2_len      [第二个包长]
 * @param  conn_offset   [connect string 偏移]
 * @param  conn_len      [connect string 长度]
 * @param  para          [oracle线程参数信息]
 * @return               [成功返回0, 失败-1]
 */
int do_conn_str(PktBuff *pktBuf, int pkt1_len, int pkt2_len, int conn_offset, int conn_len, OraclePara *para)
{
    char from_str[100] = {0};          //proxyconnstr
    char to_str[100] = {0};            //racconnstr
    int difference = 0;
    int from_len = 0;
    int to_len = 0;

    int offset = 0;
    char *p = NULL;
    int len = 0;

    snprintf(from_str, 100, "(HOST=%s)(PORT=%s)", para->tip, \
             para->rule->m_service[para->appno]->m_tport);
    snprintf(to_str, 100, "(HOST=%s)(PORT=%s)", para->dip, \
             para->rule->m_service[para->appno]->m_dport);

    from_len = strlen(from_str);
    to_len = strlen(to_str);
    difference = to_len - from_len;

    /* 确保末尾有NULL */
    pktBuf->p[pktBuf->len] = '\0';
    p = (char *)pktBuf->p;

    /* 取建立连接字符串信息 */
    if (pkt2_len == 0) {
        /* 只有一个包 */
        p = p + conn_offset;
    } else {
        /* 两个包 */
        p = p + conn_offset + TNS_HEADER_LEN + 2;
    }

    p = strcasestr(p, from_str);
    if (NULL == p)
        return -1;

    if (pktBuf->len + difference + 1 > pktBuf->buffer_len) {
        /* 没空间 */
        PRINT_ERR_HEAD
        print_err("No space in buffer [%d]", pktBuf->buffer_len);
        return -1;
    }

    /* 替换建立连接信息 from_str 为 to_str */
    len = pktBuf->len - (p + from_len - (char *)pktBuf->p);
    memmove(p + to_len, p + from_len, len);
    memcpy(p, to_str, to_len);

    /* 更新缓冲 buffer 长度 */
    pktBuf->len += difference;
    pktBuf->p[pktBuf->len] = '\0';

    if (pkt2_len == 0) {
        /* 更新 tns 头长度 */
        pkt1_len += difference;
        set_pdu_len(pktBuf->p, pkt1_len);
    } else {
        /* 更新第二个包 tns 头长度 */
        pkt2_len += difference;
        set_pdu_len(pktBuf->p + pkt1_len, pkt2_len);
    }

    /* 更新包内容 conn_len 字段 */
    conn_len += difference;
    offset = TNS_CONN_LEN_OFFSET;
    pktBuf->p[offset] = conn_len / 256;
    pktBuf->p[offset + 1] = conn_len % 256;

    PRINT_INFO_HEAD
    print_info("update connect pkt: [%s] -> [%s] OK!", from_str, to_str);
    return 0;
}

/**
 * [do_in_fd         处理客户端请求包]
 * @param  infd      [客户端fd]
 * @param  midfd     [内部跳转fd]
 * @param  pktBuf    [缓冲结构体指针]
 * @param  cherror   [错误信息]
 * @param  para      [oracle线程参数信息]
 * @return           [成功返回0, 失败-1]
 */
int do_in_fd(int infd, int midfd, PktBuff *pktBuf, char *cherror, OraclePara *para)
{
    unsigned char *p = NULL;
    char err_buf[256] = {0};
    int offset = 0;
    int len = 0;
    int ret = 0;

    int pkt1_len = 0;
    int pkt2_len = 0;
    int conn_offset = 0;
    int conn_len = 0;

    /* 缓冲 buffer 剩余长度 */
    len = pktBuf->buffer_len - pktBuf->len - 1;
    if (len <= 0) {
        PRINT_ERR_HEAD
        print_err("no space in buffer, %d : %d", \
                  pktBuf->buffer_len, pktBuf->len);
        goto in_fd_parse_error;
    }

    ret = read(infd, pktBuf->p + pktBuf->len, len);
    if (-1 == ret) {
        PRINT_ERR_HEAD
        print_err("read fail(%s) ret[%d]", \
                  strerror_r(errno, err_buf, sizeof(err_buf)), ret);
        pktBuf->len = 0;
        return -1;
    } else if (0 == ret) {
        PRINT_INFO_HEAD
        print_info("peer shutdown");
        return -1;
    }

    pktBuf->len += ret;
    pktBuf->p[pktBuf->len] = '\0';
    p = pktBuf->p;

    /* 解析失败 */
    if (pktBuf->len < TNS_HEADER_LEN || p[4] < TNS_TYPE_CONNECT || p[4] > TNS_TYPE_MAX)
        goto in_fd_parse_error;

    /* connect 信息有时会分成两个包, 由于要改数据包, 可能涉及到缓存*/
    if (p[4] == TNS_TYPE_CONNECT) {
        if (pktBuf->len < TNS_CONN_OFFSET_OFFSET + 2) {
            /* 需要更多数据 */
            PRINT_DBG_HEAD
            print_dbg("need more data[%d]!", pktBuf->len);
            return 0;
        }

        offset = TNS_CONN_LEN_OFFSET;
        conn_len = (p[offset] << 8) | p[offset + 1];
        offset = TNS_CONN_OFFSET_OFFSET;
        conn_offset = (p[offset] << 8) | p[offset + 1];

        pkt1_len = get_pdu_len(p);
        if (-1 == pkt1_len) {
            PRINT_ERR_HEAD
            print_err("tns get len failed!");
            goto in_fd_parse_error;
        }

        pkt2_len = 0;
        if (conn_offset < pkt1_len) {
            /* 所需最小长度 */
            len = conn_offset + conn_len;
            if (pkt1_len < len) {
                /* 解析失败 */
                goto in_fd_parse_error;
            }
        } else {
            if (pktBuf->len < pkt1_len + TNS_HEADER_LEN) {
                /* 需要更多数据 */
                PRINT_DBG_HEAD
                print_dbg("need more data[%d]!", pktBuf->len);
                return 0;
            }

            pkt2_len = get_pdu_len(p + pkt1_len);
            if (-1 == pkt2_len) {
                PRINT_ERR_HEAD
                print_err("tns get len failed!");
                goto in_fd_parse_error;
            }
            if (pkt2_len < conn_len + TNS_HEADER_LEN + 2) {
                /* 解析失败 */
                goto in_fd_parse_error;
            }

            /* 所需最小长度 */
            len = conn_offset + conn_len + TNS_HEADER_LEN + 2;
        }

        if (pktBuf->len < len) {
            /* 需要更多数据 */
            PRINT_DBG_HEAD
            print_dbg("need more data[%d]!", pktBuf->len);
            return 0;
        }

        /* 现在缓冲区有足够长度去解析 */
        ret = do_conn_str(pktBuf, pkt1_len, pkt2_len, conn_offset, conn_len, para);
        if (-1 == ret) {
            /* 失败也通过 */
        }
    } else {
        PRINT_DBG_HEAD
        print_dbg("begin decode request");

        if (DecodeRequest(p, pktBuf->len, cherror, para)) {
            PRINT_DBG_HEAD
            print_dbg("decode request success");

            if (AnalyseCmdRule(para->m_SqlOperName, para->m_TableName, cherror, para)) {
                RecordCallLog(para, cherror, true);
            } else {
                RecordCallLog(para, cherror, false);
                pktBuf->len = 0;
                return -1;
            }
        } else {
            /* 解码失败也让通过 因为可能是用户名密码登陆等 */
            PRINT_DBG_HEAD
            print_dbg("decode request fail");
        }
    }

in_fd_parse_error:
    /* 解析失败，也通过 */
    if (pktBuf->len == 0)
        return 0;

    ret = write(midfd, pktBuf->p, pktBuf->len);
    if (ret != pktBuf->len) {
        PRINT_ERR_HEAD
        print_err("write midfd[%d] fail[%s], [%d] [%d]", midfd, strerror_r(errno, err_buf, sizeof(err_buf)), pktBuf->len, ret);
        pktBuf->len = 0;
        return -1;
    }

    /* 清空缓冲区 */
    pktBuf->len = 0;
    return 0;
}

/**
 * [get_and_bind_tport      找到可用的重定向代理端口并绑定]
 * @param  para             [oracle线程参数信息]
 * @return                  [成功返回文件描述符, 失败-1]
 */

int get_and_bind_tport(OraclePara *para)
{
    int fd = -1;

    while (1) {

        snprintf(para->tredirectport, PORT_STR_LEN, "%d", \
                 (atoi(para->tport) + para->seqno++) % 65535 + 1);

        fd = create_and_bind_tcp(para->tip, atoi(para->tredirectport));
        if (fd == -1) {
            continue;
        }

        if (listen(fd, 100) == -1) {
            close(fd);
            continue;
        } else {
            return fd;
        }
    }

    return -1;
}

/**
 * [do_redirect             处理重定向包]
 * @param  pktBuf           [缓冲结构体指针]
 * @param  pkt1_len         [第一个包长度]
 * @param  pkt2_len         [第二个包长度]
 * @param  redirect_len     [redirect 长度]
 * @param  para             [oracle线程参数信息]
 * @return                  [成功返回0, 失败-1]
 */
int do_redirect(PktBuff *pktBuf, int pkt1_len, int pkt2_len, int redirect_len, OraclePara *para)
{
    char redirectip[IP_STR_LEN] = {0};
    char redirectport[PORT_STR_LEN] = {0};
    char err_buf[256] = {0};
    char from_str[128] = {0};
    char to_str[128] = {0};
    char chcmd[1024] = {0};
    char *p_host = NULL;
    char *p_port = NULL;
    char *p = NULL;

    int difference = 0;
    int from_len = 0;
    int to_len = 0;
    int len = 0;
    int offset = 0;

    OraclePara *para_new = NULL;
    int bind_fd = -1;
    pthread_t tid;

    const char *fmt1 = "%s -t nat -I PREROUTING -d %s -p tcp "
                       "--dport %s -j DNAT --to %s:%s";
    const char *fmt2 = "%s -t nat -D PREROUTING -d %s -p tcp "
                       "--dport %s -j DNAT --to %s:%s";

    /* 确保末尾有NULL */
    pktBuf->p[pktBuf->len] = '\0';

    /* 取重定向信息 */
    if (pkt2_len == 0) {
        /* 只有一个包 */
        p = (char *)pktBuf->p + TNS_HEADER_LEN + 2;
    } else {
        /* 两个包 */
        p = (char *)pktBuf->p + pkt1_len + TNS_HEADER_LEN + 2;
    }

    /* 取重定向服务器ip */
    if ((NULL == (p_host = strcasestr(p, "(host=")))
        || (NULL == (p = strcasestr(p_host + 6, ")")))
        || ((len = (p - (p_host + 6))) >= IP_STR_LEN)) {
        PRINT_ERR_HEAD
        print_err("redirect pkt get host error!");
        goto do_redirect_failed;
    }
    snprintf(redirectip, len + 1, "%s", p_host + 6);

    /* 取重定向服务器port */
    if ((NULL == (p_port = strcasestr(p + 1, "(port=")))
        || (NULL == (p = strcasestr(p_port + 6, ")")))
        || ((len = (p - (p_port + 6))) >= PORT_STR_LEN)) {
        PRINT_ERR_HEAD
        print_err("redirect pkt get port error!");
        goto do_redirect_failed;
    }
    snprintf(redirectport, len + 1, "%s", p_port + 6);

    from_len = p + 1 - p_host;
    if (from_len >= sizeof(from_str)) {
        /* 解析失败 */
        PRINT_ERR_HEAD
        print_err("redirect pkt parse error!");
        goto do_redirect_failed;
    }
    snprintf(from_str, from_len + 1, "%s", p_host);

    /* 找到可用重定向代理端口并绑定 */
    bind_fd = get_and_bind_tport(para);
    if (-1 == bind_fd) {
        PRINT_ERR_HEAD
        print_err("get and bind tport error!");
        goto do_redirect_failed;
    }

    snprintf(to_str, 128, "(host=%s)(port=%s)", para->tip, para->tredirectport);
    to_len = strlen(to_str);
    difference = to_len - from_len;

    if (pktBuf->len + difference + 1 > pktBuf->buffer_len) {
        /* 没空间 */
        PRINT_ERR_HEAD
        print_err("No buffer space!");
        goto do_redirect_failed;
    }

    /* 替换重定向字符串from_str 为 to_str */
    len = pktBuf->len - (p_host + from_len - (char *)pktBuf->p);
    memmove(p_host + to_len, p_host + from_len, len);
    memcpy(p_host, to_str, to_len);

    /* 更新缓冲 buffer 长度 */
    pktBuf->len += difference;
    pktBuf->p[pktBuf->len] = '\0';

    if (pkt2_len == 0) {
        /* 更新 tns 头长度 */
        pkt1_len += difference;
        set_pdu_len(pktBuf->p, pkt1_len);
    } else {
        /* 更新第二个包 tns 头长度 */
        pkt2_len += difference;
        set_pdu_len(pktBuf->p + pkt1_len, pkt2_len);
    }

    /* 更新包内容 重定向长度 字段 */
    redirect_len += difference;
    offset = TNS_HEADER_LEN;
    pktBuf->p[offset] = redirect_len / 256;
    pktBuf->p[offset + 1] = redirect_len % 256;

    PRINT_INFO_HEAD
    print_info("update redirect pkt: [%s] -> [%s] OK!", from_str, to_str);

    //要求网闸另一端修改iptables, 放行重定向服务器ip, port
    snprintf(chcmd, sizeof(chcmd), fmt1, IPTABLES, para->midip, \
             para->tredirectport, redirectip, redirectport);

    //后续清理使用
    snprintf(para->m_chcmd, 1024, fmt2, IPTABLES, para->midip, \
             para->tredirectport, redirectip, redirectport);

    if (PeerExecuteCMD(chcmd) < 0) {
        PRINT_ERR_HEAD
        print_err("peer execute cmd error[%s]", chcmd);
        goto do_redirect_failed;
    }

    PRINT_INFO_HEAD
    print_info("peer execute cmd ok[%s]", chcmd);

    para_new = (OraclePara *)malloc(sizeof(OraclePara));
    if (para_new == NULL) {
        PRINT_ERR_HEAD
        print_err("malloc fail(%s)", strerror_r(errno, err_buf, sizeof(err_buf)));
        goto do_redirect_failed;
    }
    memcpy(para_new, para, sizeof(OraclePara));

    /* 通过para_new->infd，传递bind_fd给新线程 */
    para_new->infd = bind_fd;
    if (0 != pthread_create(&tid, NULL, redirect_ser_process, para_new)) {
        PRINT_ERR_HEAD
        print_err("create redirect thread fail(%s)", strerror_r(errno, err_buf, sizeof(err_buf)));
        goto do_redirect_failed;
    }

    PRINT_INFO_HEAD
    print_info("new redirect thread!");
    return 0;

do_redirect_failed:
    if (-1 != bind_fd)
        close(bind_fd);
    if (NULL != para_new)
        free(para_new);
    if ('\0' != para->m_chcmd[0])
        PeerExecuteCMD(para->m_chcmd);
    return -1;
}

/**
 * [do_mid_fd        处理服务器返回包]
 * @param  infd      [客户端fd]
 * @param  midfd     [内部跳转fd]
 * @param  pktBuf    [缓冲结构体指针]
 * @param  cherror   [错误信息]
 * @param  para      [oracle线程参数信息]
 * @return           [成功返回0, 失败-1]
 */
int do_mid_fd(int infd, int midfd, PktBuff *pktBuf, char *cherror, OraclePara *para)
{
    unsigned char *p;
    char err_buf[256] = {0};

    int offset = 0;
    int len = 0;
    int ret = 0;

    int redirect_len = 0;
    int pkt1_len = 0;
    int pkt2_len = 0;

    /* 缓冲 buffer 剩余长度 */
    len = pktBuf->buffer_len - pktBuf->len - 1;
    if (len <= 0) {
        PRINT_ERR_HEAD
        print_err("no space in buffer, %d : %d", \
                  pktBuf->buffer_len, pktBuf->len);
        goto mid_fd_parse_error;
    }

    ret = read(midfd, pktBuf->p + pktBuf->len, len);
    if (-1 == ret) {
        PRINT_ERR_HEAD
        print_err("read fail(%s) ret[%d]", strerror_r(errno, err_buf, sizeof(err_buf)), ret);
        pktBuf->len = 0;
        return -1;
    } else if (0 == ret) {
        /* 断开连接 */
        PRINT_INFO_HEAD
        print_info("peer shutdown");
        return -1;
    }

    pktBuf->len += ret;
    pktBuf->p[pktBuf->len] = '\0';
    p = pktBuf->p;

    if (pktBuf->len < TNS_HEADER_LEN || p[4] < TNS_TYPE_CONNECT || p[4] > TNS_TYPE_MAX)
        /* 解析失败 */
        goto mid_fd_parse_error;

    /* redirect 信息有时会分成两个包, 由于要改数据包, 可能涉及到缓存*/
    if (p[4] == TNS_TYPE_REDIRECT) {
        /* 包太短 */
        if (pktBuf->len < TNS_HEADER_LEN + 2)
            goto mid_fd_parse_error;

        offset = TNS_HEADER_LEN;
        redirect_len = (p[offset] << 8) | (p[offset + 1]);
        offset += 2;

        pkt1_len = get_pdu_len(p);
        if (-1 == pkt1_len) {
            PRINT_ERR_HEAD
            print_err("tns get len failed!");
            goto mid_fd_parse_error;
        }

        pkt2_len = 0;
        if ((redirect_len + offset) <= pkt1_len) {
            /* 所需最小长度 */
            len = pkt1_len;
        } else {
            if (pktBuf->len < pkt1_len + TNS_HEADER_LEN) {
                /* 需要更多数据 */
                PRINT_DBG_HEAD
                print_dbg("need more data[%d]!", pktBuf->len);
                return 0;
            }

            pkt2_len = get_pdu_len(p + pkt1_len);
            if (-1 == pkt2_len) {
                PRINT_ERR_HEAD
                print_err("tns get len failed!");
                goto mid_fd_parse_error;
            }

            /* 所需最小长度 */
            len = pkt1_len + pkt2_len;
        }

        if (pktBuf->len < len) {
            /* 需要更多数据 */
            PRINT_DBG_HEAD
            print_dbg("need more data[%d]!", pktBuf->len);
            return 0;
        }

        /* 现在缓冲区有足够长度去解析 */
        ret = do_redirect(pktBuf, pkt1_len, pkt2_len, redirect_len, para);
        if (-1 == ret) {
            /* 解析失败，也通过 */
        }
    }

mid_fd_parse_error:
    /* 解析失败，也通过 */
    if (pktBuf->len == 0)
        return 0;

    ret = write(infd, pktBuf->p, pktBuf->len);
    if (ret != pktBuf->len) {
        PRINT_ERR_HEAD
        print_err("write infd[%d] fail[%s] [%d] [%d]", infd, strerror_r(errno, err_buf, sizeof(err_buf)), pktBuf->len, ret);
        pktBuf->len = 0;
        return -1;
    }

    pktBuf->len = 0;
    return 0;
}

/**
 * [OracleCliProcess 处理每个连接上了的客户端的线程]
 * @param  arg [description]
 * @return     [description]
 */
void *OracleCliProcess(void *arg)
{
    pthread_setself("oraclecliproc");

    PktBuff infd_buf = {NULL, 0, 0};
    PktBuff midfd_buf = {NULL, 0, 0};
    char cherror[1024] = {0};
    char err_buf[256] = {0};
    int maxfd = 0;
    fd_set fds;

    OraclePara para = *(OraclePara *)arg;
    free(arg);

    PRINT_DBG_HEAD
    print_dbg("cli thread begin");


    /* 客户端请求缓存 */
    infd_buf.p = (unsigned char *)malloc(ORCL_MAX_BUF_LEN);
    if (NULL == infd_buf.p) {
        PRINT_ERR_HEAD
        print_err("cli thread malloc failed.");
        close(para.infd);
        return NULL;
    }
    /* 服务端返回缓存 */
    midfd_buf.p = (unsigned char *)malloc(ORCL_MAX_BUF_LEN);
    if (NULL == midfd_buf.p) {
        PRINT_ERR_HEAD
        print_err("cli thread malloc failed.");
        close(para.infd);
        free(infd_buf.p);
        return NULL;
    }

    infd_buf.buffer_len = ORCL_MAX_BUF_LEN;
    midfd_buf.buffer_len = ORCL_MAX_BUF_LEN;

    int midfd = socket(AF_INET, SOCK_STREAM, 0);
    if (midfd < 0) {
        PRINT_ERR_HEAD
        print_err("socket fail(%s)", strerror_r(errno, err_buf, sizeof(err_buf)));
        close(para.infd);
        free(infd_buf.p);
        free(midfd_buf.p);
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
        print_err("inet_pton fail(%s)[%s]", strerror_r(errno, err_buf, sizeof(err_buf)), para.midip);
        close(para.infd);
        close(midfd);
        free(infd_buf.p);
        free(midfd_buf.p);
        return NULL;
    }

    ret = connect(midfd, (struct sockaddr *)&addrmid, sizeof(addrmid));
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("connect fail(%s) fd[%d]", strerror_r(errno, err_buf, sizeof(err_buf)), midfd);
        close(para.infd);
        close(midfd);
        free(infd_buf.p);
        free(midfd_buf.p);
        return NULL;
    }

    while (1) {
        cherror[0] = '\0';
        FD_ZERO(&fds);

        FD_SET(para.infd, &fds);
        FD_SET(midfd, &fds);
        maxfd = para.infd > midfd ? para.infd : midfd;

        ret = select(maxfd + 1, &fds, NULL, NULL, NULL);
        if (ret == 0) {
            //timeout
            continue;
        } else if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("select fail(%s) ret[%d]", strerror_r(errno, err_buf, sizeof(err_buf)), ret);
            break;
        }

        if (FD_ISSET(para.infd, &fds)) {
            /* 客户端请求方向数据处理 */
            ret = do_in_fd(para.infd, midfd, &infd_buf, cherror, &para);
            if (-1 == ret)
                break;
        }

        if (FD_ISSET(midfd, &fds)) {
            /* 服务端返回方向数据处理 */
            ret = do_mid_fd(para.infd, midfd, &midfd_buf, cherror, &para);
            if (-1 == ret)
                break;
        }
    }

    close(para.infd);
    close(midfd);
    free(infd_buf.p);
    free(midfd_buf.p);

    PRINT_DBG_HEAD
    print_dbg("cli thread over");
    return NULL;
}


/**
 * [DecodeRequest 解析请求指令]
 * @param  sdata   [数据包]
 * @param  slen    [数据包长度]
 * @param  cherror [用于返回出错信息]
 * @param  ppara   [oracle线程参数信息]
 * @return         [解析成功返回true]
 */
bool DecodeRequest(unsigned char *sdata, int slen, char *cherror, OraclePara *ppara)
{
    PRINT_DBG_HEAD
    print_dbg("decode request begin[%d]", slen);

    bool bflag = false;
    int sqllen = 0;
    char m_Sql[C_MAX_SQLLEN] = {0};

    if (slen <= 40) {
        PRINT_INFO_HEAD
        print_info("packet too short[%d],give up decode request", slen);
        goto _err;
    }

    if ((sdata[4] != 06))
        //|| (sdata[10] != 0x11)
        //|| (sdata[11] != 0x69)
        //|| (sdata[18] != 0x03)
        //|| (sdata[19] != 0x5e)) //request
    {
        PRINT_INFO_HEAD
        print_info("not request.slen[%d]", slen);
        goto _err;
    }

    BZERO(ppara->m_SqlOperName);
    BZERO(ppara->m_TableName);
    BZERO(ppara->m_Sql);
    if (!FindSql(sdata, slen, m_Sql, sqllen)) {
        goto _err;
    }

    DecodeOper(m_Sql, sqllen, ppara->m_SqlOperName, ppara->m_TableName);

    if (strlen(ppara->m_SqlOperName) == 0) {
        PRINT_INFO_HEAD
        print_info("not find oper name");
        goto _err;
    }

    if (strcmp(ppara->m_SqlOperName, "COMMIT") == 0
        || strcmp(ppara->m_SqlOperName, "ROLLBACK") == 0) {
        goto _ok;
    }
    if (strlen(ppara->m_TableName) == 0) {
        if (strcmp(ppara->m_TableName, "CREATE") == 0 ||
            strcmp(ppara->m_TableName, "SELECT") == 0) {
            goto _err;
        }
    }
_ok:
    bflag = true;
    PRINT_DBG_HEAD
    print_dbg("%s:%s", ppara->m_SqlOperName, ppara->m_TableName);

_err:
    PRINT_DBG_HEAD
    print_dbg("decode request over, %s", bflag ? "success" : "fail");
    return bflag;
}

/**
 * [FindSql            提取请求语句]
 * @param  sdata       [应用层payload]
 * @param  slen        [payload 长度]
 * @param  sql_comm    [用于返回sql语句]
 * @param  sqllen      [用于返回sql语句长度]
 * @return             [解析成功返回true, 失败false]
 */
bool FindSql(unsigned char *sdata, int slen, char *sql_com, int &sqllen)
{
    int offset = 0;
    char *p = NULL;
    int len = 0;
    int i = 0;

    /* 最大检索长度 */
    len = slen < MAX_LOOKUP_LEN_REQ ? slen : MAX_LOOKUP_LEN_REQ;
    p = NULL;
    while (offset + 3 < len) {
        if (isalpha(sdata[offset]) && isalpha(sdata[offset + 1]) && \
            isalpha(sdata[offset + 2]) && isalpha(sdata[offset + 3])) {
            /* 连续4个可显示字符，作为检索结束条件. */
            p = (char *)sdata + offset;
            break;
        }
        offset += 1;
    }

    if (NULL == p)
        return false;

    for (i = 0; i < C_MAX_SQLOPER; i++) {
        if (strncasecmp(p, m_DefSqlOper[i], strlen(m_DefSqlOper[i])) == 0) {
            len = strnlen(p, slen - offset);
            sqllen = len < C_MAX_SQLLEN ? len : (C_MAX_SQLLEN - 1);
            snprintf(sql_com, sqllen + 1, "%s", p);

            PRINT_DBG_HEAD
            print_dbg("offset:[%d], sqllen:[%d], sql:[%s]", offset, sqllen, sql_com);
            return true;
        }
    }

    return false;
}

/**
 * [DecodeOper 从sql语句中分析出命令和参数]
 * @param  csql   [sql语句]
 * @param  sqllen [sql语句长度]
 * @param  coper  [命令]
 * @param  cpara  [参数]
 * @return        [成功返回true]
 */
bool DecodeOper(const char *csql, int sqllen, char *coper, char *cpara)
{
    if (sqllen < 6) {
        return false;
    }

    CCommon m_common;
    int tablepos = 0, ppos = 0;
    if (strncasecmp(csql, "select ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '*' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "SELECT"); //copy oper

        //
        //SELECT DATABASE()
        //如果有DATABASE()子串
        //
        if (m_common.casestrstr((const unsigned char *)csql,
                                (const unsigned char *)"DATABASE()", 0, sqllen) == E_COMM_OK) {
            strcpy(cpara, "DATABASE()");
            return true;
        }
        for (int j = 7; j < sqllen - 5; j++) {
            if (!strncasecmp(csql + j, "from", 4)) { //search from
                if (csql[j + 4] != ' ' && csql[j + 4] != '\r' && csql[j + 4] != '\n'
                    && csql[j + 4] != '\t' && csql[j + 4] != '(') {
                    j += 4;
                    continue;
                }
                int k;
                tablepos = j + 4;
                for (k = j + 4; k < sqllen; k++) {
                    if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                        continue;
                    }

                    tablepos = k;
                    break;
                }
                if (k >= sqllen) {
                    return false;
                }

                return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
            }
        }
    } else if (strncasecmp(csql, "insert ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }

        strcpy(coper, "INSERT"); //copy oper
        for (int j = 7; j < sqllen; j++) {
            if (strncasecmp(csql + j, "into ", 4) == 0) { //search INTO
                if (csql[j + 4] != ' ' && csql[j + 4] != '\r'
                    && csql[j + 4] != '\n' && csql[j + 4] != '\t') {
                    continue;
                }
                tablepos = j + 5;
                int k;
                for (k = j + 5; k < sqllen; k++) {
                    if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                        continue;
                    }
                    tablepos = k;
                    break;
                }
                if (k >= sqllen) {
                    return false;
                }

                return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
            }
        }
    } else if (strncasecmp(csql, "update ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "UPDATE"); //copy oper

        //把回车换行偏移过去
        int k;
        for (k = 7; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            tablepos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }
        return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
    } else if (strncasecmp(csql, "delete ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "DELETE"); //copy oper
        for (int j = 7; j < sqllen; j++) {
            if (strncasecmp(csql + j, "from ", 4) == 0) { //search from
                if (csql[j + 4] != ' ' && csql[j + 4] != '\r' && csql[j + 4] != '\n' && csql[j + 4] != '\t') {
                    continue;
                }

                tablepos = j + 5;
                int k;
                for (k = j + 5; k < sqllen; k++) {
                    if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                        continue;
                    }
                    tablepos = k;
                    break;
                }
                if (k >= sqllen) {
                    return false;
                }
                return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
            }
        }
    } else if (strncasecmp(csql, "create ", 6) == 0) { //e.g. create table tablename(id int);
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "CREATE"); //copy oper

        //跳过table之前的空格回车换行
        tablepos = 7;
        int k;
        for (k = 7; k < sqllen; k++) {
            if (isalpha(csql[k]) || isdigit(csql[k]) || csql[k] == '_') {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到table开始的位置
            return false;
        }

        //sql语句出错
        if (strncasecmp(csql + tablepos, "table", 5) != 0) {
            return false;
        }

        //table之后不是空格 或回车 或换行
        if (csql[tablepos + 5] != ' ' && csql[tablepos + 5] != '\r' && csql[tablepos + 5] != '\n'
            && csql[tablepos + 5] != '\t') {
            return false;
        }

        //把table之后的回车换行空格偏移过去
        for (k = tablepos + 5; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            //没找到tablename开始的位置
            return false;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "drop ", 4) == 0) {
        if (csql[4] != ' ' && csql[4] != '\r' && csql[4] != '\n' && csql[4] != '\t') {
            return false;
        }
        strcpy(coper, "DROP"); //copy oper

        //找table开始的位置
        int k;
        tablepos = 5;
        for (k = 5; k < sqllen; k++) {
            if (isalpha(csql[k]) || isdigit(csql[k]) || csql[k] == '_') {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到table开始的位置
            return false;
        }

        //sql语句出错
        if (strncasecmp(csql + tablepos, "table", 5) != 0) {
            return false;
        }

        //table之后不是空格 或回车 或换行
        if (csql[tablepos + 5] != ' ' && csql[tablepos + 5] != '\r' && csql[tablepos + 5] != '\n'
            && csql[tablepos + 5] != '\t') {
            return false;
        }

        //把table之后的回车换行空格偏移过去
        for (k = tablepos + 5; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "alter ", 5) == 0) {
        if (csql[5] != ' ' && csql[5] != '\r' && csql[5] != '\n' && csql[5] != '\t') {
            return false;
        }
        strcpy(coper, "ALTER"); //copy oper

        //找table开始的位置
        tablepos = 6;
        int k;
        for (k = 6; k < sqllen; k++) {
            if (isalpha(csql[k]) || isdigit(csql[k]) || csql[k] == '_') {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到table开始的位置
            return false;
        }

        //
        //alter session set PLSQL_DEBUG=true;
        //alter system set log_buffer =655360 scope=both;
        //如果有alter session/system
        //
        if (strncasecmp(csql + tablepos, "session", 7) == 0) {
            strcpy(cpara, "session");
            return true;
        }

        if (strncasecmp(csql + tablepos, "system", 6) == 0) {
            strcpy(cpara, "system");
            return true;
        }

        //sql语句出错
        if (strncasecmp(csql + tablepos, "table", 5) != 0) {
            return false;
        }

        //table之后不是空格 或回车 或换行
        if (csql[tablepos + 5] != ' ' && csql[tablepos + 5] != '\r' && csql[tablepos + 5] != '\n'
            && csql[tablepos + 5] != '\t') {
            return false;
        }

        //把table之后的回车换行空格偏移过去
        for (k = tablepos + 5; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "grant ", 5) == 0) {
        if (csql[5] != ' ' && csql[5] != '\r' && csql[5] != '\n' && csql[5] != '\t') {
            return false;
        }
        strcpy(coper, "GRANT"); //copy oper

        tablepos = 6;
        int k;
        //找on开始的位置
        for (k = tablepos; k < sqllen; k++) {
            if (strncasecmp(csql + k, "on", 2) == 0) {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到on开始的位置
            return false;
        }

        //on之后不是空格 或回车 或换行
        if (csql[tablepos + 2] != ' ' && csql[tablepos + 2] != '\r' && csql[tablepos + 2] != '\n'
            && csql[tablepos + 2] != '\t') {
            return false;
        }

        //把on之后的回车换行空格偏移过去
        for (k = tablepos + 2; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }
        //grant update on [table] v1 to root@"%";
        //如果有可选的table 则偏移过去
        if (strncasecmp(csql + ppos, "table ", 6) == 0) {
            ppos += 6;
        }
        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "revoke ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "REVOKE"); //copy oper

        tablepos = 6;
        int k;
        //找on开始的位置
        for (k = tablepos; k < sqllen; k++) {
            if (strncasecmp(csql + k, "on", 2) == 0) {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到on开始的位置
            return false;
        }

        //on之后不是空格 或回车 或换行
        if (csql[tablepos + 2] != ' ' && csql[tablepos + 2] != '\r' && csql[tablepos + 2] != '\n'
            && csql[tablepos + 2] != '\t') {
            return false;
        }

        //把on之后的回车换行空格偏移过去
        for (k = tablepos + 2; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }

        //revoke update on [table] v1 from root@"%";
        //如果有可选的table 则偏移过去
        if (strncasecmp(csql + ppos, "table ", 6) == 0) {
            ppos += 6;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "commit", 6) == 0) {
        strcpy(coper, "COMMIT"); //copy oper
        return true;
    } else if (strncasecmp(csql, "rollback", 8) == 0) {
        strcpy(coper, "ROLLBACK"); //copy oper
        return true;
    }

    return false;
}

/**
 * [AnalyseCmdRule 过滤命令参数]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [存放出错信息]
 * @param  ppara   [oracle线程参数信息]
 * @return         [允许通过返回true]
 */
bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror, OraclePara *ppara)
{
    PRINT_DBG_HEAD
    print_dbg("analys cmd begin[%s:%s]", chcmd, chpara);

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
        sprintf(cherror, "%s", ORACLE_PERM_FORBID);
    }
    PRINT_DBG_HEAD
    print_dbg("analys cmd over[%s]", bflag ? "true" : "false");

    return bflag;
}

/**
 * [RecordCallLog 记录访问日志]
 * @param ppara   [oracle线程参数]
 * @param cherror [存放出错信息]
 * @param result  [true为成功]
 */
void RecordCallLog(OraclePara *ppara, const char *cherror, bool result)
{
    PRINT_DBG_HEAD
    print_dbg("recode call log[%s:%s:%s]", ppara->m_SqlOperName, ppara->m_TableName, result ? "true" : "false");

    if ((g_iflog && ppara->rule->m_service[ppara->appno]->m_cklog) || g_syslog) {

        char src_ip[IP_STR_LEN] = {0};
        char src_port[PORT_STR_LEN] = {0};
        char gap_ip[IP_STR_LEN] = {0};
        char gap_port[PORT_STR_LEN] = {0};
        struct sockaddr_in addr;
        socklen_t socklen = sizeof(addr);

        //获取源IP port
        if (getpeername(ppara->infd, (struct sockaddr *)&addr, &socklen) == 0) {
            strcpy(src_ip, inet_ntoa(addr.sin_addr));
            sprintf(src_port, "%d", ntohs(addr.sin_port));
        }

        //获取网闸IP port
        if (getsockname(ppara->infd, (struct sockaddr *)&addr, &socklen) == 0) {
            strcpy(gap_ip, inet_ntoa(addr.sin_addr));
            sprintf(gap_port, "%d", ntohs(addr.sin_port));
        }

        CallLogPara *p = new CallLogPara;
        if (p != NULL) {
            if (p->SetValues(ppara->authname, src_ip, gap_ip, src_port, gap_port, "", "",
                             ppara->rule->m_service[ppara->appno]->m_asservice,
                             ppara->m_SqlOperName, ppara->m_TableName, result ? D_SUCCESS : D_REFUSE, cherror)) {
                LogContainer &s1 = LogContainer::GetInstance();
                s1.PutPara(p);
            } else {
                PRINT_ERR_HEAD
                print_err("set values fail[authname %s, sip %s, dip %s, sport %s, dport %s, %s:%s:%s]",
                          ppara->authname, src_ip, gap_ip, src_port, gap_port,
                          ppara->rule->m_service[ppara->appno]->m_asservice,
                          ppara->m_SqlOperName, ppara->m_TableName);
                delete p;
            }
        }
    }
}

/**
 * [redirect_setup   建立重定向端口对应的连接]
 * @param  para      [oracle线程参数信息]
 * @param  midfd     [内部跳转文件描述符]
 * @return           [成功返回0, 失败-1]
 */
static int redirect_setup(OraclePara *para, int &midfd)
{
    char err_buf[256] = {0};
    int infd = 0;
    int ret = 0;

    while (1) {
        struct sockaddr_in addr;
        socklen_t addrlen;
        BZERO(addr);
        addrlen = sizeof(addrlen);

        infd = accept(para->infd, (struct sockaddr *)&addr, &addrlen);
        if (infd <= 0) {
            PRINT_ERR_HEAD
            print_err("accept fail(%s)", strerror_r(errno, err_buf, sizeof(err_buf)));
            continue;
        } else {
            break;
        }
    }
    close(para->infd);
    para->infd = infd;

    midfd = socket(AF_INET, SOCK_STREAM, 0);
    if (midfd < 0) {
        PRINT_ERR_HEAD
        print_err("socket fail(%s)", strerror_r(errno, err_buf, sizeof(err_buf)));
        goto redirect_setup_fail;
    }

    struct sockaddr_in addrmid;
    BZERO(addrmid);
    addrmid.sin_family = AF_INET;
    addrmid.sin_port = htons(atoi(para->tredirectport));
    ret = inet_pton(AF_INET, para->midip, (void *)&addrmid.sin_addr);
    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("inet_pton fail(%s)", strerror_r(errno, err_buf, sizeof(err_buf)));
        goto redirect_setup_fail;
    }

    ret = connect(midfd, (struct sockaddr *)&addrmid, sizeof(addrmid));
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("connect fail(%s), [%s] : [%s]", strerror_r(errno, err_buf, sizeof(err_buf)), para->midip, para->tredirectport);
        goto redirect_setup_fail;
    }

    return 0;

redirect_setup_fail:
    if (-1 != para->infd) {
        close(para->infd);
        para->infd = -1;
    }
    if (-1 != midfd) {
        close(midfd);
        midfd = -1;
    }

    return -1;
}

/**
 * [redirect_ser_process    服务重定向处理线程函数]
 * @param  arg              [description]
 * @return                  [description]
 */
void *redirect_ser_process(void *arg)
{
    pthread_setself("redirect_ser");

    unsigned char buff[ORCL_MAX_BUF_LEN];           /* 空间太大，用时初始化 */
    char cherror[1024] = {0};
    char err_buf[256] = {0};
    int maxfd = 0;
    int midfd = -1;
    fd_set fds;


    OraclePara para = *(OraclePara *)arg;
    free(arg);

    int ret = redirect_setup(&para, midfd);
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("redirect_setup failed!");
        goto redirect_end;
    }

    while (1) {
        FD_ZERO(&fds);
        FD_SET(para.infd, &fds);
        FD_SET(midfd, &fds);
        maxfd = para.infd > midfd ? para.infd : midfd;

        ret = select(maxfd + 1, &fds, NULL, NULL, NULL);
        if (ret == 0) {
            continue;//timeout
        } else if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("select fail(%s)", strerror_r(errno, err_buf, sizeof(err_buf)));
            goto redirect_end;
        }

        if (FD_ISSET(para.infd, &fds)) {
            buff[0] = '\0';
            cherror[0] = '\0';

            int n = read(para.infd, buff, sizeof(buff) - 1);
            if (n <= 0) {
                PRINT_ERR_HEAD
                print_err("read fail(%s)", strerror_r(errno, err_buf, sizeof(err_buf)));
                goto redirect_end;
            }
            buff[n] = '\0';

            if (DecodeRequest(buff, n, cherror, &para)) {
                if (AnalyseCmdRule(para.m_SqlOperName, para.m_TableName, cherror, &para)) {
                    RecordCallLog(&para, cherror, true);
                } else {
                    RecordCallLog(&para, cherror, false);
                    goto redirect_end;
                }
            } else {
                //解码失败也让通过 因为可能是用户名密码登陆等
            }

            int m = write(midfd, buff, n);
            if (m != n) {
                PRINT_ERR_HEAD
                print_err("write fail(%s), m[%d] n[%d]", strerror_r(errno, err_buf, sizeof(err_buf)), m, n);
                goto redirect_end;
            }
        }

        if (FD_ISSET(midfd, &fds)) {
            buff[0] = '\0';

            int n = read(midfd, buff, sizeof(buff) - 1);
            if (n <= 0) {
                PRINT_ERR_HEAD
                print_err("read fail(%s)", strerror_r(errno, err_buf, sizeof(err_buf)));
                goto redirect_end;
            }
            buff[n] = '\0';

            int m = write(para.infd, buff, n);
            if (m != n) {
                PRINT_ERR_HEAD
                print_err("write fail(%s), m[%d] n[%d]", strerror_r(errno, err_buf, sizeof(err_buf)), m, n);
                goto redirect_end;
            }
        }
    }

redirect_end:
    if (-1 != para.infd)
        close(para.infd);
    if (-1 != midfd)
        close(midfd);
    PeerExecuteCMD(para.m_chcmd);

    return NULL;
}
