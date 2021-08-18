/*******************************************************************************************
*文件:  StartxmppInst.cpp
*描述:  开启xmpp任务实例
*作者:  王君雷
*日期:  2020-08-17
*修改:        添加处理XMPP报文逻辑         2020-08-19
*修改:        添加处理XMPP传输文件逻辑     2020-08-28
*修改:        使用sha1源码加密             2020-09-01
*修改:        添加过滤功能                 2020-09-03
*修改:        添加访问日志功能             2020-09-04
*修改:        兼容海关平台和Spark平台      2020-09-08
*修改:        修复源ip和from字段信息对应不上问题      2020-09-14
*修改:        兼容海关环境                 2020-09-25
*******************************************************************************************/
#include <pthread.h>
#include <errno.h>
#include <netinet/tcp.h>
#include "StartxmppInst.h"
#include "simple.h"
#include "quote_global.h"
#include "FCLogContainer.h"
#include "debugout.h"
#include <string.h>
#include "sha1.h"

static int32 xmppcheckbuf(pchar buff, pchar s_from, pchar s_to, pchar d_from, pchar d_to, pxmppsf s_f, uint32 s_r);
static void xmppchecksid_string(pchar buff, pchar f_t_i, pchar bufftmp, bool flag = true);
static int32 xmppwritesid_info(pchar buff, pchar s_from, pchar s_to, pchar d_from, pchar d_to, int expire_time);
static int32 xmpp_check_file(pchar buff, bool f_t, int32 len, int expire_time);
static int32 xmpp_del_file_info(int expire_time);
static void *xmppListenThread(void *arg);
static void *xmppCliProcess(void *arg);
static bool xmpp_analysecmdrule(char *chcmd, char *chpara, char *cherror, xmppPara *ppara);
static bool xmpp_decoderequest(pchar buff, xmppPara *ppara);
static int xmpp_get_expire_time(xmppPara *ppara);
static void xmpp_RecordCallLog(xmppPara *ppara, const char *cherror, bool result);
static bool xmppget_ip(pchar to_ip, pchar d_ip, pxmppsf s_f);

static const struct _filter {
    pchar cmd;
    pchar param[XMPP_PLATFORM];
    uint32 type;
} filtermode[] = {
    {"presence", {"status", NULL}, XMPP_STATUS},
    {"presence", {"type=\"", NULL}, XMPP_TYPE},
    {"message", {"<body", "<name>MsgText</name><value", NULL}, XMPP_MESSAGE},
    {"iq", {NULL}, 0}
};
/**
 * [StartxmppInst 启动xmpp处理实例]
 * @param  rule  [规则指针]
 * @param  tip   [代理IP]
 * @param  midip [中间跳转IP]
 * @param  dip   [目的服务器IP]
 * @param  appno [应用编号]
 * @return       [成功返回0]
 */
int StartxmppInst(CSYSRULES *rule, char *tip, char *midip, char *dip, int appno)
{
    if ((rule == NULL) || (tip == NULL) || (midip == NULL) || (dip == NULL) ) {
        PRINT_ERR_HEAD
        print_err("start xmpp para null[%s:%s:%s:%d]", tip, midip, dip, appno);
        return -1;
    }

    xmppPara *ppara = (xmppPara *)malloc(sizeof(xmppPara));
    if (ppara == NULL) {
        PRINT_ERR_HEAD
        print_err("xmpp malloc fail %s", strerror(errno));
        return -1;
    }
    memset(ppara, 0, sizeof(xmppPara));
    ppara->rule = rule;
    strcpy(ppara->tip, tip);
    strcpy(ppara->midip, midip);
    strcpy(ppara->dip, dip);
    ppara->appno = appno;
    strcpy(ppara->tport, rule->m_service[appno]->m_tport);
    ppara->expire_time = xmpp_get_expire_time(ppara);
    PRINT_INFO_HEAD
    print_info("xmpp craete thread info %s->%s->%s->%s", ppara->tip, ppara->midip, ppara->dip, ppara->tport);
    //创建监听线程
    pthread_t thid = 0;
    int ret = pthread_create(&thid, NULL, &xmppListenThread, (void *)ppara);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("xmpp craete thread fail %d", ret);
        free(ppara);
        return -1;
    }
    return 0;
}
/**
 * [xmppListenThread 监听线程函数]
 * @param  arg [xmppPPara参数]
 * @return     [未使用]
 */
static void *xmppListenThread(void *arg)
{
    pthread_setself("xmpplisten");

    xmppPara inpara = *(xmppPara *)arg;
    free(arg);

    int fd = create_and_bind_tcp(inpara.tip, atoi(inpara.tport));
    if (fd == -1) {
        PRINT_ERR_HEAD
        print_err("xmpp bind tcp fail[%s:%s]", inpara.tip, inpara.tport);
        return NULL;
    }

    if (listen(fd, 100) == -1) {
        PRINT_ERR_HEAD
        print_err("xmpp listen fail %s", strerror(errno));
        close(fd);
        return NULL;
    }
    PRINT_INFO_HEAD
    print_info("xmpp listen ok[%s:%s]", inpara.tip, inpara.tport);

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
            print_err("xmpp accept fail %d,%s", infd, strerror(errno));
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
                                     LOG_CONTENT_XMPP_REFUSE, "", "");
                log_mng.DisConnect();
            }
            PRINT_ERR_HEAD
            print_err("xmpp src obj[%s] not in sobjs", srcip);
            close(infd);
            continue;
        }
        //时间模式由网闸另一端去处理即可
        //传递给线程的参数
        xmppPara *ppara = (xmppPara *)malloc(sizeof(xmppPara));
        if (ppara == NULL) {
            PRINT_ERR_HEAD
            print_err("xmpp malloc fail %s", strerror(errno));
            close(infd);
            continue;
        }
        memset(ppara, 0, sizeof(xmppPara));
        ppara->infd = infd;
        strcpy(ppara->sip, inet_ntoa(addr.sin_addr));
        strcpy(ppara->tip, inpara.tip);
        strcpy(ppara->midip, inpara.midip);
        strcpy(ppara->dip, inpara.dip);
        strcpy(ppara->tport, inpara.tport);
        ppara->appno = inpara.appno;
        ppara->rule = inpara.rule;
        strcpy(ppara->authname, authname);
        ppara->seqno = ++seq;
        ppara->expire_time = inpara.expire_time;

        pthread_t thid = 0;
        int ret = pthread_create(&thid, NULL, &xmppCliProcess, (void *)ppara);
        if (ret != 0) {
            PRINT_ERR_HEAD
            print_err("xmpp craete cli thread fail %d", ret);
            close(infd);
            free(ppara);
            continue;
        }
        usleep(1000);
    }

    PRINT_ERR_HEAD
    print_err("xmpp listen thread will exit");
    close(fd);
    return NULL;
}
/**
 * [xmppCliProcess XMPP客户端处理函数]
 * @param  arg [xmppPPara结构指针]
 * @return     [未收用]
 */
static void *xmppCliProcess(void *arg)
{
    pthread_setself("xmppcliprocess");

    xmppPara para = *(xmppPara *)arg;
    free(arg);
    int midfd = socket(AF_INET, SOCK_STREAM, 0);
    if (midfd < 0) {
        PRINT_ERR_HEAD
        print_err("xmpp socket fail[%s]", strerror(errno));
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
        print_err("xmpp inet_pton fail[%d,%s,%s]", ret, para.midip, strerror(errno));
        close(para.infd);
        close(midfd);
        return NULL;
    }

    ret = connect(midfd, (struct sockaddr *)&addrmid, sizeof(addrmid));
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("xmpp connect fail[%d,%s,%s]", ret, para.midip, strerror(errno));
        close(para.infd);
        close(midfd);
        return NULL;
    }

    fd_set fds;
    int maxfd = 0;
    unsigned char buff[MAX_BUF_LEN] = {0};
    char cherror[1024] = {0};

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
            print_err("xmpp select error[%d,%s]", ret, strerror(errno));
            close(para.infd);
            close(midfd);
            return NULL;
        }

        if (FD_ISSET(para.infd, &fds)) {
            BZERO(buff);
            PRINT_DBG_HEAD
            print_dbg("xmpp ip s %s->%s", para.rule->m_specsip, para.dip);
            int n = read(para.infd, buff, sizeof(buff) - 8);
            if (n <= 0) {
                PRINT_ERR_HEAD
                print_err("xmpp read send error[%d,%s]", n, strerror(errno));
                close(para.infd);
                close(midfd);
                return NULL;
            }
            if (xmpp_decoderequest((pchar)buff, &para)) {
                if (!xmpp_analysecmdrule(para.ch_cmd, para.ch_param, cherror, &para)) {

                    xmpp_RecordCallLog(&para, cherror, false);
                    PRINT_INFO_HEAD
                    print_info("xmpp filter info faild :%s", cherror);
                    continue;
                }
                if (para.ch_param[0] != '\0')
                    xmpp_RecordCallLog(&para, cherror, true);
            }

            xmppwritesid_info((char *)buff, para.sip, para.tip, para.rule->m_specsip, para.dip, para.expire_time);
            if (xmppcheckbuf((char *)buff, para.sip, para.tip, para.rule->m_specsip, para.dip, para.src_from, XMPP_S) != -1) {
                n = strlen((pchar)buff);
            }
            xmpp_check_file((char *)buff, true, n, para.expire_time);

            PRINT_DBG_HEAD
            print_dbg("xmpp buff %s", buff);
            int m = write(midfd, buff, n);
            if (m != n) {
                PRINT_ERR_HEAD
                print_err("xmpp write send  error[%d,%s]", m, strerror(errno));
                close(para.infd);
                close(midfd);
                return NULL;
            }
        }

        if (FD_ISSET(midfd, &fds)) {
            BZERO(buff);
            PRINT_DBG_HEAD
            print_dbg("xmpp ip r  %s->%s", para.tip, para.dip);
            int n = read(midfd, buff, sizeof(buff));
            if (n <= 0) {
                PRINT_ERR_HEAD
                print_err("xmpp read recv error[%d,%s]", n, strerror(errno));
                close(para.infd);
                close(midfd);
                return NULL;
            }

            xmppwritesid_info((char *)buff, para.sip, para.tip, para.rule->m_specsip, para.dip, para.expire_time);
            if (xmppcheckbuf((char *)buff, para.dip, para.rule->m_specsip, para.tip, para.sip, para.src_from, XMPP_R) != -1) {
                n = strlen((pchar)buff);
            }
            int32 is_xmpp_file = xmpp_check_file((char *)buff, false, n, para.expire_time);
            if (is_xmpp_file == XMPP_FILE_SUCCESS) {
                xmpp_RecordCallLog(&para, "", true);
            } else if (is_xmpp_file == XMPP_FILE_FAILD) {
                xmpp_RecordCallLog(&para, "", false);
            }

            int m = write(para.infd, buff, n);
            if (m != n) {
                PRINT_ERR_HEAD
                print_err("xmpp write recv error[%d,%s]", m, strerror(errno));
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
 * [xmppcheck_string 替换报文源ip]
 * @param  buff [数据报文]
 * @param  s_ip [源ip]
 * @param  d_ip [目的ip]
 * @return     [ture 代表报文修改过，false 报文无修改]
 */
static bool xmppcheck_string(pchar buff, pchar s_ip, pchar d_ip, bool is_host = false)
{
    char *tmp = NULL, tmpip[64] = {0};
    char bufftmp[MAX_BUF_LEN] = {0};
    bool flag = false;

    if (is_host) {
        tmp = strstr(buff, "host=\"");
        while (tmp != NULL) {
            pchar p_tmp = NULL;
            p_tmp = strstr(tmp, "port=\"");
            if (p_tmp != NULL) {
                memset(bufftmp, 0, strlen(bufftmp));
                memcpy(bufftmp, buff, tmp - buff + strlen("host=\""));
                memcpy(bufftmp + strlen(bufftmp), d_ip, strlen(d_ip));
                memcpy(bufftmp + strlen(bufftmp), p_tmp - 2, strlen(p_tmp - 2)); //减2目的是，port字符前两位字符信息

                memset(buff, 0, strlen(buff));
                memcpy(buff, bufftmp, strlen(bufftmp));
                buff[strlen(buff)] = '\0';
            }

            tmp = strstr(tmp + strlen("host=\""), "host=\"");
            flag = true;
        }

    } else {
        tmp = strstr(buff, s_ip);
        while (tmp != NULL) {
            sscanf(tmp, "%[0-9.]", tmpip);//获取报文ip
            if (strlen(tmpip) == strlen(s_ip)) {
                memset(bufftmp, 0, strlen(bufftmp));
                memcpy(bufftmp, buff, tmp - buff);
                memcpy(bufftmp + strlen(bufftmp), d_ip, strlen(d_ip));
                memcpy(bufftmp + strlen(bufftmp), tmp + strlen(s_ip), strlen(tmp + strlen(s_ip)));

                memset(buff, 0, strlen(buff));
                memcpy(buff, bufftmp, strlen(bufftmp));
                buff[strlen(buff)] = '\0';
            }

            tmp = strstr(tmp + strlen(s_ip), s_ip);
            flag = true;
        }
    }
    return flag;
}
/**
 * [xmppcheckbuf 处理xmpp报文]
 * @param  buff [数据报文]
 * @param  s_from [源ip]
 * @param  s_to [网闸内/外ip]
 * @param  d_from [网闸外、内ip]
 * @param  d_to [目的ip]
 * @param  s_f [源ip和from ip对应关系]
 * @param  s_r [接受/发送标识]
 * @return     [ -1 报文无修改]
 */
static int32 xmppcheckbuf(pchar buff, pchar s_from, pchar s_to, pchar d_from, pchar d_to, pxmppsf s_f, uint32 s_r)
{
    bool flag = false;
    char jiddata[1024] = {0};
    char fromip[XMPP_IP_LEN] = {0}, srcip[XMPP_IP_LEN] = {0}, toip[XMPP_IP_LEN] = {0};
    char *tmp = NULL;
    if (s_from == NULL || s_to == NULL || d_from == NULL || d_to == NULL)
        return -1;
    memcpy(srcip, s_from, strlen(s_from));
    //获取xmpp数据包from字段ip信息，不依赖源端ip；防止源端ip和from字段对应不上导致xmpp通讯异常
    tmp = strstr(buff, "from=\"");
    if (tmp != NULL) {
        sscanf(tmp, "%*[^0-9]%s", jiddata);
        if (strlen(jiddata) > 8) { //必须符合正常ip
            tmp = jiddata;
            sscanf(tmp, "%*[^@]%s", jiddata);
            if (strlen(jiddata) > 8) { //必须符合正常ip
                tmp = jiddata;
                if (tmp[0] == '@') {
                    sscanf(tmp, "%*[@]%[0-9.]", jiddata);
                } else {
                    sscanf(tmp, "%[0-9.]", jiddata);
                }
                if (strlen(jiddata) > 8) { //必须符合正常ip
                    s_from = jiddata;
                    memcpy(fromip, s_from, strlen(s_from));
                    memcpy(s_f[s_r].from, s_from, strlen(s_from));
                    memcpy(s_f[s_r].src, srcip, strlen(srcip));
                    PRINT_INFO_HEAD
                    print_info("xmpp src->from[%s->%s] %d", s_f[s_r].src, s_f[s_r].from, s_r);
                    if (xmppget_ip(toip, d_to, s_f))
                        d_to = toip;
                }
            }
        }
        PRINT_INFO_HEAD
        print_info("xmpp from jiddata %s", jiddata);
    }

    PRINT_DBG_HEAD
    print_dbg("xmpp from %s", buff);

    flag |= xmppcheck_string(buff, s_from, d_from);

    PRINT_DBG_HEAD
    print_dbg("xmpp to %s", buff);

    flag |= xmppcheck_string(buff, s_to, d_to);

    PRINT_DBG_HEAD
    print_dbg("xmpp to end %s", buff);

    flag |= xmppcheck_string(buff, s_from, d_from, true);

    PRINT_DBG_HEAD
    print_dbg("xmpp host end %s", buff);

    if (flag)
        return strlen(buff);
    return -1;
}
/**
 * [xmppchecksid_string 处理xmpp传输文件报文]
 * @param  buff [数据报文]
 * @param  f_t_i [from/to/id查询信息]
 * @param  bufftmp [查询信息存储位置]
 * @param  flag [区分id信息和from/to信息]
 */
static void xmppchecksid_string(pchar buff, pchar f_t_i, pchar bufftmp, bool flag)
{
    char *tmp = NULL;
    if (flag) {
        tmp = strstr(buff, f_t_i);
        if (tmp != NULL) {
            pchar tmp_s = NULL,  tmp_m = NULL, tmp_e = NULL;
            tmp_s = strstr(tmp, "@");
            tmp_m = strstr(tmp, "/");
            if (tmp_s) {
                tmp_e = strstr(tmp_s, "\"");
                if (tmp_m && tmp_e && tmp_e > tmp_m) {
                    memcpy(bufftmp + strlen(bufftmp), tmp + strlen(f_t_i), tmp_e - tmp - strlen(f_t_i));
                }
                PRINT_DBG_HEAD
                print_dbg("xmpp xmppchecksid_string  %s", bufftmp);
            }
        }
    } else {
        tmp = strstr(buff, "<si");
        if (tmp != NULL) {
            tmp = strstr(tmp, f_t_i);
            if (tmp != NULL) {
                pchar tmp_e = NULL;
                tmp_e = strstr(tmp +  strlen(f_t_i), "\"");
                if (tmp_e > tmp) {
                    memcpy(bufftmp + strlen(bufftmp), tmp + strlen(f_t_i), tmp_e - tmp - strlen(f_t_i));
                }
                PRINT_DBG_HEAD
                print_dbg("xmpp xmppchecksid_string 2  %s", bufftmp);
            }
        }

    }
}
/**
 * [xmpp_write_file_info 写文件传输的唯一标识]
 * @param  count [当前记录个数]
 * @param  TOTAL [总共个数]
 * @param  file [操作文件参数]
 * @param  data [from/to信息]
 */
static void xmpp_write_file_info(uint32 count, bool TOTAL, CFILEOP &file, pxmppfileinfo data)
{
    pchar SYSROOT[2] = {"SYS", "COUNT"};
    pchar TASKCFG = "FILE_";
    char tasktmp[64] = {0};

    if (TOTAL) {
        file.WriteCfgFileInt(SYSROOT[0], SYSROOT[1], count);
    } else {
        sprintf(tasktmp, "%s%d", TASKCFG, count);

        char tmp[64] = {0};
        snprintf(tmp, sizeof(tmp) - 1, "%llu", data->starttime);
        file.WriteCfgFile(tasktmp, "TIME", tmp);

        file.WriteCfgFile(tasktmp, "FROM", data->from);
        file.WriteCfgFile(tasktmp, "TO", data->to);
    }
}

/**
 * [xmppwritesid_info 记录传输文件sid+jid(r)+jid(t)]
 * @param  buff [数据报文]
 * @param  s_from [源ip]
 * @param  s_to [网闸内/外ip]
 * @param  d_from [网闸外、内ip]
 * @param  d_to [目的ip]
 * @return     [ -1 报文无修改]
 */
static int32 xmppwritesid_info(pchar buff, pchar s_from, pchar s_to, pchar d_from, pchar d_to, int expire_time)
{
    char bufftmp[MAX_BUF_LEN] = {0};
    char cmd[MAX_BUF_LEN] = {0};
    xmppfileinfo data;
    CFILEOP file;
    int file_count = 0;
    pchar SYSROOT[2] = {"SYS", "COUNT"};

    if (strstr(buff, "file-transfer")) { //判断时候是传输文件格式

        xmppchecksid_string(buff, "id=\"", bufftmp, false);//sid
        xmppchecksid_string(buff, "from=\"", bufftmp);//from
        xmppchecksid_string(buff, "to=\"", bufftmp);//to
    } else {
        return 0;
    }
    memset(&data, 0, sizeof(data));
    memcpy(data.from, bufftmp, strlen(bufftmp)); //from 数据

    xmppcheck_string(bufftmp, s_from, d_from);  //to 数据
    xmppcheck_string(bufftmp, s_to, d_to);

    memcpy(data.to, bufftmp, strlen(bufftmp));
    data.starttime = time(NULL);

    xmpp_del_file_info(expire_time);//删除一天前的数据

#if (SIDE==100)
    if (file.OpenFile(XMPP_ADDR_EXT_FILE, "w+") == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("xmppwritesid_info CFG(%s) ERROR!!", XMPP_ADDR_EXT_FILE);
        return -1;
    }
#elif (SIDE==200)
    if (file.OpenFile(XMPP_ADDR_INT_FILE, "w+") == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("xmppwritesid_info CFG(%s) ERROR!!", XMPP_ADDR_INT_FILE);
        return -1;
    }
#endif
    //读取当前记录的文件个数
    file.ReadCfgFileInt((char *)SYSROOT[0], (char *)SYSROOT[1], (int *)&file_count);
    xmpp_write_file_info(file_count, false, file, &data);
    xmpp_write_file_info(file_count + 1, true, file, &data);
    file.WriteFileEnd();

#if (SIDE==100)
    sprintf(cmd, "/initrd/abin/putfile %s %s", XMPP_ADDR_EXT_FILE, XMPP_ADDR_EXT_FILE);
#elif (SIDE==200)
    sprintf(cmd, "/initrd/abin/putfile %s %s", XMPP_ADDR_INT_FILE, XMPP_ADDR_INT_FILE);
#endif
    PRINT_DBG_HEAD
    print_dbg("xmpp xmppchecksid_string cmd 3 %s", cmd);
    system(cmd);
    return 0;
}
/**
 * [xmpp_sha1en xmpp sha1 加密]
 * @param  buff [xmpp数据]
 * @param  hash [加密数据]
 */
static void xmpp_sha1en(pchar buff, unsigned char *hash)
{
    SHA1Context sha;
    SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *) buff, strlen(buff));
    SHA1Result(&sha, hash);
    for (int i = 0; i < 20; i++) {
        PRINT_DBG_HEAD
        print_dbg("xmpp sha1en from success %.2x", (int)hash[i]);
    }
}
/**
 * [xmpp_getfiledata 读取传输文件参数]
 * @param  filename [文件名字]
 * @param  src [数据源]
 * @param  buff [数据报文]
 * @param  expire_time [文件过期时间]
 * 返回值 -1失败 0 成功
 */
static uint32 xmpp_getfiledata(pchar filename, int src, pchar buff, int expire_time)
{
    pchar SYSROOT[2] = {"SYS", "COUNT"};
    pchar TASKCFG = "FILE_";
    uint32 file_count = 0;
    CFILEOP file;
    char tasktmp[64] = {0};
    char from[XMPP_ADDR_MAX] = {0};
    char to[XMPP_ADDR_MAX] = {0};
    unsigned char hash[20];
    char  sha1[64] = {0};
    time_t current_time = 0;
    if (file.OpenFile((char *)filename, "rb") == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("xmpp_getfiledata OPEN CFG(%s) ERROR!!", filename);
        return -1;
    }

    //读取任务数
    file.ReadCfgFileInt((char *)SYSROOT[0], (char *)SYSROOT[1], (int *)&file_count);
    if (file_count <= 0) {
        PRINT_INFO_HEAD;
        print_info("dbsync_tool TASK IS OVERFLOW, LIST = %d", file_count);
        return -1;
    }
    current_time = time(NULL);
    for (int32 i = 0; i < file_count; i++) {
        sprintf(tasktmp, "%s%d", TASKCFG, i);

        file.ReadCfgFile(tasktmp, src == XMPP_FROM ? "TO" : "FROM", to, sizeof(to));
        xmpp_sha1en(to, hash);
        for (int j = 0; j < 20; j++) {
            sprintf(sha1 + j * 2, "%.2x", (int)hash[j]);
        }
        PRINT_DBG_HEAD;
        print_dbg("xmpp_getfiledata sha sha1 sha1 %s->%s", sha1, buff + XMPP_FILE_HEAD_LEN);
        if (memcmp(sha1, buff + XMPP_FILE_HEAD_LEN, XMPP_FILE_DATA_LEN) == 0) {
            char tmp[64] = {0};
            file.ReadCfgFile(tasktmp, "TIME", tmp, sizeof(tmp));
            if (abs(current_time - atoll(tmp)) > (XMPP_ONE_DAY_S * expire_time)) { //文件过期不能下载
                PRINT_DBG_HEAD;
                print_dbg("xmpp_getfiledata file expire");
                break;
            }
            file.ReadCfgFile(tasktmp,  src == XMPP_FROM ? "FROM" : "TO", from, sizeof(from));
            xmpp_sha1en(from, hash);
            for (int j = 0; j < 20; j++) {
                sprintf(buff + XMPP_FILE_HEAD_LEN + j * 2, "%.2x", (int)hash[j]);
            }
            break;
        }
    }
    file.CloseFile();
    return 0;
}
/**
 * [xmpp_check_file 读取传输文件参数]
 * @param  buff [数据报文]
 * @param  f_t [源/目的]
 * @param  len [接受数据包长度，判断是否为验证文件唯一标识长度]
 * @param  expire_time [文件过期时间]
 * 返回值 1失败 0 成功 -1不做处理
 */
static int32 xmpp_check_file(pchar buff, bool f_t, int32 len, int expire_time)
{
    int32 is_xmpp_file = XMPP_NOT_FILE;
    if (len != 47)
        return is_xmpp_file;
    if (f_t) {
        if (buff[0] == 0x05 && buff[1] == 0x01 && buff[2] == 0x00 && buff[3] == 0x03 && buff[4] == 0x28) {
#if (SIDE==100)
            xmpp_getfiledata(XMPP_ADDR_INT_FILE, XMPP_FROM, buff, expire_time);
#elif (SIDE==200)
            xmpp_getfiledata(XMPP_ADDR_EXT_FILE, XMPP_FROM, buff, expire_time);
#endif
            is_xmpp_file = XMPP_FILE_SUCCESS;
        }
        PRINT_DBG_HEAD
        print_dbg("xmpp xmpp_check_file from success");
    } else {
        if (buff[0] == 0x05 && buff[1] == 0x00 && buff[2] == 0x00 && buff[3] == 0x03 && buff[4] == 0x28) {
#if (SIDE==100)
            xmpp_getfiledata(XMPP_ADDR_INT_FILE, XMPP_TO, buff, expire_time);
#elif (SIDE==200)
            xmpp_getfiledata(XMPP_ADDR_EXT_FILE, XMPP_TO, buff, expire_time);
#endif
            is_xmpp_file = XMPP_FILE_SUCCESS;
        } else if (buff[0] == 0x05 && buff[1] != 0x00 && buff[2] == 0x00 && buff[3] == 0x03 && buff[4] == 0x28) {
            is_xmpp_file = XMPP_FILE_FAILD;
        }
        PRINT_DBG_HEAD
        print_dbg("xmpp xmpp_check_file to success");
    }
    return is_xmpp_file;
}
/*
*  [xmpp_del_file_info 删除一天以前的文件信息（超过这个时间不能下载文件）]
*
* @param  expire_time [文件过期时间]
* 返回值目前未使用
*/
static int32 xmpp_del_file_info(int expire_time)
{
    pchar SYSROOT[2] = {"SYS", "COUNT"};
    pchar TASKCFG = "FILE_";
    char tasktmp[64] = {0};
    uint32 file_count = 0, file_count_tmp = 0, del_count = 0;
    pxmppfileinfo file_data;
    time_t current_time = 0;
    char cmd[_FILEPATHMAX] = {0};
    CFILEOP file;

#if (SIDE==100)
    if (file.OpenFile(XMPP_ADDR_EXT_FILE, "rb", true) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("xmpp_del_file_info CFG(%s) ERROR!!", XMPP_ADDR_EXT_FILE);
        return -1;
    }
#elif (SIDE==200)
    if (file.OpenFile(XMPP_ADDR_INT_FILE, "rb", true) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("xmpp_del_file_info CFG(%s) ERROR!!", XMPP_ADDR_INT_FILE);
        return -1;
    }
#endif
    //读取任务数
    file.ReadCfgFileInt((char *)SYSROOT[0], (char *)SYSROOT[1], (int *)&file_count);
    if (file_count <= 0) {
        PRINT_INFO_HEAD;
        print_info("xmpp_del_file_info TASK IS OVERFLOW, LIST = %d", file_count);
        return -1;
    }
    file_data = (pxmppfileinfo) malloc(file_count * sizeof(xmppfileinfo));
    if (file_data == NULL) {
        PRINT_INFO_HEAD;
        print_info("xmpp_del_file_info mallos false");
        return -1;
    }
    memset(file_data, 0, file_count * sizeof(xmppfileinfo));
    current_time = time(NULL);
    //读取
    for (int32 i = 0; i < file_count; i++) {
        char tmp[64] = {0};

        sprintf(tasktmp, "%s%d", TASKCFG, i);
        file.ReadCfgFile(tasktmp, "TIME", tmp, sizeof(tmp));
        file_data[i].starttime = atoll(tmp);
        file.ReadCfgFile(tasktmp, "FROM", file_data[i].from, sizeof(file_data[i].from));
        file.ReadCfgFile(tasktmp, "TO", file_data[i].to, sizeof(file_data[i].to));

        if (abs(current_time - file_data[i].starttime) > (XMPP_ONE_DAY_S * expire_time)) {
            PRINT_ERR_HEAD;
            print_err("xmpp_del_file_info start time: %llu, current time %llu", file_data[i].starttime, current_time);
            file_data[i].is_del = true;
        }
    }
    file.CloseFile();

    if (file.CreateNewFile(XMPP_ADDR_TMP_FILE) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("xmpp_del_file_info CFG(%s) ERROR!!", XMPP_ADDR_TMP_FILE);
        free(file_data);
        return -1;
    }
    PRINT_DBG_HEAD;
    print_dbg("xmpp_del_file_info  file count:%d", file_count);
    for (int32 i = 0; i < file_count; i++) {
        if (file_data[i].is_del != true) {
            xmpp_write_file_info(file_count_tmp, false, file, file_data + i);
            file_count_tmp++;
        } else {
            del_count++;
            PRINT_DBG_HEAD;
            print_dbg("xmpp_del_file_info   file start time:%llu", file_data[i].starttime);
        }
    }
    if (file_count_tmp != 0)
        xmpp_write_file_info(file_count_tmp, true, file, NULL);
    file.WriteFileEnd();

    if (file_count_tmp != 0 || del_count == file_count) {
#if (SIDE==100)
        sprintf(cmd, "cp %s %s", XMPP_ADDR_TMP_FILE, XMPP_ADDR_EXT_FILE);
#elif (SIDE==200)
        sprintf(cmd, "cp %s %s", XMPP_ADDR_TMP_FILE, XMPP_ADDR_INT_FILE);
#endif
        system(cmd);
        PRINT_DBG_HEAD;
        print_dbg("xmpp_del_file_info cmd: %s", cmd);
    }
    free(file_data);
    return 0;
}
/**
 * [xmpp_analysecmdrule 过滤命令参数]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @param  ppara   [xmppPPara指针]
 * @return         [允许通过返回true]
 */
static bool xmpp_analysecmdrule(char *chcmd, char *chpara, char *cherror, xmppPara *ppara)
{
    PRINT_DBG_HEAD
    print_dbg("xmpp_analysecmdrule cmd[%s] para[%s]", chcmd, chpara);

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

        PRINT_DBG_HEAD
        print_dbg("xmpp_analysecmdrule analyse cmd[%s] para[%s] para2[%s]", service->m_cmd[i]->m_cmd, service->m_cmd[i]->m_parameter, service->m_cmd[i]->m_sign);
    }
    if (!bflag) {
        PRINT_ERR_HEAD
        print_err("xmpp_analysecmdrule analyse cmd result, forbid[%s:%s]", chcmd, chpara);
        sprintf(cherror, "%s", XMPP_PERM_FORBID);
    }
    return bflag;
}
/**
 * [xmpp_get_param 写过滤参数]
 * @param  param   [过滤参数]
 * @param  type    [解析参数类型]
 * @param  buff    [报文信息]
 * @param  type_str [参数类型字符串]
 */
static pchar xmpp_get_param(pchar param, uint32 type, pchar buff, pchar type_str)
{
    pchar tmp_s = NULL, tmp_e = NULL;
    uint32 len = 0;
    switch (type) {
    case XMPP_STATUS:
        memcpy(param, type_str, strlen(type_str));
        break;
    case XMPP_TYPE:
        if (buff != NULL) {
            tmp_s = strstr(buff +  strlen(type_str), "\"");
            if (tmp_s != NULL) {
                len = tmp_s - buff - strlen(type_str);
                if (len > MAX_PARA_NAME_LEN) {
                    len = MAX_PARA_NAME_LEN - 1;
                }
                memcpy(param, buff + strlen(type_str), len);
            }
        }
        break;
    case XMPP_MESSAGE:
        if (buff != NULL) {
            tmp_s = strstr(buff +  strlen(type_str), ">");

            if (tmp_s != NULL) {
                tmp_e = strstr(tmp_s, "</");
                if (tmp_e != NULL) {
                    len = tmp_e - tmp_s - strlen(">");
                    if (len > MAX_PARA_NAME_LEN) {
                        len = MAX_PARA_NAME_LEN - 1;
                    }
                    memcpy(param, tmp_s + strlen(">"), len);
                }
            }
        }
        break;

    default:
        break;
    }
    return param;
}
/**
 * [xmpp_decoderequest 过滤信息解析]
 * @param  buff   [报文信息]
 * @param  ppara  [xmppPPara指针]
 * @return        [有过滤参数返回true]
 */
static bool xmpp_decoderequest(pchar buff, xmppPara *ppara)
{
    bool status = false;
    if (buff[0] == '<') {//报文开头
        memset(ppara->ch_cmd, 0, sizeof(ppara->ch_cmd));
        memset(ppara->ch_param, 0, sizeof(ppara->ch_param));
        for (int i = 0; i < sizeof(filtermode) / sizeof(struct _filter); i++) { //获取命令值
            pchar tmp_s = NULL;
            tmp_s = strstr(buff, filtermode[i].cmd);
            if (tmp_s != NULL) {
                memcpy(ppara->ch_cmd, filtermode[i].cmd, strlen(filtermode[i].cmd));
                int j = 0;
                while (filtermode[i].param[j] != NULL && (j < XMPP_PLATFORM)) {
                    tmp_s = strstr(buff, filtermode[i].param[j]);
                    PRINT_DBG_HEAD
                    print_dbg("xmpp_analysecmdrule param :%s", filtermode[i].param[j]);
                    if (tmp_s != NULL) {
                        xmpp_get_param(ppara->ch_param, filtermode[i].type, tmp_s, filtermode[i].param[j]);
                    }
                    j++;
                }
                status = true;
                break;
            }
        }
    }
    PRINT_DBG_HEAD
    print_dbg("xmpp_analysecmdrule param:cmd[%s:%s]", ppara->ch_param, ppara->ch_cmd);
    return status;
}
/**
 * [xmpp_get_expire_time 过去传输文件保留多长时间]
 * @param  ppara  [xmppPPara指针]
 * @return        [返回保留天数]
 */
static int xmpp_get_expire_time(xmppPara *ppara)
{
    CCommon m_common;
    CSERVICECONF *service = ppara->rule->m_service[ppara->appno];
    int  expire_time = 0;

    for (int i = 0; i < service->m_cmdnum; i++) {
        if (strcasecmp("expire_time", service->m_cmd[i]->m_cmd) == 0) {
            if (service->m_cmd[i]->m_parameter[0] != '\0') {
                expire_time = atoi(service->m_cmd[i]->m_parameter);
            }
        }
    }
    PRINT_DBG_HEAD
    print_dbg("xmpp_get_expire_time %d", expire_time);
    return expire_time ? expire_time : 1; //默认文件过期时间为1天
}
/**
 * [xmpp_RecordCallLog 记录访问日志]
 * @param ppara   [TRSPPara指针]
 * @param cherror [出错信息]
 * @param result  [日志结果]
 */
static void xmpp_RecordCallLog(xmppPara *ppara, const char *cherror, bool result)
{
    PRINT_DBG_HEAD
    print_dbg("xmpp_RecordCallLog record log.[%s,%s,%s]", ppara->ch_cmd, ppara->ch_param, result ? "pass" : "forbid");

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
                             ppara->ch_cmd, result ? "" : ppara->ch_param, result ? D_SUCCESS : D_REFUSE, cherror)) {
                LogContainer &s1 = LogContainer::GetInstance();
                s1.PutPara(p);
            } else {
                PRINT_ERR_HEAD
                print_err("xmpp_RecordCallLog set values fail[authname %s, sip %s, dip %s, sport %s, dport %s, %s:%s:%s:%s:%s]",
                          ppara->authname, src_ip, gap_ip, src_port, gap_port,
                          ppara->rule->m_service[ppara->appno]->m_asservice,
                          ppara->ch_cmd,
                          ppara->ch_param,
                          result ? "pass" : "forbid",
                          cherror);
                delete p;
            }

        }
    }
}

/**
 * [xmppget_ip 获取ip对应ip信息]
 * @param  to_ip [to ip]
 * @param  d_ip   [目的ip]
 * @param  s_f   [源ip和from ip对应关系]
 * @return     [ true 获取成功]
 */
static bool xmppget_ip(pchar to_ip, pchar d_ip, pxmppsf s_f)
{
    bool is_success = false;

    for (int i = 0; i < XMPP_S_F_NUM; i++) {
        if (strcmp(s_f[i].src, d_ip) == 0) {
            memcpy(to_ip, s_f[i].from, strlen(s_f[i].from));
            is_success = true;
            break;
        }
    }
    PRINT_DBG_HEAD
    print_dbg("xmppget_ip to ip: %s; d ip:%s %s", to_ip, d_ip, is_success ? "success" : "faild");
    return is_success;
}
