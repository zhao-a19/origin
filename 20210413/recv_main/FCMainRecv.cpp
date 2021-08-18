/*******************************************************************************************
*文件:  FCMainRecv.cpp
*描述:  网闸内部通信，接收对端消息并处理
*作者:  王君雷
*日期:  2014
*
*修改:
*         接收到外网发来传输日志后通知sys6，用以界面展示隔离通道的状态  ------> 2016-01-25
*         recvmain向sys6 killall发送信号，把输出定位到dev null          ------> 2016-01-29
*         检查mysql中，添加DBSYNCLOG表，数据库同步集成到网闸内部        ------> 2016-05-31
*         检查mysql中，添加SECMGLOG表                                   ------> 2016-06-08
*         检查mysql中，添加su_gap_sessions表                            ------> 2016-08-03
*         允许配置内部连接口为eth0                                      ------> 2016-12-26
*         为容错，系统启动执行一次repair SYSTEM_STATUS                  ------> 2017-08-07
*         CMD_EXECUTE_TYPE执行命令后在确认，保证命令已经执行过          ------> 2017-08-08
*         重新设计通道状态判断方法，recvmain不再向sys6 killall发送信号  ------> 2017-11-20
*         加入zlog记录日志                                              ------> 2018-04-09
*         成员函数命名统一风格                                          ------> 2018-04-11
*         执行hwclock -w时添加后台执行符号                              ------> 2018-08-15
*         把MainRecvUdp拆分为10多个函数，减少函数体大小;
*         命令代理服务移动到本程序中                                    ------> 2018-11-28
*         磁盘空间告警与检测线程移动到recvmain中                        ------> 2018-12-07
*         修改函数HandleEndOfFile中错误的关闭描述符BUG;
*         接收到的内部命令严格检查长度字段                              ------> 2018-12-18
*         设置内部通信地址时使用的掩码，改用DEFAULT_LINK_MASK           ------> 2019-07-20
*         main函数空调一次mysql初始化，解决多线程mysql初始化安全问题,
*         181207引入                                                    ------> 2019-08-27
*         使用DBGlobalPrepare函数代替空调一次mysql对象初始化            ------> 2019-08-27
*         关键位置添加更多zlog，方便运行定位                            ------> 2019-08-30
*         获取系统状态线程和外网同步日志线程移动到recvmain              ------> 2019-11-19-dzj
*         修改启动系统状态线程失败时，没有连接mysql就开始写数据库的bug  ------> 2019-12-06 wjl
*         内网收到外网发来的日志类型请求，先解析表名，插入出错后能通知巡视
*         线程去修复                                                    ------> 2019-12-15 wjl
*         可以处理GET_LOCAL_IP_TYPE类型请求                             ------> 2019-12-19 wjl
*         添加启动rsyslogd服务线程                                      ------> 2020-01-16 wjl
*         可以处理DEV_ID_SYNC类型请求                                   ------> 2020-02-14 wjl
*         向文件接收服务发送消息的socket，设置发送超时，防止阻塞        ------> 2020-02-20 wjl
*         添加守护进程、UDP接收文件使用线程，添加TCP方式收文件线程      ------> 2020-02-24
*         解决syslog开关，对系统状态日志不能马上生效的BUG，191119引入的BUG
*                                                                  ------> 2020-07-06 wjl
*         支持飞腾平台                                                  ------> 2020-07-27
*         使用NOHUP_RUN宏                                               ------> 2020-09-20
*         对于飞腾平台，初始化时touch重建error.log日志文件                 ------> 2020-10-09
*         解决飞腾平台忘记创建var/log/mysql/目录的问题                  ------> 2020-10-14
*         启动调用start改为startall                                   ------> 2020-10-28
*******************************************************************************************/
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>

#include "FCMainRecv.h"
#include "FCSendFileUdp.h"
#include "sendfiletcp.h"
#include "const.h"
#include "fileoperator.h"
#include "FCMsgAck.h"
#include "lcdmanager.h"
#include "FCTimeToPeer.h"
#include "simple.h"
#include "FCSysStatus.h"
#include "FCRecvFile.h"
#include "recvfiletcp.h"
#include "FCPeerExecuteCMD.h"
#include "FCMacInfo.h"
#include "debugout.h"
#include "simple.h"
#include "hardinfo.h"
#include "FCCmdProxy.h"
#include "FCLogDel.h"
#include "tbl_err_comm.h"
#include "FCLogTran.h"
#include "localip_api.h"
#include "rsyslogd.h"
#include "devidsync.h"

bool g_rulechange = true;
bool g_diskalertchange = true;
bool g_rsyslodchange = true;
bool g_slogchange = false;

int g_last_recv = 0;
int g_linklan = -1;
int g_linklanipseg = 0;
int g_linklanport = 0;
int g_linktcpfileport = 0;
loghandle glog_p = NULL;

/**
 * [SetChangeInfo 设置改变的变量]
 */
void SetChangeInfo(void)
{
    g_rulechange = true;
    g_diskalertchange = true;
    g_rsyslodchange = true;
    g_slogchange = true;
}

/**
 * [sigfun 信号处理函数]
 * @param sig [信号编号]
 */
void sigfun(int sig)
{
    if (sig == SIGUSR1) {
        //重新读取IP信息
        printf("Reloading IP info...\n");
        SetChangeInfo();
    } else {
    }
}

CMainRecv::CMainRecv(int ipseg, int port)
{
    m_linkipseg = ipseg;
    m_linkport = port;
    m_recvfd = 0;
}

CMainRecv::~CMainRecv(void)
{
    CLOSE(m_recvfd);
    CloseMapConnect();
    m_log.DisConnect();
}

/**
 * [CMainRecv::CloseMapConnect 关闭所有连接]
 */
void CMainRecv::CloseMapConnect(void)
{
    map<string, int>::iterator iter;
    for (iter = m_mapfd.begin(); iter != m_mapfd.end(); iter++) {
        PRINT_INFO_HEAD
        print_info("begin close fd:%d", iter->second);
        close(iter->second);
    }
    m_mapfd.clear();
}

/**
 * [SysStatusThread 开启系统状态采集程序]
 */
void SysStatusThread(void)
{
    char chsyslog[SYSLOG_BUF_LEN] = {0};
    int ret = StartGetSysStatus();
    if (ret != 0) {
        CLOGMANAGE mlog;
        mlog.Init();
        sprintf(chsyslog, "%s[%d]", LOG_CONTENT_RUN_STATUS_ERR, ret);
        mlog.WriteSysLog(LOG_TYPE_SYS_STATUS, D_FAIL, chsyslog);
        mlog.DisConnect();
        PRINT_ERR_HEAD;
        print_err("start get system status thread fail");
        exit(0);
    }
}


/**
 * [CMainRecv::ConnectToApp 建立与文件接收模块的长连接]
 * @param  connectstr [连接服务时使用的路径字串的一部分]
 * @return             [成功返回0]
 */
int CMainRecv::ConnectToApp(const char *connectstr)
{
    //如果map中已有
    if (m_mapfd.end() != m_mapfd.find(connectstr)) {
        return 0;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%d:%s]", fd, strerror(errno));
        return -1;
    }

    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

    struct sockaddr_un addr;
    BZERO(addr);
    addr.sun_family = AF_UNIX;
    sprintf(addr.sun_path, "%s-%s", UNIX_SERV_PATH, connectstr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PRINT_ERR_HEAD
        print_err("connect error[%s:%s]", addr.sun_path, strerror(errno));
        close(fd);
        return -1;
    }

    m_mapfd[connectstr] = fd;

    struct timeval timeout1 = {10, 0};
    struct timeval timeout2 = {2, 0};
    setsockopt(m_mapfd[connectstr], SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout1, sizeof(struct timeval));
    setsockopt(m_mapfd[connectstr], SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout2, sizeof(struct timeval));
    PRINT_INFO_HEAD
    print_info("connect ok[str:%s fd:%d]", connectstr, fd);
    return 0;
}

/**
 * [ReadLinkInfo 读取内联信息]
 * @param  plinklan  [内联网卡]
 * @param  plinkseg  [内联IP段]
 * @param  plinkport [内联端口]
 * @return           [成功返回0]
 */
int ReadLinkInfo(int *plinklan, int *plinkseg, int *plinkport)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile error[%s]", SYSINFO_CONF);
        return -1;
    }

    fileop.ReadCfgFileInt("SYSTEM", "LinkLanIPSeg", plinkseg);
    if (*plinkseg < 1 || *plinkseg > 255) {
        PRINT_ERR_HEAD
        print_err("read LinkLanIPSeg error[%d], use default 1", *plinkseg);
        *plinkseg = 1;
    }

    fileop.ReadCfgFileInt("SYSTEM", "LinkLan", plinklan);
    if (*plinklan < 0) {
        PRINT_ERR_HEAD
        print_err("read LinkLan error[%d]!exit", *plinklan);
        exit(-1);
    }

    fileop.ReadCfgFileInt("SYSTEM", "LinkLanPort", plinkport);
    if (*plinkport < 1 || *plinkport > 65535) {
        PRINT_ERR_HEAD
        print_err("read LinkLanPort error[%d], use default %d", *plinkport, DEFAULT_LINK_PORT);
        *plinkport = DEFAULT_LINK_PORT;
    }

    fileop.ReadCfgFileInt("SYSTEM", "LinkTCPFilePort", &g_linktcpfileport);
    if ((g_linktcpfileport < 1) || (g_linktcpfileport > 65535)) {
        g_linktcpfileport = DEFAULT_LINK_TCP_FILE_PORT;
    }
    fileop.CloseFile();
    PRINT_INFO_HEAD
    print_info("linkseg[%d] linklan[%d] linklanport[%d] linktcpfileport[%d]",
               *plinkseg, *plinklan, *plinkport, g_linktcpfileport);
    return 0;
}

/**
 * [CMainRecv::SetSocket 创建绑定socket]
 */
void CMainRecv::SetSocket(void)
{
    //如果已经打开就关闭掉
    CLOSE(m_recvfd);

    //接收描述符
    while ((m_recvfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%d:%s], retry", m_recvfd, strerror(errno));
        sleep(1);
    }

    //setsockopt
    int yes = 1;
    while (setsockopt(m_recvfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        PRINT_ERR_HEAD
        print_err("setsockopt error[fd:%d err:%s], retry", m_recvfd, strerror(errno));
        sleep(1);
    }

    char ip[IP_STR_LEN] = {0};
    sprintf(ip, "%d.0.0.%s", m_linkipseg, (DEVFLAG[0] == 'I') ? "254" : "253");

    //填写地址结构
    struct sockaddr_in addr;
    BZERO(addr);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_linkport);
    while (inet_pton(AF_INET, ip, (void *)&addr.sin_addr) <= 0) {
        PRINT_ERR_HEAD
        print_err("inet_pton error[IP:%s port:%d err:%s], retry", ip, m_linkport, strerror(errno));
        sleep(1);
    }

    //绑定地址和端口
    while (bind(m_recvfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PRINT_ERR_HEAD
        print_err("bind error[%d:%s], retry", m_recvfd, strerror(errno));
        sleep(1);
    }

    PRINT_INFO_HEAD
    print_info("set socket ok[IP:%s port:%d fd:%d]", ip, m_linkport, m_recvfd);
}

/**
 * [CMainRecv::CheckMysql 检查mysql表有没有损坏]
 */
void CMainRecv::CheckMysql(void)
{
    MYSQL msql;
    char chcmd[CMD_BUF_LEN] = {0};
    char chmysql[256] = {0};
    char tblname[][32] = {
        "CallLOG", "FILTERLOG", "FileSyncLOG", "LINKLOG", "MGLOG", "SECMGLOG",
        "SYSLOG", "SYSTEM_STATUS", "DBSYNCLOG", "su_gap_sessions"
    };
    int tabnum = sizeof(tblname) / sizeof(tblname[0]);

    while (mysql_init_connect(&msql) != 0) {
        PRINT_ERR_HEAD
        print_err("mysql_init_connect error, retry");
        sleep(1);
    }

    //检查表
    for (int i = 0; i < tabnum; i++) {
        BZERO(chmysql);
        sprintf(chmysql, "delete from %s where 1=2", tblname[i]);
        if (mysql_query(&msql, chmysql) != 0) {

            PRINT_DBG_HEAD
            print_dbg("Table[%s] Damaged,Begin To Rebuild It", tblname[i]);

            sprintf(chcmd, "%s localhost %s ", CREATEDB_FILE, tblname[i]);
            system(chcmd);
            system("sync");
        }
    }
    mysql_close(&msql);

    //为容错，执行一次repair SYSTEM_STATUS
    mysql_init_connect(&msql);
    if (mysql_query(&msql, "repair table SYSTEM_STATUS") == 0) {
    } else {
        PRINT_INFO_HEAD
        print_info("repair SYSTEM_STATUS fail");
    }
    mysql_close(&msql);

    PRINT_DBG_HEAD
    print_dbg("Check mysql over");
}

/**
 * [CMainRecv::DoLogInfo 把外网发过来的日志写入本侧的数据库]
 * @param  sqlbuf [sql语句]
 * @return        [写成功返回true]
 */
bool CMainRecv::DoLogInfo(const char *sqlbuf)
{
    bool bflag = false;
    char tblname[40] = {0};

    if (!m_log.ParseTblName(sqlbuf, tblname, sizeof(tblname))) {
        PRINT_ERR_HEAD
        print_err("parse tbl name fail[%s]", sqlbuf);
        return false;
    }

    if (m_log.WriteToDB(tblname, sqlbuf) != E_OK) {
        m_log.DisConnect();
        if (m_log.Init() == E_OK) {
            //重连后再尝试写一次
            if (m_log.WriteToDB(tblname, sqlbuf) == E_OK) {
                bflag = true;
            } else {
                PRINT_ERR_HEAD
                print_err("write db fail");
            }
        } else {
            PRINT_ERR_HEAD
            print_err("database recovery fail");
        }
    } else {
        bflag = true;
    }

    return bflag;
}

/**
 * [CMainRecv::InitClean 设备初始化时需要清理的内容]
 */
void CMainRecv::InitClean(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "rm -rf %s*", SYS_AUTH_DIR);
    system(chcmd);
    system("rm -rf /var/log/*");
#if (SUOS_V==2000)
    system("mkdir -p /var/log/mysql/");
    system("touch /var/log/mysql/error.log");
    system("chown -R mysql:mysql /var/log/mysql/error.log");
    PRINT_INFO_HEAD
    print_info("ft os touch mysql error.log");
#endif
    system("sync");
}

/*
 *总接收数据程序 如果需要再转发给其他应用
 */
int CMainRecv::MainRecvUdp(void)
{
    unsigned int length = 0;
    char recv_buf[MAX_BUF_LEN + sizeof(length) + sizeof(HEADER)];
    HEADER header;
    struct sockaddr_in cliaddr;
    socklen_t cliaddrlen = 0;
    bool isrulefile = false;

    while (m_log.Init() != E_OK) {
        PRINT_ERR_HEAD
        print_err("log init retry");
        sleep(1);
    }

    SetSocket();
    CheckMysql();

    while (1) {
        BZERO(recv_buf);
        BZERO(cliaddr);
        cliaddrlen = sizeof(cliaddr);

        int ret = recvfrom(m_recvfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&cliaddr,
                           &cliaddrlen);
        if (ret < (int)(sizeof(HEADER) + sizeof(length))) {
            PRINT_ERR_HEAD
            print_err("recvfrom error[ret:%d fd:%d err:%s]", ret, m_recvfd, strerror(errno));
            usleep(100000);
            continue;
        }

        //处理接收到的数据
        memcpy(&header, recv_buf, sizeof(header));
        memcpy(&length, recv_buf + sizeof(header), sizeof(length));
        g_last_recv = time(NULL);

        switch (header.appnum) {
        case LOG_INFO_TYPE: //传输日志
            HandleLog(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                      m_recvfd, &cliaddr, cliaddrlen);
            break;
        case SYNC_TIME_TYPE: //同步系统时间
            HandleSyncTime(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                           m_recvfd, &cliaddr, cliaddrlen);
            break;
        case SYNC_MICRO_TIME_TYPE: //同步时间(微妙级别)
            HandleSyncMicroTime(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                                m_recvfd, &cliaddr, cliaddrlen);
            break;
        case GET_TIME_TYPE: //要求系统时间同步
            HandleGetTime(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                          m_recvfd, &cliaddr, cliaddrlen);
            break;
        case SYS_INIT_TYPE: //系统初始化
            HandleSysInit(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                          m_recvfd, &cliaddr, cliaddrlen);
            break;
        case DEV_RESTART_TYPE: //设备重启
            HandleDevRestart(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                             m_recvfd, &cliaddr, cliaddrlen);
            break;
        case CMD_PROXY_TYPE: //命令代理
            HandleCmdProxy(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                           m_recvfd, &cliaddr, cliaddrlen);
            break;
        case CMD_EXECUTE_TYPE: //命令执行
            HandleCmdExec(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                          m_recvfd, &cliaddr, cliaddrlen);
            break;
        case VERSION_SYNC_TYPE: //版本同步
            HandleVersionSync(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                              m_recvfd, &cliaddr, cliaddrlen);
            break;
        case GET_FILE_TYPE: //获取文件
            HandleGetFile(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                          m_recvfd, &cliaddr, cliaddrlen);
            break;
        case GET_OUT_MAC_TYPE: //内网请求外网发mac
            HandleGetOutMac(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                            m_recvfd, &cliaddr, cliaddrlen);
            break;
        case GET_CARD_STATUS_TYPE: //请求获得网卡状态
            HandleGetCardStatus(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                                m_recvfd, &cliaddr, cliaddrlen);
            break;
        case FILE_TRANSFER_TYPE: //文件传输
            HandleFileTransfer(recv_buf + sizeof(header), length, header, isrulefile, &cliaddr, cliaddrlen);
            break;
        case GET_LOCAL_IP_TYPE:
            HandleGetLocalIP(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                             m_recvfd, &cliaddr, cliaddrlen);
            break;
        case DEVID_SYNC_TYPE:
            HandleDevIDSync(recv_buf + sizeof(header) + sizeof(length), length - sizeof(length),
                            m_recvfd, &cliaddr, cliaddrlen);
            break;
        default:
            PRINT_ERR_HEAD
            print_err("unknown type = %d. len = %d. ret = %d", header.appnum, length, ret);
            break;
        }
    }

    PRINT_ERR_HEAD
    print_err("main recv udp will exit");
    return -1;
}

/**
 * [CMainRecv::HandleLog 处理外网发来的日志 并给确认信息]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleLog(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                          socklen_t addrlen)
{
    char recv_sql_com[MAX_SQL_LEN] = {0};

    if (DEVFLAG[0] == 'I') {
        if ((len < (int)sizeof(recv_sql_com)) && (len > 0)) {
            memcpy(recv_sql_com, buff, len);
            SendMsgAck(fd, paddr, addrlen, LOG_INFO_TYPE,
                       DoLogInfo(recv_sql_com) ? MSG_ACK_OK : MSG_ACK_FAIL);
        } else {
            PRINT_ERR_HEAD
            print_err("log len err[%d] fd[%d]", len, fd);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("outnet recv log info type");
    }
}

/**
 * [CMainRecv::HandleSyncTime 处理系统时间同步]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleSyncTime(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                               socklen_t addrlen)
{
    SendMsgAck(fd, paddr, addrlen, SYNC_TIME_TYPE, MSG_ACK_OK);

    char timestr[100] = {0};
    char exe_buf[128] = {0};

    if ((len < (int)sizeof(timestr)) && (len > 0)) {
        memcpy(timestr, buff, len);
        sprintf(exe_buf, "date %s", timestr);
        system(exe_buf);
        system("hwclock -w &");
    } else {
        PRINT_ERR_HEAD
        print_err("sync time len err[%d] fd[%d]", len, fd);
    }
}

/**
 * [CMainRecv::HandleSyncMicroTime 处理系统时间同步（微秒级别）]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleSyncMicroTime(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                                    socklen_t addrlen)
{
    struct timeval tv;

    if (len == (int)sizeof(tv)) {
        memcpy(&tv, buff, sizeof(tv));
        settimeofday(&tv, NULL);
        SendMsgAck(fd, paddr, addrlen, SYNC_MICRO_TIME_TYPE, MSG_ACK_OK);
        system("hwclock -w &");
        PRINT_INFO_HEAD
        print_info("sync micro time ok");
    } else {
        PRINT_ERR_HEAD
        print_err("len err[%d],expect[%d]", len, (int)sizeof(tv));
    }
}

/**
 * [CMainRecv::HandleGetTime 处理要求时间同步请求]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleGetTime(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                              socklen_t addrlen)
{
    if (DEVFLAG[0] != 'I') {
        if (len == 0) {
            SendMsgAck(fd, paddr, addrlen, GET_TIME_TYPE, MSG_ACK_OK);
            if (time_to_peer(m_linkipseg, m_linkport) < 0) {
                PRINT_ERR_HEAD
                print_err("time to peer error");
            }
        } else {
            PRINT_ERR_HEAD
            print_err("len err %d", len);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("innet recv get time type");
    }
}

/**
 * [CMainRecv::HandleSysInit 处理系统初始化请求]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleSysInit(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                              socklen_t addrlen)
{
    if (DEVFLAG[0] != 'I') {
        if (len == 0) {
            SendMsgAck(fd, paddr, addrlen, SYS_INIT_TYPE, MSG_ACK_OK);
            InitClean();

            PRINT_INFO_HEAD
            print_info("sys init request.reboot ...");
            system("reboot");
        } else {
            PRINT_ERR_HEAD
            print_err("len err %d", len);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("innet recv sys init type");
    }
}

/**
 * [CMainRecv::HandleDevRestart 处理设备重启请求]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleDevRestart(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                                 socklen_t addrlen)
{
    if (DEVFLAG[0] != 'I') {
        if (len == 0) {
            SendMsgAck(fd, paddr, addrlen, DEV_RESTART_TYPE, MSG_ACK_OK);

            PRINT_INFO_HEAD
            print_info("dev restart request.reboot...");
            system("reboot");
        } else {
            PRINT_ERR_HEAD
            print_err("len err %d", len);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("innet recv restart type");
    }
}

/**
 * [CMainRecv::HandleCmdProxy 处理命令代理请求]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleCmdProxy(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                               socklen_t addrlen)
{
    //对于内网端 是把响应信息放入消息队列
    //对于外网端 是把请求信息放入消息队列 代码复用不使用2个不同的类型了
    if (len > 0) {
        SendMsgAck(fd, paddr, addrlen, CMD_PROXY_TYPE, MSG_ACK_OK);
        cmdproxy_putmsg(buff, len);
    } else {
        PRINT_ERR_HEAD
        print_err("len err %d", len);
    }
}

/**
 * [CMainRecv::HandleCmdExec 处理命令执行请求]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleCmdExec(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                              socklen_t addrlen)
{
    //与命令代理的区别是  命令执行无需返回响应信息
    char chcmd[1024] = {0};
    if ((len >= (int)sizeof(chcmd)) || (len <= 0)) {
        PRINT_ERR_HEAD
        print_err("cmd len err[%d:%s]", len, buff);
    } else {
        memcpy(chcmd, buff, len);

        if (memcmp(chcmd, ETC_START, len) == 0) {
            PRINT_INFO_HEAD
            print_info("exec [%s]", chcmd);
        }
        system(chcmd);
        SendMsgAck(fd, paddr, addrlen, CMD_EXECUTE_TYPE, MSG_ACK_OK);
    }
}

/**
 * [CMainRecv::HandleVersionSync 处理版本同步请求]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleVersionSync(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                                  socklen_t addrlen)
{
    if (DEVFLAG[0] != 'I') {
        if (len > 0) {
            SendMsgAck(fd, paddr, addrlen, VERSION_SYNC_TYPE, MSG_ACK_OK);
            WriteVersion(buff, len);

            PRINT_INFO_HEAD
            print_info("version sync request");
            system("sync");
        } else {
            PRINT_ERR_HEAD
            print_err("len err %d", len);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("innet recv version sync type");
    }
}

/**
 * [CMainRecv::HandleGetFile 处理获取文件请求 目前只有外网端会接收到这种类型消息]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleGetFile(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                              socklen_t addrlen)
{
    char filename[MAX_FILE_PATH_LEN] = {0};
    int mode = REMAIN_AFTER_SEND;

    //因为外网的UDP接收端通常不忙碌，所以直接处理，不另起进程/线程执行了
    if (DEVFLAG[0] != 'I') {
        if ((len - sizeof(mode) > 0)
            && (len - sizeof(mode) < sizeof(filename))) {

            SendMsgAck(fd, paddr, addrlen, GET_FILE_TYPE, MSG_ACK_OK);
            memcpy(&mode, buff, sizeof(mode));
            memcpy(filename, buff + sizeof(mode), len - sizeof(mode));

            PRINT_INFO_HEAD
            print_info("file[%s]:%s", filename,
                       (mode == DELTE_AFTER_SEND) ? "delete after send" : "remain after send");

            //发送文件
            if ((send_file_tcp(filename, filename) == 0) || (send_file_udp(filename) == 0)) {
                //文件处理方式   1:发送完保留  2:发送完删除
                if (mode == DELTE_AFTER_SEND) {
                    unlink(filename);
                    system("sync");
                }
            }
        } else {
            PRINT_ERR_HEAD
            print_err("len err %d", len);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("innet recv get file type");
    }
}

/**
 * [CMainRecv::HandleGetOutMac 处理获取外网MAC请求]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleGetOutMac(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                                socklen_t addrlen)
{
    int ethno = 0;
    char mac[MAC_STR_LEN] = {0};
    char sendbuf[512] = {0};

    if (DEVFLAG[0] != 'I') {
        if (len == sizeof(ethno)) {
            memcpy(&ethno, buff, sizeof(ethno));
            for (int i = 0; i < 3; i++) { //最多尝试3次
                if (get_mac(ethno, mac)) {
                    break;
                } else {
                    PRINT_ERR_HEAD
                    print_err("get mac error [%d] retry", ethno);
                    usleep(1000);
                }
            }

            memcpy(sendbuf, &ethno, sizeof(ethno));
            memcpy(sendbuf + sizeof(ethno), mac, 17);

            if (sendto(fd, sendbuf, sizeof(ethno) + 17, 0, (struct sockaddr *)paddr, addrlen) < 0) {
                PRINT_ERR_HEAD
                print_err("sendto error ethno[%d] mac[%s] err[%s] fd[%d]", ethno, mac, strerror(errno), fd);
            }
        } else {
            PRINT_ERR_HEAD
            print_err("len err %d", len);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("innet recv get out mac type");
    }
}

/**
 * [CMainRecv::HandleGetCardStatus 处理获取网卡连接状态请求]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleGetCardStatus(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                                    socklen_t addrlen)
{
    char ethname[8] = {0};
    char sendbuf[64] = {0};
    int ret = 0;

    if (DEVFLAG[0] != 'I') {
        if ((len < (int)sizeof(ethname)) && (len > 0)) {
            memcpy(ethname, buff, len);
            ret = get_netcard_status(ethname);
            memcpy(sendbuf, ethname, strlen(ethname));
            memcpy(sendbuf + strlen(ethname), &ret, sizeof(ret));

            if (sendto(fd, sendbuf, strlen(ethname) + sizeof(ret), 0, (struct sockaddr *)paddr,
                       addrlen) < 0) {
                PRINT_ERR_HEAD
                print_err("sendto error[%s]", strerror(errno));
            }
        } else {
            PRINT_ERR_HEAD
            print_err("card name len err[%d] fd[%d]", len, fd);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("innet recv get card status type");
    }
}

/**
 * [CMainRecv::HandleGetLocalIP 获取去往指定的IP时本地使用的IP]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleGetLocalIP(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                                 socklen_t addrlen)
{
    char localip[IP_STR_LEN] = {0};
    char dstip[IP_STR_LEN] = {0};

    if ((len < (int)sizeof(dstip)) && (len > 0)) {
        memcpy(dstip, buff, len);
        if (get_localip(dstip, localip, sizeof(localip)) == 0) {
            if (sendto(fd, localip, strlen(localip), 0, (struct sockaddr *)paddr, addrlen) < 0) {
                PRINT_ERR_HEAD
                print_err("dstip[%s] get localip response sendto err[%s]", dstip, strerror(errno));
            }
        } else {
            PRINT_ERR_HEAD
            print_err("dstip[%s] get localip err. fd[%d]", dstip, fd);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("ip len err[%d] fd[%d]", len, fd);
    }
}

/**
 * [CMainRecv::HandleDevIDSync 处理设备ID号同步请求]
 * @param buff    [请求缓冲区]
 * @param len     [长度]
 * @param fd      [描述符]
 * @param paddr   [地址]
 * @param addrlen [地址长度]
 */
void CMainRecv::HandleDevIDSync(const char *buff, int len, int fd, struct sockaddr_in *paddr,
                                socklen_t addrlen)
{
    char devid[DEV_ID_LEN] = {0};
    char curdevid[DEV_ID_LEN] = {0};

    if ((len < (int)sizeof(devid)) && (len > 0)) {
        memcpy(devid, buff, len);
        read_devid(curdevid, sizeof(curdevid));

        PRINT_INFO_HEAD
        print_info("peer devid[%s] curdevid[%s]", devid, curdevid);

        if (strcmp(devid, curdevid) != 0) {
            write_devid(devid);
        }

        if (sendto(fd, curdevid, strlen(curdevid), 0, (struct sockaddr *)paddr, addrlen) < 0) {
            PRINT_ERR_HEAD
            print_err("devid sync response sendto err[%s].devid[%s] curdevid[%s]",
                      strerror(errno), devid, curdevid);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("devid len err[%d] fd[%d]", len, fd);
    }
}

/**
 * [CMainRecv::IsRuleFile 判断是否为SYSRULES文件]
 * @param  filename [文件名称]
 * @return          [是返回true]
 */
bool CMainRecv::IsRuleFile(const char *filename)
{
    if ((filename != NULL) && (strcmp(filename, RULE_CONF) == 0)) {
        PRINT_INFO_HEAD
        print_info("rule is comming...");
        return true;
    }
    return false;
}

/**
 * [CMainRecv::HandleEndOfFile 处理文件结束包]
 * @param localfd    [本地套接字描述符]
 * @param isrulefile [是否为SYSRULES文件]
 * @param paddr      [地址]
 * @param addrlen    [地址长度]
 */
void CMainRecv::HandleEndOfFile(int localfd, bool isrulefile, struct sockaddr_in *paddr, socklen_t addrlen)
{
    char buf[32] = {0};
    char chcmd[CMD_BUF_LEN] = {0};
    int ret = 0;
TAG:
    ret = recv(localfd, buf, sizeof(buf), 0);
    if (ret > 0) {
        if (strcmp(buf, "1") == 0) {

            SendMsgAck(m_recvfd, paddr, addrlen, FILE_TRANSFER_TYPE, MSG_ACK_OK);

            //是SYSRULES的最后一个包
            if (isrulefile && (DEVFLAG[0] != 'I')) {
                //重启
                system(STOP_OUT_BUSINESS);
                PRINT_DBG_HEAD
                print_dbg("restart program!");

                CLOSE(m_recvfd);
                sprintf(chcmd, "%s /initrd/abin/sys6_w >/dev/null &", NOHUP_RUN);
                system(chcmd);
                SetSocket();
                SetChangeInfo();
                system("sync");
            }
        } else {
            SendMsgAck(m_recvfd, paddr, addrlen, FILE_TRANSFER_TYPE, MSG_ACK_FAIL);
            PRINT_ERR_HEAD
            print_err("outnet check file error. must retransfer");
            m_log.WriteSysLog(LOG_TYPE_TRAN_FILE, D_FAIL, LOG_CONTENT_RETRAN_FILE);
        }
    } else if ((ret < 0) && (errno == EINTR)) {
        PRINT_INFO_HEAD
        print_info("recv again.ret=%d, %s", ret, strerror(errno));
        goto TAG;
    } else {
        PRINT_ERR_HEAD
        print_err("tran policy files fail, outnet not properly received. ret=%d, %s", ret, strerror(errno));
        CloseMapConnect();
    }
}

/**
 * [CMainRecv::HandleSend 处理发送文件相关数据]
 * @param  fd   [描述符]
 * @param  buff [待发送缓冲区]
 * @param  len  [缓冲区长度]
 * @return      [失败返回负值]
 */
int CMainRecv::HandleSend(int fd, const char *buff, unsigned int len)
{
    int ret = 0;
    for (int i = 0; i < 5; ++i) {
        ret = send(fd, buff, len, MSG_NOSIGNAL);
        if (ret == len) {
            break;
        } else if (ret < 0) {
            if (errno == EAGAIN) {
                usleep(10000 * (i + 1));
                PRINT_INFO_HEAD
                print_info("send again...,len[%d]", len);
                continue;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    return ret;
}

/**
 * [CMainRecv::HandleFileTransfer 处理文件传输数据包]
 * @param buff       [把HEADER偏移过去之后的数据包]
 * @param length     [长度]
 * @param header     [头部]
 * @param isrulefile [是否为SYSRULES文件]
 * @param paddr      [地址]
 * @param addrlen    [地址长度]
 */
void CMainRecv::HandleFileTransfer(const char *buff, unsigned int length, HEADER &header, bool &isrulefile,
                                   struct sockaddr_in *paddr, socklen_t addrlen)
{
    char connectstr[32] = {0};
    int failcnt = 0;          //连续失败次数
    bool isendfile = false;
    int ret = 0;

    sprintf(connectstr, "%d-%d-%d-%d", header.ipnum, header.rulenum, header.appnum, header.tomirror);

    if ((unsigned int)FILE_BEGIN == length) {
        length = FILE_BLOCKSIZE + sizeof(length);
        isrulefile = IsRuleFile(buff + sizeof(length) + MD5_STR_LEN + sizeof(int));
    } else if ((unsigned int)FILE_END == length) {
        isendfile = true;
        length = sizeof(length);
    }

    while (failcnt < 3) {
        //如果还没建立连接，则创建之
        if (m_mapfd.end() == m_mapfd.find(connectstr)) {
            ConnectToApp(connectstr);
            failcnt++;
        } else {

            if ((ret = HandleSend(m_mapfd[connectstr], buff, length)) != (int)length) {
                PRINT_ERR_HEAD
                print_err("send error[%s],failcnt[%d],ret[%d],expected[%d]", strerror(errno),
                          failcnt, ret, length);
                failcnt++;
                close(m_mapfd[connectstr]);
                m_mapfd.erase(connectstr);
            } else {
                break;
            }
        }
    }

    if (failcnt == 3) {
        PRINT_ERR_HEAD
        print_err("send data failed 3 times.skip it.[len:%d str:%s]", length, connectstr);
        SendMsgAck(m_recvfd, paddr, addrlen, header.appnum, MSG_ACK_FAIL);
    } else {
        //发送一个文件结束
        if (isendfile) {
            HandleEndOfFile(m_mapfd[connectstr], isrulefile, paddr, addrlen);
        } else {
            SendMsgAck(m_recvfd, paddr, addrlen, header.appnum, MSG_ACK_OK);
        }
    }
}

/**
 * [CMainRecv::WriteVersion 写版本信息]
 * @param  vername [版本名称]
 * @param  len     [长度]
 * @return         [成功返回0]
 */
int CMainRecv::WriteVersion(const char *vername, int len)
{
    FILE *fp = fopen(START_CF, "w");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen error[%s:%s]", START_CF, strerror(errno));
        return -1;
    }

    char buf[1024] = "[SYSTEM]\nVersion=";
    strcat(buf, vername);
    strcat(buf, "\n\n");

    int ret = fwrite(buf, 1, strlen(buf), fp);
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("fwrite error[%d,%s]", ret, strerror(errno));
        fclose(fp);
        return -1;
    }
    fflush(fp);
    fclose(fp);

    PRINT_DBG_HEAD
    print_dbg("write ok");
    return 0;
}


/**
 * [SetLinkIP 设置内联IP]
 */
void SetLinkIP(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "ifconfig eth%d %d.0.0.%s netmask %s up", g_linklan, g_linklanipseg,
            (DEVFLAG[0] == 'I') ? "254" : "253", DEFAULT_LINK_MASK);
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("set link ip over[%s]", chcmd);
}

/**
 * [ChildProcess 子进程]
 * @return  [成功返回0 正常情况下不会返回，永久执行]
 */
int ChildProcess(void)
{
    signal(SIGUSR1, sigfun);
    CLOGMANAGE::DBGlobalPrepare();

    PRINT_INFO_HEAD
    print_info("lcd show begin");
    StartShowLCD();

    PRINT_INFO_HEAD
    print_info("recv file udp begin");
    StartRecvFileUDP();
    StartRecvFileTCP();

    CmdProxyInit();
    tbl_err_comm_init();

    PRINT_INFO_HEAD
    print_info("log space check begin");
    StartLogDel();

    PRINT_INFO_HEAD
    print_info("get system status thread");
    SysStatusThread();
    StartRsyslogd();

    if (DEVFLAG[0] != 'I') {
        PRINT_INFO_HEAD
        print_info("outnet start log tran thread");
        StartLogTran();

        PRINT_INFO_HEAD
        print_info("peer execute[%s]", ETC_STARTALL);
        //外网 发送消息，要求内网重启业务，从而把最新策略发过来，外网业务也会跟着重启了
        if (PeerExecuteCMD(ETC_STARTALL) < 0) {
            PRINT_ERR_HEAD
            print_err("peer execute cmd err");
        }

        PRINT_INFO_HEAD
        print_info("cmdproxy server begin");
        StartCmdProxyServer();
    } else {

        //内网 整理网卡MAC写入文件mac.info 供WEB界面展示使用
        StartMacInfo();
        StartDevIDSync();
    }

    PRINT_INFO_HEAD
    print_info("recv udp request begin");
    CMainRecv mainrecv(g_linklanipseg, g_linklanport);
    mainrecv.MainRecvUdp();
    return 0;
}

int main(int argc, char **argv)
{
    _log_init_(glog_p, recvmain);

    PRINT_INFO_HEAD
    print_info("recvmain process begin");
    signal(SIGUSR1, SIG_IGN);
    ReadLinkInfo(&g_linklan, &g_linklanipseg, &g_linklanport);
    SetLinkIP();

    while (1) {
        pid_t pid = 0;
        pid = fork();
        if (pid < 0) {
            PRINT_ERR_HEAD
            print_err("fork error");
        } else if (pid == 0) {
            ChildProcess();
            while (1) {
                sleep(100);
            }
            exit(0);
        } else {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                PRINT_ERR_HEAD
                print_err("The child process %d exit normally,WEXITSTATUS code[%d],WIFEXITED code[%d]",
                          pid, WEXITSTATUS(status), WIFEXITED(status));
            } else {
                PRINT_ERR_HEAD
                print_err("The child process %d exit abnormally, Status is %d", pid, status);
            }
            PRINT_ERR_HEAD
            print_err("Daemon restart");
        }
        sleep(2);
    }

    return 0;
}
