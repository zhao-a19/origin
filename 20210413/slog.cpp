/*******************************************************************************************
*文件:  slog.h
*描述:  发送syslog到本地服务接口
*作者:  王君雷
*日期:  2020-01-10
*修改:
*       添加函数ReadSwitch                                            ------> 2020-07-06
*       增加日志输出，增加判断编码逻辑                                  ------> 2020-12-09
*       程序优化，在组syslog字符串之前先判断是否需要发送syslog           ------> 2021-02-19
		修改内容过滤日志乱码											 ------> 2021-02-28
*******************************************************************************************/
//#include <syslog.h>
#include <sys/syslog.h>
#include "slog.h"
#include "fileoperator.h"
#include "debugout.h"
#include "common.h"
#include "log_translate.h"
#include "gap_config.h"
#include "stringex.h"

#define S_LOG_LEN_MAX       2048                     // syslog规定最大日志长度

#define S_LOG_ALERT     "1"     /* 报警 */
#define S_LOG_CRIT      "2"     /* 严重 */
#define S_LOG_ERR       "3"     /* 错误*/
#define S_LOG_WARNING   "4"     /* 警告 */
#define S_LOG_NOTICE    "5"     /* 通知 */
#define S_LOG_INFO      "6"     /* 信息 */
#define S_LOG_DEBUG     "7"     /* 调试 */

static char   syslog_utf8[] = "\xE7\xB3\xBB\xE7\xBB\x9F\xE6\x97\xA5\xE5\xBF\x97";                               //系统日志
static char   sysstatlog_utf8[] = "\xE7\xB3\xBB\xE7\xBB\x9F\xE7\x8A\xB6\xE6\x80\x81\xE6\x97\xA5\xE5\xBF\x97";   //系统状态日志
static char   sysstatlog_gbk[] = {0XCF, 0XB5, 0XCD, 0XB3, 0XD7, 0XB4, 0XCC, 0XAC, 0XC8, 0XD5, 0XD6, 0XBE, 0X00};//系统状态日志
static char   filelog_utf8[] = "\xE6\x96\x87\xE4\xBB\xB6\xE4\xBA\xA4\xE6\x8D\xA2\xE6\x97\xA5\xE5\xBF\x97";      //文件交换日志
static char   attack_utf8[] = "\xE6\x94\xBB\xE5\x87\xBB\xE9\x98\xB2\xE6\x8A\xA4\xE6\x97\xA5\xE5\xBF\x97";       //攻击防护日志
static char   filter_utf8[] = "\xE5\x86\x85\xE5\xAE\xB9\xE8\xBF\x87\xE6\xBB\xA4\xE6\x97\xA5\xE5\xBF\x97";       //内容过滤日志
static char   accesslog_utf8[] = "\xE8\xAE\xBF\xE9\x97\xAE\xE6\x97\xA5\xE5\xBF\x97";                            //访问日志
static char   access_refuse_utf8[] = "\xE8\xAE\xBF\xE9\x97\xAE\xE9\x98\xBB\xE6\x96\xAD";                        //访问阻断
static char   refuse_utf8[] = "\xE6\x8B\x92\xE7\xBB\x9D";                                                       //拒绝
// static char   success_utf8[] = "\xE6\x88\x90\xE5\x8A\x9F";                                                   //成功
// static char   sysstat_utf8[] = "\xE7\xB3\xBB\xE7\xBB\x9F\xE7\x8A\xB6\xE6\x80\x81";                           //系统状态

SLOG_CLI_OPER::SLOG_CLI_OPER(void)
{
    memset(m_id, 0, sizeof(m_id));
    memset(m_fw, 0, sizeof(m_fw));
    memset(m_devid, 0, sizeof(m_devid));
    m_syslog = false;
    //读取通用配置信息
    ReadConfig();
    SlogInit();
}

SLOG_CLI_OPER::~SLOG_CLI_OPER(void)
{
    SlogClose();
}

/**
 * [SLOG_CLI_OPER::ReadConfig 读取配置信息 为成员变量赋值]
 * @return  [成功返回true]
 */
bool SLOG_CLI_OPER::ReadConfig(void)
{
    int tmpint = 0;
    CFILEOP fop;
    CCommon common;

    //设备类型
    if (fop.OpenFile(SYSINFO_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("slog read config open[%s] fail", SYSINFO_CONF);
        return false;
    }
    fop.ReadCfgFile("SYSTEM", "DEVTYPE", m_id, sizeof(m_id));

    //设备序列号
    fop.ReadCfgFile("SYSTEM", "DevIndex", m_devid, sizeof(m_devid));
    fop.CloseFile();
    if (strlen(m_devid) == 0) {
        ReadSerial(m_devid, sizeof(m_devid));
    }

    //hostname
    common.Sysinfo("hostname", m_fw, sizeof(m_fw));

    //是否开启SYSLOG
    if (fop.OpenFile(SYSSET_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("slog read config open[%s] fail", SYSSET_CONF);
        return false;
    }
    fop.ReadCfgFileInt("SYSTEM", "LogType", &tmpint);
    m_syslog = (tmpint == 1);

    if (fop.ReadCfgFileInt("SYSTEM", "SYSLOG_CHARSET", &tmpint) == E_FILE_OK)   m_gbkset = (tmpint == 0);// 0:gbk  1:utf8
    else m_gbkset = true;

    fop.CloseFile();

    PRINT_DBG_HEAD
    print_dbg("slog read config over. id[%s] devid[%s] fw[%s] syslog[%d] server charset[%s]",
              m_id, m_devid, m_fw, m_syslog ? 1 : 0, m_gbkset ? "gbk" : "utf8");
    return true;
}

/**
 * [SLOG_CLI_OPER::ReadSwitch 读取日志开关]
 * @return  [成功返回true]
 */
bool SLOG_CLI_OPER::ReadSwitch(void)
{
    CFILEOP fop;
    int tmpint = 0;

    if (fop.OpenFile(SYSSET_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("slog read switch open[%s] fail", SYSSET_CONF);
        return false;
    }

    fop.ReadCfgFileInt("SYSTEM", "LogType", &tmpint);
    m_syslog = (tmpint == 1);

    if (fop.ReadCfgFileInt("SYSTEM", "SYSLOG_CHARSET", &tmpint) == E_FILE_OK)   m_gbkset = (tmpint == 0);//系统状态监控重新读取
    else m_gbkset = true;

    fop.CloseFile();

    PRINT_INFO_HEAD
    print_info("[%s]logtype is %d", SYSSET_CONF, tmpint);
    return true;
}

/**
 * [SLOG_CLI_OPER::ReadSerial 读取唯一码 当做ID号使用]
 * @param  serial [唯一码 出参]
 * @param  len    [缓冲区长度]
 * @return        [读取成功返回true]
 */
bool SLOG_CLI_OPER::ReadSerial(char *serial, int len)
{
    CFILEOP fop;
    if (fop.OpenFile(SERIAL_CFG, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", SERIAL_CFG);
        return false;
    }

    if (fop.ReadCfgFile("SYSTEM", "SERIAL", serial, len) != E_FILE_OK) {
        fop.CloseFile();
        return false;
    }

    PRINT_DBG_HEAD
    print_dbg("serial[%s]", serial);
    fop.CloseFile();
    return true;
}

/**
 * [SLOG_CLI_OPER::SlogInit 初始化相关]
 * @param  ident [description]
 * @return       [成功返回0]
 */
int SLOG_CLI_OPER::SlogInit(const char *ident)
{
    if (m_syslog) {
        openlog(ident, LOG_CONS | LOG_PID, LOG_USER);
        PRINT_DBG_HEAD
        print_dbg("slog init ok");
    }
    return 0;
}

/**
 * [SLOG_CLI_OPER::SlogClose 关闭]
 * @return  [成功返回0]
 */
int SLOG_CLI_OPER::SlogClose(void)
{
    if (m_syslog) {
        closelog();
    }
    return 0;
}

/**
 * [SLOG_CLI_OPER::SlogFormat 组装并发送]
 * @return  [成功返回0]
 */
int SLOG_CLI_OPER::SlogFormat(const char *pri, const char *fmt, ...)
{
    if (m_syslog) {
        char outbuf[S_LOG_LEN_MAX * 2] = { 0 };
        va_list args;
        va_start(args, fmt);
        vsprintf((char *)outbuf, fmt, args);
        va_end(args);

        if (strlen(outbuf) > S_LOG_LEN_MAX) {
            PRINT_ERR_HEAD;
            print_err("ERROR:slog buf is too long![%s]\n", outbuf);
            return -1;
        }

        if (strlen(m_devid) == 0) {
            ReadSerial(m_devid, sizeof(m_devid));
        }
        syslog(GetsyslogPriLevel(pri), outbuf);
        PRINT_DBG_HEAD
        print_dbg("INFO : slog send [%s]", outbuf);
    }
    return 0;
}

/**
 * [SLOG_CLI_OPER::GetPriLevel 获取级别]
 * @param  result  [日志结果]
 * @return         [日志级别]
 */
const char *SLOG_CLI_OPER::GetPriLevel(const char *result)
{
    if (strcmp(result, D_SUCCESS) == 0) {
        return S_LOG_NOTICE;//5
    } else if (strcmp(result, D_WARN) == 0) {
        return S_LOG_WARNING;//4
    } else if (strcmp(result, D_FAIL) == 0 || strcmp(result, D_REFUSE) == 0) {
        return S_LOG_ERR;//3
    } else {
        return S_LOG_INFO;//默认 6
    }
}

/**
 * [SLOG_CLI_OPER::GetsyslogPriLevel description]
 * @param  pri [字符串形式的级别]
 * @return     [级别]
 */
int SLOG_CLI_OPER::GetsyslogPriLevel(const char *pri)
{
    if (strcmp(pri, S_LOG_ALERT) == 0) {
        return LOG_ALERT;
    } else if (strcmp(pri, S_LOG_CRIT) == 0) {
        return LOG_CRIT;
    } else if (strcmp(pri, S_LOG_ERR) == 0) {
        return LOG_ERR;
    } else if (strcmp(pri, S_LOG_WARNING) == 0) {
        return LOG_WARNING;
    } else if (strcmp(pri, S_LOG_NOTICE) == 0) {
        return LOG_NOTICE;
    } else if (strcmp(pri, S_LOG_INFO) == 0) {
        return LOG_INFO;
    } else if (strcmp(pri, S_LOG_DEBUG) == 0) {
        return LOG_DEBUG;
    } else {
        return LOG_INFO;
    }
}

/**
 * [SLOG_CLI_OPER::WriteSysLog 处理系统日志]
 * @param  logtype [日志类型]
 * @param  result  [结果]
 * @param  remark  [备注]
 * @param  isout   [是否为外网]
 * @param  dtime   [时间]
 * @return         [成功返回0]
 */
int SLOG_CLI_OPER::WriteSysLog(const char *logtype, const char *result, const char *remark,
                               int isout, const char *dtime)    //所有参数均为后台程序传入，没有读配置文件，均为gbk
{
    //<5>ID="SU-GAP3000" FW="SUGAP" TIME="2019-09-24 15:28:08" PRI="5" DEVID="GAP-123EA89" MODULE="系统日志"
    //MSG="系统状态" DESC="启动系统状态采集程序" RESULT="成功" ISOUT="1"
    bool gbkset = false;
    char _logtype[1024] = {0};
    char _remark[1024] = {0};
    char _result[1024] = {0};
    char tmp[1024] = {0};

    if (!m_syslog) {
        return 0;
    }
    strcpy(tmp, result);
    if ((get_sucharset(tmp) == CHARSET_GBK)) gbkset = true;
    const char *pri = GetPriLevel(result);

    if (m_gbkset) {
        if (gbkset) {
            return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                              "MSG=\"%s\" DESC=\"%s\" RESULT=\"%s\" ISOUT=\"%d\"",
                              pri, m_id, m_fw, dtime, pri, m_devid, LOGNAME_SYSLOG,
                              logtype, remark, result, isout);
        } else {
            PRINT_DBG_HEAD
            print_dbg("syslog charset utf-8 to gbk");

            strconv("UTF-8", logtype, "GBK", _logtype);
            strconv("UTF-8", remark, "GBK", _remark);
            strconv("UTF-8", result, "GBK", _result);
            return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                              "MSG=\"%s\" DESC=\"%s\" RESULT=\"%s\" ISOUT=\"%d\"",
                              pri, m_id, m_fw, dtime, pri, m_devid, LOGNAME_SYSLOG,
                              _logtype, _remark, _result, isout);
        }
    } else {
        if (gbkset) {
            PRINT_DBG_HEAD
            print_dbg("syslog charset gbk to utf-8");

            strconv("GBK", logtype, "UTF-8", _logtype);
            strconv("GBK", remark, "UTF-8", _remark);
            strconv("GBK", result, "UTF-8", _result);
            return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                              "MSG=\"%s\" DESC=\"%s\" RESULT=\"%s\" ISOUT=\"%d\"",
                              pri, m_id, m_fw, dtime, pri, m_devid, syslog_utf8,
                              _logtype, _remark, _result, isout);
        } else {
            return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                              "MSG=\"%s\" DESC=\"%s\" RESULT=\"%s\" ISOUT=\"%d\"",
                              pri, m_id, m_fw, dtime, pri, m_devid, syslog_utf8,
                              logtype, remark, result, isout);
        }
    }
}

/**
 * [SLOG_CLI_OPER::WriteSysStatusLog 处理系统状态日志]
 * @param  linknum   [并发数]
 * @param  cpuinfo   [CPU使用率]
 * @param  diskinfo  [磁盘使用率]
 * @param  meminfo   [内存使用率]
 * @param  netinfo   [隔离通道状态]
 * @param  netflow   [实时吞吐量]
 * @param  devstatus [设备整体状态]
 * @param  descr     [描述]
 * @param  isout     [是否外网]
 * @param  dtime     [时间]
 * @return           [成功返回0]
 */
int SLOG_CLI_OPER::WriteSysStatusLog(int linknum, const char *cpuinfo, const char *diskinfo,
                                     const char *meminfo, const char *netinfo, unsigned long long int netflow,
                                     char devstatus, const char *descr, int isout, const char *dtime)   //只需处理 MODULE
{
    //<5>ID = "SU-GAP3000" FW = "SUGAP" TIME = "2019-09-24 15:28:08" PRI = "5" DEVID = "GAP-123EA89"
    //MODULE="系统状态日志" CPU="1.850639%"
    //MEM="1.647148%" DISK="61.178864%" LINKNUM="100" NET="1" NETFLOW="1416" DEVSTATUS="1" DESC="secway warn" ISOUT="1"
    if (!m_syslog) {
        return 0;
    }
    const char *pri = (devstatus == '1') ? S_LOG_ERR : S_LOG_NOTICE;
    return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                      "CPU=\"%s%%\" MEM=\"%s%%\" DISK=\"%s%%\" LINKNUM=\"%d\" NET=\"%s\" NETFLOW=\"%lld\" DEVSTATUS=\"%c\" DESC=\"%s\" ISOUT=\"%d\"",
                      pri, m_id, m_fw, dtime, pri, m_devid, (m_gbkset ? sysstatlog_gbk : sysstatlog_utf8),
                      cpuinfo, meminfo, diskinfo, linknum, netinfo, netflow, devstatus, descr, isout);
}

/**
 * [SLOG_CLI_OPER::WriteCallLog 处理访问日志]
 * @param  user     [用户名]
 * @param  srcip    [源IP]
 * @param  dstip    [目的IP]
 * @param  srcport  [源端口]
 * @param  dstport  [目的端口]
 * @param  srcmac   [源MAC]
 * @param  dstmac   [目的MAC]
 * @param  service  [服务名]
 * @param  cmd      [命令]
 * @param  param    [参数]
 * @param  result   [结果]
 * @param  remark   [备注]
 * @param  isout    [是否为外网]
 * @param  dtime    [时间]
 * @return         [成功返回0]
 */
int SLOG_CLI_OPER::WriteCallLog(const char *user, const char *srcip, const char *dstip,
                                const char *srcport, const char *dstport, const char *srcmac, const char *dstmac,
                                const char *service, const char *cmd, const char *param, const char *result,
                                const char *remark, int isout, const char *dtime)   //user为web写入配置文件，utf8
{
    //<5>Aug 02 23:53:28 192.168.1.254 ID="SU-GAP3000" FW="SUGAP" TIME="2019-09-24 15:28:08" PRI="5" DEVID="GAP-123EA89" MODULE="访问日志"
    //USER="user1" SRC="1.1.1.1" DST="1.1.1.2" SPT="1234" DPT="80" SMAC="11:11:11:22:22:22" DMAC="11:11:11:33:33:33"
    //PROTO="HTTP" MSG="GET sina.com" DESC="禁止通过" RESULT="拒绝" ISOUT="1"
    char _remark[1024] = {0};
    char _result[1024] = {0};
    char _user[1024] = {0};
    char _service[1024] = {0};
    const char *pri = GetPriLevel(result);

    if (!m_syslog) {
        return 0;
    }
    if (m_gbkset) {
        PRINT_DBG_HEAD
        print_dbg("CallLog charset utf-8 to gbk");

        strconv("UTF-8", user, "GBK", _user);
        return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                          "USER=\"%s\" SRC=\"%s\" DST=\"%s\" SPT=\"%s\" DPT=\"%s\" SMAC=\"%s\" DMAC=\"%s\" "
                          "PROTO=\"%s\" MSG=\"%s %s\" DESC=\"%s\" RESULT=\"%s\" ISOUT=\"%d\"",
                          pri, m_id, m_fw, dtime, pri, m_devid, LOGNAME_CALLLOG,
                          _user, srcip, dstip, srcport, dstport, srcmac, dstmac,
                          service, cmd, param, remark, result, isout);
    } else {
        PRINT_DBG_HEAD
        print_dbg("CallLog charset gbk to utf-8");

        strconv("GBK", remark, "UTF-8", _remark);
        strconv("GBK", result, "UTF-8", _result);
        strconv("GBK", service, "UTF-8", _service);
        return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                          "USER=\"%s\" SRC=\"%s\" DST=\"%s\" SPT=\"%s\" DPT=\"%s\" SMAC=\"%s\" DMAC=\"%s\" "
                          "PROTO=\"%s\" MSG=\"%s %s\" DESC=\"%s\" RESULT=\"%s\" ISOUT=\"%d\"",
                          pri, m_id, m_fw, dtime, pri, m_devid, accesslog_utf8,
                          user, srcip, dstip, srcport, dstport, srcmac, dstmac,
                          _service, cmd, param, _remark, _result, isout);
    }
}

/**
 * [SLOG_CLI_OPER::WriteFileSyncLog 处理文件交换日志]
 * @param  taskid   [任务号]
 * @param  taskname [任务名称]
 * @param  srcip    [源IP]
 * @param  dstip    [目的IP]
 * @param  spath    [源路径]
 * @param  dpath    [目的路径]
 * @param  fname    [文件名]
 * @param  result   [结果]
 * @param  remark   [备注]
 * @param  isout    [是否为外网]
 * @param  dtime    [时间]
 * @return          [成功返回0]
 */
int SLOG_CLI_OPER::WriteFileSyncLog(int taskid, const char *taskname, const char *srcip, const char *dstip,
                                    const char *spath, const char *dpath, const char *fname, const char *result,
                                    const char *remark, int isout, const char *dtime)   // taskname spath dpath result remark为utf8 fname不确定
{
    //<5>Aug 02 23:53:28 192.168.1.254 ID="SU-GAP3000" FW="SUGAP" TIME="2019-09-24 15:28:08" PRI="5" DEVID="GAP-123EA89" MODULE="文件交换日志"
    //SRC="1.1.1.1" DST="1.1.1.2" TASKNAME="filetest" SPATH="testpath" DPATH="testdpath" FILENAME="1.txt" MSG="同步文件" DESC="" RESULT="成功" ISOUT="1"
    char _taskname[1024] = {0};
    char _spath[1024] = {0};
    char _dpath[1024] = {0};
    char _fname[1024] = {0};
    char _result[1024] = {0};
    char _remark[1024] = {0};
    char tmp[1024] = {0};
    const char *pri = GetPriLevel(result);

    if (!m_syslog) {
        return 0;
    }

    if (m_gbkset) {
        PRINT_DBG_HEAD
        print_dbg("FileSyncLog charset utf-8 to gbk");

        strconv("UTF-8", taskname, "GBK", _taskname);
        strconv("UTF-8", spath, "GBK", _spath);
        strconv("UTF-8", dpath, "GBK", _dpath);
        strconv("UTF-8", result, "GBK", _result);
        strconv("UTF-8", remark, "GBK", _remark);
        strcpy(tmp, fname);
        if ((get_sucharset(tmp) == CHARSET_GBK)) strcpy(_fname, fname);
        else strconv("UTF-8", fname, "GBK", _fname);

        return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                          "SRC=\"%s\" DST=\"%s\" TASKNAME=\"%s\" SPATH=\"%s\" DPATH=\"%s\" FILENAME=\"%s\" "
                          "MSG=\"%s\" DESC=\"%s\" RESULT=\"%s\" ISOUT=\"%d\"",
                          pri, m_id, m_fw, dtime, pri, m_devid, LOGNAME_FILESYNCLOG,
                          srcip, dstip, _taskname, _spath, _dpath, _fname,
                          _remark, "", _result, isout);

    } else {
        PRINT_DBG_HEAD
        print_dbg("FileSyncLog charset gbk to utf-8");

        strcpy(tmp, fname);
        if ((get_sucharset(tmp) == CHARSET_UTF8)) strcpy(_fname, fname);
        else strconv("GBK", fname, "UTF-8", _fname);
        return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                          "SRC=\"%s\" DST=\"%s\" TASKNAME=\"%s\" SPATH=\"%s\" DPATH=\"%s\" FILENAME=\"%s\" "
                          "MSG=\"%s\" DESC=\"%s\" RESULT=\"%s\" ISOUT=\"%d\"",
                          pri, m_id, m_fw, dtime, pri, m_devid, filelog_utf8,
                          srcip, dstip, taskname, spath, dpath, _fname,
                          remark, "", result, isout);
    }
}

/**
 * [SLOG_CLI_OPER::WriteLinkLog 处理攻击防护日志]
 * @param  srcip    [源IP]
 * @param  dstip    [目的IP]
 * @param  srcport  [源端口]
 * @param  dstport  [目的端口]
 * @param  srcmac   [源MAC]
 * @param  dstmac   [目的MAC]
 * @param  remark [备注]
 * @param  srcmac [源MAC]
 * @param  dstmac [目的MAC]
 * @param  isout  [是否外网]
 * @param  dtime  [时间]
 * @return        [成功返回0]
 */
int SLOG_CLI_OPER::WriteLinkLog(const char *srcip, const char *dstip, const char *srcport, const char *dstport,
                                const char *remark, const char *srcmac, const char *dstmac, int isout, const char *dtime)   //remark为gbk
{
    //<5>Aug 02 23:53:28 192.168.1.254 ID="SU-GAP3000" FW="SUGAP" TIME="2019-09-24 15:28:08" PRI="5" DEVID="GAP-123EA89" MODULE="攻击防护日志"
    //SRC="1.1.1.1" DST="1.1.1.2" SPT="1234" DPT="80" SMAC="11:11:11:22:22:22" DMAC="11:11:11:33:33:33" MSG="访问阻断" DESC="" ACTION="拒绝" ISOUT="1"
    char _remark[1024] = {0};
    char *result = D_REFUSE;
    const char *pri = GetPriLevel(result);

    if (!m_syslog) {
        return 0;
    }

    if (m_gbkset) {
        return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                          "SRC=\"%s\" DST=\"%s\" SPT=\"%s\" DPT=\"%s\" SMAC=\"%s\" DMAC=\"%s\" "
                          "MSG=\"%s\" DESC=\"%s\" ACTION=\"%s\" ISOUT=\"%d\"",
                          pri, m_id, m_fw, dtime, pri, m_devid, LOGNAME_LINKLOG,
                          srcip, dstip, srcport, dstport, srcmac, dstmac,
                          LOG_CONTENT_REFUSE, remark, result, isout);
    } else {
        PRINT_DBG_HEAD
        print_dbg("LinkLog charset gbk to utf-8");

        strconv("GBK", remark, "UTF-8", _remark);
        return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                          "SRC=\"%s\" DST=\"%s\" SPT=\"%s\" DPT=\"%s\" SMAC=\"%s\" DMAC=\"%s\" "
                          "MSG=\"%s\" DESC=\"%s\" ACTION=\"%s\" ISOUT=\"%d\"",
                          pri, m_id, m_fw, dtime, pri, m_devid, attack_utf8,
                          srcip, dstip, srcport, dstport, srcmac, dstmac,
                          access_refuse_utf8, _remark, refuse_utf8, isout);
    }
}

/**
 * [SLOG_CLI_OPER::WriteFilterLog 处理内容过滤日志]
 * @param  user    [用户名]
 * @param  fname   [内容]
 * @param  remark  [备注]
 * @param  service [服务模块]
 * @param  srcip   [源IP]
 * @param  dstip   [目的IP]
 * @param  srcport [源端口]
 * @param  dstport [目的端口]
 * @param  isout   [是否外网]
 * @param  dtime   [时间]
 * @return         [成功返回0]
 */
int SLOG_CLI_OPER::WriteFilterLog(const char *user, const char *fname, const char *remark, const char *service,
                                  const char *srcip, const char *dstip, const char *srcport, const char *dstport,
                                  int isout, const char *dtime)     //user 为utf8 remark service fname为gbk
{
    //<5>Aug 02 23:53:28 192.168.1.254 ID="SU-GAP3000" FW="SUGAP" TIME="2019-09-24 15:28:08" PRI="5" DEVID="GAP-123EA89" MODULE="内容过滤日志"
    //USER="user1" SRC="1.1.1.1" DST="1.1.1.2" SPT="1234" DPT="80" PROTO="HTTP" MSG="发现关键字" DESC="密码" ACTION="拒绝" ISOUT="1"
    char _user[1024] = {0};
    char _fname[1024] = {0};
    char _remark[1024] = {0};
    char _service[1024] = {0};
    char tmp[1024] = {0};
    char *result = D_REFUSE;
    const char *pri = GetPriLevel(result);

    if (!m_syslog) {
        return 0;
    }

    if (m_gbkset) {
        PRINT_DBG_HEAD
        print_dbg("FilterLog charset utf-8 to gbk");

        strconv("UTF-8", user, "GBK", _user);
        strcpy(tmp, fname);
        if ((get_sucharset(tmp) == CHARSET_GBK)) strcpy(_fname, fname);
        else strconv("UTF-8", fname, "GBK", _fname);
        strcpy(tmp, remark);
        if ((get_sucharset(tmp) == CHARSET_GBK)) strcpy(_remark, remark);
        else strconv("UTF-8", remark, "GBK", _remark);
        strcpy(tmp, service);
        if ((get_sucharset(tmp) == CHARSET_GBK)) strcpy(_service, service);
        else strconv("UTF-8", service, "GBK", _service);

        return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                          "USER=\"%s\" SRC=\"%s\" DST=\"%s\" SPT=\"%s\" DPT=\"%s\" PROTO=\"%s\" "
                          "MSG=\"%s\" DESC=\"%s\" ACTION=\"%s\" ISOUT=\"%d\"",
                          pri, m_id, m_fw, dtime, pri, m_devid, LOGNAME_FILTERLOG,
                          _user, srcip, dstip, srcport, dstport, service,
                          fname, remark, result, isout);
    } else {
        PRINT_DBG_HEAD
        print_dbg("FilterLog charset gbk to utf-8");

        strcpy(tmp, fname);
        if ((get_sucharset(tmp) == CHARSET_UTF8)) strcpy(_fname, fname);
        else strconv("GBK", fname, "UTF-8", _fname);
        strcpy(tmp, remark);
        if ((get_sucharset(tmp) == CHARSET_UTF8)) strcpy(_remark, remark);
        else strconv("GBK", remark, "UTF-8", _remark);
        strcpy(tmp, service);
        if ((get_sucharset(tmp) == CHARSET_UTF8)) strcpy(_service, service);
        else strconv("GBK", service, "UTF-8", _service);

        return SlogFormat(pri, "<%s>ID=\"%s\" FW=\"%s\" TIME=\"%s\" PRI=\"%s\" DEVID=\"%s\" MODULE=\"%s\" "
                          "USER=\"%s\" SRC=\"%s\" DST=\"%s\" SPT=\"%s\" DPT=\"%s\" PROTO=\"%s\" "
                          "MSG=\"%s\" DESC=\"%s\" ACTION=\"%s\" ISOUT=\"%d\"",
                          pri, m_id, m_fw, dtime, pri, m_devid, filter_utf8,
                          user, srcip, dstip, srcport, dstport, _service,
                          _fname, _remark, refuse_utf8, isout);
    }
}
