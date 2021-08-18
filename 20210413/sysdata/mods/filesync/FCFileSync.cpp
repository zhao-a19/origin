/*******************************************************************************************
*文件:  FCFileSync.cpp
*描述:  文件同步任务类
*作者:  王君雷
*日期:  2016-03
*修改:
*       线程ID使用pthread_t类型                                         ------> 2018-08-07
*       函数和变量统一风格；无参函数加void；使用zlog                    ------> 2018-09-05
*       修改外网备份目录IP地址解析错误,20180905引入的问题               ------> 2018-11-02
*       支持IPV6                                                        ------> 2019-06-08
*       修改解析挂载路径IP中的错误                                      ------> 2019-07-11
*       文件交换模块支持双机热备                                        ------> 2019-12-19 wjl
*       文件交换支持分模块生效                                          ------> 2020-11-10
*       所有任务总共只写一次配置文件                                    ------> 2021-01-11
*       msync每次重启都记录系统日志                                     ------> 2021-01-13
*       修改解析文件交换共享路径中的IP时，字符串没有加尾零的问题，可能会影响
*       文件交换双机热备对内网侧所使用IP的判断                            ------> 2021-07-16
*******************************************************************************************/
#include <sys/stat.h>
#include <string.h>
#include <algorithm>
#include <semaphore.h>

#include "FCYWBS.h"
#include "FCFileSync.h"
#include "define.h"
#include "debugout.h"
#include "readcfg.h"
#include "card_mg.h"

extern sem_t *g_iptables_lock;
extern CardMG g_cardmg;

int g_fsync_num = 0;
bool g_fsync_change = false;

CFileSyncTask::CFileSyncTask(int taskid)
{
    BZERO(m_outpath);
    BZERO(m_outbakpath);
    BZERO(m_outip);
    BZERO(m_outbakip);
    BZERO(m_outmappath);
    BZERO(m_outbakmappath);
    m_outbakflag = false;
    m_taskid = taskid;
}

CFileSyncTask::~CFileSyncTask(void)
{
}

/**
 * [CFileSyncTask::analysisIP 从挂载路径中解析出IP]
 * @param ch      [挂载字符串]
 * 例：
 * //192.168.200.1/dirx
 * //2001:1111:1111:1111:1111:1111:1111:1111/test1
 * @param ipbuff  [存放IP的缓冲区]
 * @param bufflen [缓冲区长度]
 */
#define ishex(c) (isdigit(c) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F')))
void CFileSyncTask::analysisIP(const char *ch, char *ipbuff, int bufflen)
{
    //查找首次出现数字的地方 或 十六进制字母的地方
    const char *ptr = strpbrk(ch, "0123456789ABCDEFabcdef");
    if (ptr == NULL) {
        PRINT_ERR_HEAD
        print_err("path error[%s]", ch);
        return;
    }

    memset(ipbuff, 0, bufflen);
    int len = 0;
    while ((ishex(ptr[len])) || (ptr[len] == ':') || (ptr[len] == '.')) {
        len++;
    }
    if (len >= bufflen) {
        PRINT_ERR_HEAD
        print_err("ip too long[%s].max support len[%d]", ch, bufflen - 1);
    } else {
        memcpy(ipbuff, ptr, len);
        PRINT_DBG_HEAD
        print_dbg("analysis ip result[%s]", ipbuff);
    }
}

/**
 * [CFileSyncTask::setOutPath 设置外网mount的路径 并提取出IP保存到成员变量]
 * @param ch [待处理字符串]
 * 例：
 * //192.168.200.1/dirx
 * //2001:1111:1111:1111:1111:1111:1111:1111/test1
 */
void CFileSyncTask::setOutPath(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }
    if (strlen(ch) >= sizeof(m_outpath)) {
        PRINT_ERR_HEAD
        print_err("para too long[%s].max support len[%d]", ch, (int)sizeof(m_outpath) - 1);
        return;
    }
    strcpy(m_outpath, ch);
    analysisIP(ch, m_outip, sizeof(m_outip));
}

/**
 * [CFileSyncTask::setInPath 设置内网mount的路径 并提取出IP保存到成员变量]
 * @param ch [待处理字符串]
 */
void CFileSyncTask::setInPath(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }
    if (strlen(ch) >= sizeof(m_inpath)) {
        PRINT_ERR_HEAD
        print_err("para too long[%s].max support len[%d]", ch, (int)sizeof(m_outpath) - 1);
        return;
    }
    strcpy(m_inpath, ch);
    analysisIP(ch, m_inip, sizeof(m_inip));
}

/**
 * [CFileSyncTask::setOutBakPath 设置外网mount的备份路径 并提取出IP保存到成员变量]
 * @param ch [待处理字符串]
 * 例：
 * //192.168.200.1/dirx
 * //2001:1111:1111:1111:1111:1111:1111:1111/test1
 */
void CFileSyncTask::setOutBakPath(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }
    if (strlen(ch) >= sizeof(m_outbakpath)) {
        PRINT_ERR_HEAD
        print_err("para too long[%s].max support len[%d]", ch, (int)sizeof(m_outbakpath) - 1);
        return;
    }
    strcpy(m_outbakpath, ch);
    analysisIP(ch, m_outbakip, sizeof(m_outbakip));
}

/**
 * [CFileSyncTask::setInBakPath 设置内网mount的备份路径 并提取出IP保存到成员变量]
 * @param ch [待处理字符串]
 */
void CFileSyncTask::setInBakPath(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }
    if (strlen(ch) >= sizeof(m_inbakpath)) {
        PRINT_ERR_HEAD
        print_err("para too long[%s].max support len[%d]", ch, (int)sizeof(m_inbakpath) - 1);
        return;
    }
    strcpy(m_inbakpath, ch);
    analysisIP(ch, m_inbakip, sizeof(m_inbakip));
}

/**
 * [CFileSyncTask::setOutBakFlag 设置是否开启了外网备份]
 * @param ch [待处理字符串]
 */
void CFileSyncTask::setOutBakFlag(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    m_outbakflag = (ch[0] == '1');
}

/**
 * [CFileSyncTask::setInBakFlag 设置是否开启了内网备份]
 * @param ch [待处理字符串]
 */
void CFileSyncTask::setInBakFlag(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    m_inbakflag = (ch[0] == '1');
}

/**
 * [CFileSyncTask::setOutPort 设置外网使用的端口]
 * @param ch [端口]
 */
void CFileSyncTask::setOutPort(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    if (strlen(ch) >= sizeof(m_outport)) {
        PRINT_ERR_HEAD
        print_err("para too long[%s].max support len[%d]", ch, (int)sizeof(m_outport) - 1);
        return;
    }
    strcpy(m_outport, ch);
    if (atoi(m_outport) <= 0) {
        PRINT_INFO_HEAD
        print_info("out port use default 445");
        strcpy(m_outport, "445");
    }
}

/**
 * [CFileSyncTask::setOutBakPort 设置外网使用的端口]
 * @param ch [端口]
 */
void CFileSyncTask::setOutBakPort(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    if (strlen(ch) >= sizeof(m_outbakport)) {
        PRINT_ERR_HEAD
        print_err("para too long[%s].max support len[%d]", ch, (int)sizeof(m_outbakport) - 1);
        return;
    }
    strcpy(m_outbakport, ch);
    if (atoi(m_outbakport) <= 0) {
        PRINT_INFO_HEAD
        print_info("out bak port use default 445");
        strcpy(m_outbakport, "445");
    }
}

/**
 * [CFileSyncTask::setOutFileSys 设置外网文件交换类型]
 * @param ch [类型]
 */
void CFileSyncTask::setOutFileSys(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    if (strlen(ch) >= sizeof(m_outfilesys)) {
        PRINT_ERR_HEAD
        print_err("para too long[%s].max support len[%d]", ch, (int)sizeof(m_outfilesys) - 1);
        return;
    }
    strcpy(m_outfilesys, ch);
}

/**
 * [CFileSyncTask::setOutBakFileSys 设置外网备份文件交换类型]
 * @param ch [类型]
 */
void CFileSyncTask::setOutBakFileSys(const char *ch)
{
    if (ch == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    if (strlen(ch) >= sizeof(m_outbakfilesys)) {
        PRINT_ERR_HEAD
        print_err("para too long[%s].max support len[%d]", ch, (int)sizeof(m_outbakfilesys) - 1);
        return;
    }
    strcpy(m_outbakfilesys, ch);
}

/**
 * [CFileSyncTask::getOutPort 获取外网端口]
 * @return  [端口]
 */
const char *CFileSyncTask::getOutPort(void)
{
    return m_outport;
}

/**
 * [CFileSyncTask::getOutBakPort 获取外网备份端口]
 * @return  [端口]
 */
const char *CFileSyncTask::getOutBakPort(void)
{
    return m_outbakport;
}

/**
 * [CFileSyncTask::getOutFileSys 获取外网文件类型]
 * @return  [类型]
 */
const char *CFileSyncTask::getOutFileSys(void)
{
    return m_outfilesys;
}

/**
 * [CFileSyncTask::getOutBakFileSys 获取外网备份文件类型]
 * @return  [类型]
 */
const char *CFileSyncTask::getOutBakFileSys(void)
{
    return m_outbakfilesys;
}

/**
 * [CFileSyncTask::setNatPath 设置外网NAT跳转路径]
 * 例如：//192.168.200.100/test1 转换为 //1.0.0.102/test1
 * @param natip [跳转IP]
 */
void CFileSyncTask::setNatPath(const char *natip)
{
    PRINT_DBG_HEAD
    print_dbg("filesync begin set nat path.[%s][%s]", m_outpath, natip);

    char *ptr = NULL;
    ptr = strchr(m_outpath + 2, '/');
    if (ptr == NULL) {
        PRINT_ERR_HEAD
        print_err("outpath error[%s]", m_outpath);
        return;
    }
    sprintf(m_outmappath, "//%s%s", natip, ptr);
    PRINT_DBG_HEAD
    print_dbg("filesync set nat path over. nat path[%s]", m_outmappath);
}

/**
 * [CFileSyncTask::setNatBakPath 设置外网备份NAT跳转路径]
 * @param natip [跳转IP]
 */
void CFileSyncTask::setNatBakPath(const char *natip)
{
    PRINT_DBG_HEAD
    print_dbg("filesync begin set nat bak path.[%s][%s]", m_outbakpath, natip);

    char *ptr = NULL;
    if (m_outbakflag) {
        ptr = strchr(m_outbakpath + 2, '/');
        if (ptr == NULL) {
            PRINT_ERR_HEAD
            print_err("outbakpath error[%s]", m_outbakpath);
            return;
        }
        sprintf(m_outbakmappath, "//%s%s", natip, ptr);
        PRINT_DBG_HEAD
        print_dbg("filesync set nat bak path over.path[%s]", m_outbakmappath);
    }
}

/**
 * [CFileSyncTask::writeConf 把整理后的mount路径写入配置文件]
 * @param  fileop [文件操作对象]
 * @return  [成功返回0 失败返回负值]
 */
int CFileSyncTask::writeConf(CFILEOP &fileop)
{
    char taskid[16] = {0};
    sprintf(taskid, "TASK%d", m_taskid);
    int ret = fileop.WriteCfgFile(taskid, "OutMapPath", m_outmappath);
    if (E_FILE_FALSE == ret) {
        PRINT_ERR_HEAD
        print_err("write cfg file fail[%s][%s]", taskid, m_outmappath);
        return -1;
    }
    if (m_outbakflag) {
        ret = fileop.WriteCfgFile(taskid, "OutBakMapPath", m_outbakmappath);
        if (E_FILE_FALSE == ret) {
            PRINT_ERR_HEAD
            print_err("write cfg file fail[%s][%s]", taskid, m_outbakmappath);
            return -1;
        }
    }
    return 0;
}

/**
 * [CFileSyncTask::getOutBakFlag 获取外网是否开启了备份]
 * @return  [description]
 */
bool CFileSyncTask::getOutBakFlag(void)
{
    return m_outbakflag;
}

/**
 * [CFileSyncTask::getInBakFlag 获取内网是否开启了备份]
 * @return  [description]
 */
bool CFileSyncTask::getInBakFlag(void)
{
    return m_inbakflag;
}

/**
 * [CFileSyncTask::getOutIP 获取外网mount路径的IP]
 * @return [IP]
 */
const char *CFileSyncTask::getOutIP(void)
{
    return m_outip;
}

/**
 * [CFileSyncTask::getInIP 获取内网mount路径的IP]
 * @return [IP]
 */
const char *CFileSyncTask::getInIP(void)
{
    return m_inip;
}

/**
 * [CFileSyncTask::getOutBakIP 获取外网备份mount路径的IP]
 * @return [IP]
 */
const char *CFileSyncTask::getOutBakIP(void)
{
    return m_outbakip;
}

/**
 * [CFileSyncTask::getInBakIP 获取内网备份mount路径的IP]
 * @return [IP]
 */
const char *CFileSyncTask::getInBakIP(void)
{
    return m_inbakip;
}

/**
 * [msyncDeamon 文件同步 线程函数]
 * @param  arg [未使用]
 * @return     [description]
 */
void *msyncDeamon(void *arg)
{
    pthread_setself("msyncdeamon");

    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "%s >/dev/null 2>&1&", MSYNC_FILE);
    CCommon common;

_LOOP:
    if (g_fsync_num > 0) {
        CLOGMANAGE mlog;
        if (mlog.Init() == E_OK) {
            mlog.WriteSysLog(LOG_TYPE_FILE_SYNC, D_SUCCESS, LOG_CONTENT_RUN_FILE_SYNC);
            mlog.DisConnect();
        } else {
            PRINT_ERR_HEAD
            print_err("msync mysql init fail");
        }
        system(chcmd);
        PRINT_INFO_HEAD
        print_info("chcmd[%s]", chcmd);
        sleep(3);
    }

    while (1) {
        sleep(1);
        if (g_fsync_change) {
            system("killall msync >/dev/null 2>&1");
            g_fsync_change = false;
            PRINT_INFO_HEAD
            print_info("fsync change.tasknum[%d]", g_fsync_num);
            sleep(1);
            goto _LOOP;
        }

        if ((g_fsync_num > 0) && (!common.ProcessRuning("msync"))) {
            PRINT_ERR_HEAD
            print_err("msync restart");
            goto _LOOP;
        }
    }

    return NULL;
}

/**
 * [StartMsync 启动文件同步程序]
 * @return  [成功返回0]
 */
int StartMsync(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, msyncDeamon, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create thread error");
        return -1;
    }

    return 0;
}

FILESYNC_MG::FILESYNC_MG(void)
{
    m_offset = 0;
    m_task_num = 0;
    memset(m_task, 0, sizeof(m_task));
    m_indstip.clear();
    m_outdstip.clear();
    m_outnatip.clear();
    m_ftpport.clear();
}

FILESYNC_MG::~FILESYNC_MG(void)
{
    clear();
}

/**
 * [FILESYNC_MG::clear 清空]
 */
void FILESYNC_MG::clear(void)
{
    DELETE_N(m_task, m_task_num);
    m_task_num = 0;
    g_cardmg.clear(FILESYNC_MOD);
    m_indstip.clear();
    m_outdstip.clear();
    m_outnatip.clear();
    m_ftpport.clear();
}

/**
 * [FILESYNC_MG::loadConf 加载配置信息]
 * @return  [成功返回0]
 */
int FILESYNC_MG::loadConf(void)
{
    char tmp[500] = {0};
    char taskno[16] = {0};
    int tasknum = 0;
    int ret = -1;

    CFILEOP fileop;
    if (fileop.OpenFile(FILESYNC_CONF, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", FILESYNC_CONF);
        goto _out;
    }

    READ_INT(fileop, "SYS", "TaskNum", tasknum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("filesync tasknum[%d]", tasknum);

    for (int i = 0; i < tasknum; i++) {
        CFileSyncTask *filesync = addTask();
        if (filesync == NULL) {
            break;
        }

        sprintf(taskno, "TASK%d", i);
        READ_STRING(fileop, taskno, "OutPath", tmp, true, _out);
        filesync->setOutPath(tmp);
        READ_STRING(fileop, taskno, "OutBackupFlag", tmp, true, _out);
        filesync->setOutBakFlag(tmp);

        BZERO(tmp);
        READ_STRING(fileop, taskno, "OutPort", tmp, false, _out);
        filesync->setOutPort(tmp);
        BZERO(tmp);
        READ_STRING(fileop, taskno, "OutFileSys", tmp, false, _out);
        filesync->setOutFileSys(tmp);

        if (filesync->getOutBakFlag()) {
            READ_STRING(fileop, taskno, "OutBackupDir", tmp, true, _out);
            filesync->setOutBakPath(tmp);

            BZERO(tmp);
            READ_STRING(fileop, taskno, "OutBackupPort", tmp, false, _out);
            filesync->setOutBakPort(tmp);
            BZERO(tmp);
            READ_STRING(fileop, taskno, "OutBackupFileSys", tmp, false, _out);
            filesync->setOutBakFileSys(tmp);
        }

        READ_STRING(fileop, taskno, "InPath", tmp, true, _out);
        filesync->setInPath(tmp);
        READ_STRING(fileop, taskno, "InBackupFlag", tmp, true, _out);
        filesync->setInBakFlag(tmp);
        if (filesync->getInBakFlag()) {
            READ_STRING(fileop, taskno, "InBackupDir", tmp, true, _out);
            filesync->setInBakPath(tmp);
        }
    }
    statistics();
    ret = 0;
_out:
    fileop.CloseFile();
    return ret;
}

/**
 * [FILESYNC_MG::addTask 添加一个任务]
 * @return  [成功返回任务指针失败返回NULL]
 */
CFileSyncTask *FILESYNC_MG::addTask(void)
{
    if (m_task_num == ARRAY_SIZE(m_task)) {
        PRINT_ERR_HEAD
        print_err("reach max support filesyncnum[%d]", ARRAY_SIZE(m_task));
        return NULL;
    }
    m_task[m_task_num] = new CFileSyncTask(m_task_num);
    if (m_task[m_task_num] == NULL) {
        PRINT_ERR_HEAD
        print_err("new CFileSyncTask fail. current tasknum[%d]", m_task_num);
        return NULL;
    }
    m_task_num++;
    return m_task[m_task_num - 1];
}

/**
 * [FILESYNC_MG::statistics 统计内外网服务器IP、外网侧FTP端口]
 */
void FILESYNC_MG::statistics(void)
{
    PRINT_INFO_HEAD
    print_info("statistics begin");

    m_indstip.clear();
    m_outdstip.clear();
    m_ftpport.clear();
    for (int i = 0; i < m_task_num; ++i) {
        push(m_indstip, m_task[i]->getInIP());
        if (m_task[i]->getInBakFlag()) {
            push(m_indstip, m_task[i]->getInBakIP());
        }
        push(m_outdstip, m_task[i]->getOutIP());
        if (strcasecmp(m_task[i]->getOutFileSys(), "FTP") == 0) {
            if (strcmp(m_task[i]->getOutPort(), "21") != 0) {
                push(m_ftpport, m_task[i]->getOutPort());
            }
        }
        if (m_task[i]->getOutBakFlag()) {
            push(m_outdstip, m_task[i]->getOutBakIP());
            if (strcasecmp(m_task[i]->getOutBakFileSys(), "FTP") == 0) {
                if (strcmp(m_task[i]->getOutBakPort(), "21") != 0) {
                    push(m_ftpport, m_task[i]->getOutBakPort());
                }
            }
        }
    }
    PRINT_INFO_HEAD
    print_info("statistics over.indstip[%d],outdstip[%d],outftport[%d]",
               m_indstip.size(), m_outdstip.size(), m_ftpport.size());
}

/**
 * [FILESYNC_MG::push 把str无重复的放入vector]
 * @param vec [vector]
 * @param str  [str]
 */
void FILESYNC_MG::push(vector<string> &vec, const char *str)
{
    vector<string>::iterator it = find(vec.begin(), vec.end(), str);
    if (it == vec.end()) {
        vec.push_back(str);
    } else {
        PRINT_DBG_HEAD
        print_dbg("ignore [%s]", str);
    }
}

/**
 * [FILESYNC_MG::setOffset 设置偏移量]
 * @param offsetcnt [偏移量]
 */
void FILESYNC_MG::setOffset(int offsetcnt)
{
    m_offset = offsetcnt;
}

/**
 * [FILESYNC_MG::makeNatIP 生成NAT IP]
 */
void FILESYNC_MG::makeNatIP(void)
{
    char natip[IP_STR_LEN] = {0};
    m_outnatip.clear();
    for (int i = 0; i < m_outdstip.size(); ++i) {
        if (is_ip6addr(m_outdstip[i].c_str())) {
            MakeV6NatIP(false, g_linklanipseg, m_offset + i + 1, natip, sizeof(natip));
        } else {
            MakeV4NatIP(false, g_linklanipseg, m_offset + i + 1, natip, sizeof(natip));
        }
        m_outnatip.push_back(natip);
        PRINT_INFO_HEAD
        print_info("[%s]-->[%s]", m_outdstip[i].c_str(), m_outnatip[i].c_str());
    }
}

/**
 * [FILESYNC_MG::findIP 查找IP所在vector的下标]
 * @param  vec [vector]
 * @param  ip  [IP]
 * @return     [成功返回下标 失败返回负值]
 */
int FILESYNC_MG::findIP(vector<string> &vec, const char *ip)
{
    int ret = -1;
    for (int i = 0; i < vec.size(); ++i) {
        if (strcmp(vec[i].c_str(), ip) == 0) {
            ret = i;
            break;
        }
    }
    return ret;
}

/**
 * [FILESYNC_MG::setNatIP 设置各个任务的nat ip]
 */
void FILESYNC_MG::setNatIP(void)
{
    int id = 0;
    for (int i = 0; i < m_task_num; ++i) {
        id = findIP(m_outdstip, m_task[i]->getOutIP());
        m_task[i]->setNatPath(m_outnatip[id].c_str());
        if (m_task[i]->getOutBakFlag()) {
            id = findIP(m_outdstip, m_task[i]->getOutBakIP());
            m_task[i]->setNatBakPath(m_outnatip[id].c_str());
        }
    }
}

/**
 * [FILESYNC_MG::writeConf 回写配置文件]
 */
void FILESYNC_MG::writeConf(void)
{
    PRINT_INFO_HEAD
    print_info("filesync write conf begin. tasknum[%d]", m_task_num);

    CFILEOP fileop;
    int ret = 0;

    if (fileop.OpenFile(FILESYNC_CONF, "r+") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("open file[%s] error", FILESYNC_CONF);
        goto _out;
    }

    for (int i = 0; i < m_task_num; ++i) {
        ret = m_task[i]->writeConf(fileop);
        if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("write conf fail. taskid[%d]", i);
            goto _out;
        }
    }

    PRINT_INFO_HEAD
    print_info("filesync write conf ok. tasknum[%d]", m_task_num);
    fileop.CloseFile();
    return;

_out:
    PRINT_ERR_HEAD
    print_err("filesync write conf fail");
    fileop.CloseFile();
    return;
}

/**
 * [FILESYNC_MG::configNatIP 配置NAT IP]
 */
void FILESYNC_MG::configNatIP(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int i = 0; i < m_outnatip.size(); ++i) {
        if (is_ip6addr(m_outnatip[i].c_str())) {
            sprintf(chcmd, "ifconfig eth%d inet6 add '%s'/64 up", g_linklan, m_outnatip[i].c_str());
        } else {
            sprintf(chcmd, "ifconfig eth%d:%d '%s' netmask '%s' up",
                    g_linklan, m_offset + i, m_outnatip[i].c_str(), DEFAULT_LINK_MASK);
        }
        system(chcmd);
        PRINT_INFO_HEAD
        print_info("[%s]", chcmd);
    }
}

/**
 * [FILESYNC_MG::setOutIptables 设置外网侧IPTABLES]
 */
void FILESYNC_MG::setOutIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int i = 0; i < m_outdstip.size(); ++i) {
        MAKE_TABLESTRING(chcmd, "-t nat -A NAT_FILE -d '%s' -p tcp -j DNAT --to '%s'",
                         is_ip6addr(m_outnatip[i].c_str()), m_outnatip[i].c_str(), m_outdstip[i].c_str());
        sem_wait(g_iptables_lock);
        system(chcmd);
        sem_post(g_iptables_lock);
        PRINT_INFO_HEAD
        print_info("[%s]", chcmd);
    }
}

/**
 * [FILESYNC_MG::clearOutIptables 清理外网侧IPTABLES规则]
 */
void FILESYNC_MG::clearOutIptables(void)
{
    sem_wait(g_iptables_lock);
    system("iptables -t nat -F NAT_FILE");
    system("ip6tables -t nat -F NAT_FILE");
    sem_post(g_iptables_lock);
    PRINT_INFO_HEAD
    print_info("filesync clear out nat iptables");
}

/**
 * [FILESYNC_MG::outFtpPortNum 外网侧FTP端口个数]
 * @return  [外网侧FTP端口个数]
 */
int FILESYNC_MG::outFtpPortNum(void)
{
    return m_ftpport.size();
}

/**
 * [FILESYNC_MG::taskNum 任务个数]
 * @return  [任务个数]
 */
int FILESYNC_MG::taskNum(void)
{
    return m_task_num;
}
