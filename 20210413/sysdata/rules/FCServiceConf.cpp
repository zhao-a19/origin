/*******************************************************************************************
*文件:  FCServiceConf.cpp
*描述:  应用服务类
*作者:  王君雷
*日期:  2016-03
*修改:
*       CSERVICECONF 添加以该类指针为参数的构造函数          ------> 2018-03-14
*       应用名称计算MD5值 MD5值相等也认为匹配上了            ------> 2021-03-24
*       多IP对应匹配，当devconfig中应用名称为明文，SYSRULES中应用名称为md5值时也做兼容匹配
*                                                          ------> 2021-05-07
*******************************************************************************************/
#include <string.h>
#include "debugout.h"
#include "FCServiceConf.h"
#include "common.h"

CCMDCONF::CCMDCONF(void)
{
    m_start = 0;
    BZERO(m_cmd);
    BZERO(m_sign);
    BZERO(m_parameter);
    BZERO(m_str);
    m_action = true;
    m_strlen = -1;
}

CCMDCONF::CCMDCONF(const CCMDCONF *pcmd)
{
    if (pcmd != NULL) {
        m_start = pcmd->m_start;
        m_action = pcmd->m_action;
        memcpy(m_cmd, pcmd->m_cmd, sizeof(m_cmd));
        memcpy(m_sign, pcmd->m_sign, sizeof(m_sign));
        memcpy(m_parameter, pcmd->m_parameter, sizeof(m_parameter));
        memcpy(m_str, pcmd->m_str, sizeof(m_str));
        m_strlen = pcmd->m_strlen;
    }
}

CCMDCONF:: ~CCMDCONF(void)
{
}

CSERVICECONF::CSERVICECONF(void)
{
    m_cmdnum = 0;
    m_IfExec = false;
    m_cklog = false;
    BZERO(m_asservice);
    BZERO(m_name);
    BZERO(m_namemd5);
    BZERO(m_cmd);
    m_queuenum = 0;
}

CSERVICECONF::CSERVICECONF(const char *chname)
{
    m_cmdnum = 0;
    m_IfExec = false;
    m_cklog = false;
    BZERO(m_asservice);
    BZERO(m_cmd);
    m_queuenum = 0;

    if ((chname != NULL) && (strlen(chname) < sizeof(m_name))) {
        strcpy(m_name, chname);
        GetNameMd5();
    } else {
        PRINT_ERR_HEAD
        print_err("service name error[%s]", chname);
        BZERO(m_name);
        BZERO(m_namemd5);
    }
}

CSERVICECONF::~CSERVICECONF(void)
{
    DELETE_N(m_cmd, C_MAX_CMD);
}

/**
 * 构造函数
 */
CSERVICECONF::CSERVICECONF(const CSERVICECONF *pser)
{
    if (pser != NULL) {
        memcpy(m_name, pser->m_name, sizeof(m_name));
        memcpy(m_namemd5, pser->m_namemd5, sizeof(m_namemd5));
        memcpy(m_protocol, pser->m_protocol, sizeof(m_protocol));
        memcpy(m_asservice, pser->m_asservice, sizeof(m_asservice));
        memcpy(m_sport, pser->m_sport, sizeof(m_sport));
        memcpy(m_dport, pser->m_dport, sizeof(m_dport));
        memcpy(m_tport, pser->m_tport, sizeof(m_tport));
        m_IfExec = pser->m_IfExec;
        m_cklog = pser->m_cklog;
        m_cmdnum = pser->m_cmdnum;
        m_queuenum = pser->m_queuenum;
        for (int i = 0; i < m_cmdnum; i++) {
            m_cmd[i] = new CCMDCONF(pser->m_cmd[i]);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("para null");
    }
}

/**
 * [CSERVICECONF::GetNameMd5 计算应用名称对应的MD5]
 */
void CSERVICECONF::GetNameMd5(void)
{
#if 0
    PRINT_INFO_HEAD
    print_info("%s", m_name);

    char chcmd[1024] = {0};
    CCommon commmon;
    sprintf(chcmd, "echo %s|md5sum|cut -d\" \" -f0", m_name);

    if (commmon.Sysinfo(chcmd, m_namemd5, sizeof(m_namemd5)) == NULL) {
        PRINT_ERR_HEAD
        print_err("chcmd[%s] fail", chcmd);
    } else {
        if (strlen(m_namemd5) == 32) {
            PRINT_INFO_HEAD
            print_info("name[%s] namemd5[%s]", m_name, m_namemd5);
        } else {
            PRINT_ERR_HEAD
            print_err("name[%s] namemd5[%s]", m_name, m_namemd5);
            BZERO(m_namemd5);
        }
    }
#else
    CCommon commmon;
    if (!commmon.GetStrMd5(m_name, m_namemd5, sizeof(m_namemd5))) {
        PRINT_ERR_HEAD
        print_err("get [%s] md5 fail", m_name);
    }
#endif
}

/**
 * [CSERVICECONF::NameEq 判断应用名称是否相同]
 * @param  name [应用名称]
 * @return      [相同返回true]
 */
bool CSERVICECONF::NameEq(const char *name)
{
    if (name == NULL) {
        PRINT_ERR_HEAD
        print_err("name is null");
        return false;
    }

    if (strcmp(name, m_name) == 0) {
        return true;
    }
    if (strlen(name) == 32) {
        if (strcmp(name, m_namemd5) == 0) {
            PRINT_INFO_HEAD
            print_info("Name[%s] NameMd5[%s] eq", m_name, name);
            return true;
        }
    }
    return false;
}

/**
 * [CSERVICECONF::NameEq 判断应用名称是否相同]
 * @param  name    [输入应用名称]
 * @param  namemd5 [输入应用名称的md5值]
 * @return         [相同返回true]
 */
bool CSERVICECONF::NameEq(const char *name, const char *namemd5)
{
    if (NameEq(name)) {
        return true;
    }

    if ((strlen(namemd5) == 32) && (strcmp(namemd5, m_name) == 0)) {
        PRINT_INFO_HEAD
        print_info("in devconfig appname[%s] in sysrules appname[%s],eq", name, m_name);
        return true;
    }
    return false;
}

/**
 * [CSERVICECONF::SetQueueNum 设置队列号]
 * @param queuenum [队列号]
 */
void CSERVICECONF::SetQueueNum(int queuenum)
{
    if (queuenum >= 0) {
        m_queuenum = queuenum;
    } else {
        PRINT_ERR_HEAD
        print_err("queue num error[%d]", queuenum);
    }
}

/**
 * [CSERVICECONF::GetQueueNum 获取队列号]
 * @return     [返回队列号]
 */
int CSERVICECONF::GetQueueNum(void)
{
    return m_queuenum;
}

/**
 * [CSERVICECONF::GetProtocol 获取传输层协议]
 * @return  [传输层协议]
 */
const char *CSERVICECONF::GetProtocol(void)
{
    if (strcmp(m_protocol, "") == 0) {
        PRINT_ERR_HEAD
        print_err("protocol is empty");
        return NULL;
    }
    return m_protocol;
}

/**
 * [CCMDCONF::HexToStr 把十六进制字符串转换为一般字符串]
 * @param  ch  [十六进制字符串]
 * @param  len [字符串长度]
 * @return     [成功返回true]
 */
bool CCMDCONF::HexToStr(const char *ch, int len)
{
    //大于0 说明之前转换过 可以直接使用
    if (m_strlen > 0) {
        return true;
    }
    int high = 0, low = 0, tmp = 0;
    if ((ch == NULL) || (len <= 0) || (len % 2 == 1) || (len / 2 > (int)sizeof(m_str))) {
        PRINT_ERR_HEAD
        print_err("para err. len = %d", len);
        return false;
    }

    for (int i = 0; i < len / 2; i++) {
        high = HexCharToValue(ch[i * 2]);
        low = HexCharToValue(ch[i * 2 + 1]);
        if ((high < 0) || (low < 0)) {
            PRINT_ERR_HEAD
            print_err("high = %d,low = %d", high, low);
            return false;
        }

        tmp = high * 16 + low;
        m_str[i] = (char)tmp;
    }

    m_strlen = len / 2;
    m_str[m_strlen] = '\0';

    PRINT_DBG_HEAD
    print_dbg("hex to str ok. m_strlen = %d", m_strlen);
    return true;
}

/**
 * [CCMDCONF::HexCharToValue 把十六进制字符转换为数值]
 * @param  ch [十六进制字符]
 * @return    [失败返回-1]
 */
int CCMDCONF::HexCharToValue(const char ch)
{
    int result = 0;

    if ((ch >= '0') && (ch <= '9')) {
        result = (int)(ch - '0');
    } else if ((ch >= 'a') && (ch <= 'z')) {
        result = (int)(ch - 'a') + 10;
    } else if ((ch >= 'A') && (ch <= 'Z')) {
        result = (int)(ch - 'A') + 10;
    } else {
        result = -1;
        PRINT_ERR_HEAD
        print_err("hex char to value err. ch = 0x%02x", ch);
    }
    return result;
}
