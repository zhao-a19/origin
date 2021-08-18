/*******************************************************************************************
*文件:  cip.cpp
*描述:  CIP模块
*作者:  王君雷
*日期:  2021-02-01
*修改:
*******************************************************************************************/
#include "cip.h"
#include "debugout.h"
#include "util-debug.h"

#define INT_INRANGE(a, b, c) (((c) >= (a)) && ((c) <= (b)))
#define FLOAT_INRANGE(a, b, c) (((c) >= (a)) && ((c) <= (b)))

CCIP::CCIP(void)
{
    Clear();
}

CCIP::~CCIP(void)
{
}

/**
 * [CCIP::Clear 清空初始化成员变量]
 */
void CCIP::Clear(void)
{
    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));
    memset(m_chpara2, 0, sizeof(m_chpara2));
    m_vecint.clear();
    m_vecfloat.clear();
    m_vecbool.clear();
    m_pointtype = POINT_UNKNOWN;
}

/**
 * [CCIP::DoMsg 处理应用信息]
 * @param  sdata     [IP头开始的数据]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [数据包是否改变了]
 * @param  bFromSrc  [是否来自客户端]
 * @return           [允许通过返回true]
 */
bool CCIP::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror, pktchange);
    } else {
        return DoDstMsg(sdata, slen, cherror, pktchange);
    }
}

/**
 * [CCIP::DoSrcMsg 处理应用信息 来自客户端的请求]
 * @param  sdata     [IP头开始的数据]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [数据包是否改变了]
 * @return           [允许通过返回true]
 */
bool CCIP::DoSrcMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange)
{
    int hdflag = GetHeadLen(sdata);
    int applayerlen = slen - hdflag;
    if (applayerlen <= 0) {
        return true;
    }

    Clear();
    if (m_parser.parser(sdata + hdflag, slen - hdflag)) {
        if (m_parser.get_command(m_chcmd, sizeof(m_chcmd))
            && m_parser.get_para(m_chpara, sizeof(m_chpara))
            && ((m_pointtype = m_parser.get_pointtype()) != POINT_UNKNOWN)) {
            switch (m_pointtype) {
            case POINT_INT:
                m_vecint = m_parser.get_vecint();
                break;
            case POINT_FLOAT:
                m_vecfloat = m_parser.get_vecfloat();
                break;
            case POINT_BOOL:
                m_vecbool = m_parser.get_vecbool();
                break;
            default:
                SCLogDebug("ignore pointtype 0x%04x", m_pointtype);
                break;
            }
        }
        if (strlen(m_chcmd) > 0) {
            bool flag = Filter(cherror);
            MakePara();
            RecordCallLog(sdata, m_chcmd, m_chpara2, cherror, flag);
            SCLogDebug("cip cmd[%s] para[%s] %s", m_chcmd, m_chpara2, flag ? "pass" : "forbid");
            return flag;
        } else {
            PRINT_INFO_HEAD
            print_info("not find command");
        }
    } else {
        PRINT_INFO_HEAD
        print_info("parser fail. slen[%d]", slen);
    }
    return true;
}

/**
 * [CCIP::MakePara 组装参数信息 用于记录日志]
 * @return  [组装成功返回true]
 */
bool CCIP::MakePara(void)
{
    char tmpbuf[32] = {0};

    if (strcmp(m_chcmd, CIP_READ_STR) == 0) {
        sprintf(m_chpara2, "%s:%s", CIP_POINT_NAME, m_chpara);
        return true;
    }

    switch (m_pointtype) {
    case POINT_INT:
        sprintf(m_chpara2, "%s:%s%s:", CIP_POINT_NAME, m_chpara, CIP_POINT_VALUE);
        for (int i = 0; i < m_vecint.size(); ++i) {
            sprintf(tmpbuf, " %d", m_vecint[i]);
            if (strlen(m_chpara2) + strlen(tmpbuf) < sizeof(m_chpara2)) {
                strcat(m_chpara2, tmpbuf);
            }
        }
        break;
    case POINT_BOOL:
        sprintf(m_chpara2, "%s:%s%s:", CIP_POINT_NAME, m_chpara, CIP_POINT_VALUE);
        for (int i = 0; i < m_vecbool.size(); ++i) {
            sprintf(tmpbuf, " %d", m_vecbool[i]);
            if (strlen(m_chpara2) + strlen(tmpbuf) < sizeof(m_chpara2)) {
                strcat(m_chpara2, tmpbuf);
            }
        }
        break;
    case POINT_FLOAT:
        sprintf(m_chpara2, "%s:%s%s:", CIP_POINT_NAME, m_chpara, CIP_POINT_VALUE);
        for (int i = 0; i < m_vecfloat.size(); ++i) {
            sprintf(tmpbuf, " %f", m_vecfloat[i]);
            if (strlen(m_chpara2) + strlen(tmpbuf) < sizeof(m_chpara2)) {
                strcat(m_chpara2, tmpbuf);
            }
        }
        break;
    default:
        strcpy(m_chpara2, m_chpara);
        break;
    }
    return true;
}

/**
 * [CCIP::MatchValue 匹配测点的值 为写动作时才进入该函数]
 * @param  para2 [界面配置的附加参数]
 * @param  action  [true表示白名单]
 * @return       [匹配返回true]
 */
bool CCIP::MatchValue(const char *para2, bool action)
{
    if (para2 == NULL) {
        PRINT_ERR_HEAD
        print_err("para error");
        return false;
    }
    if (para2[0] == 0) {
        return true; //为空匹配所有
    }

    bool ret = false; //默认值为false
    //对于白名单 所有测点值必须都在范围内才算匹配
    //对于黑名单 只要有一个值在范围内就算匹配
    switch (m_pointtype) {
    case POINT_INT: {
        int low = 0, high = 0;
        const char *p = strchr(para2, '-');
        if (p == NULL) {
            low = high = atoi(para2);
        } else {
            low = atoi(para2);
            high = atoi(p + 1);
        }
        SCLogDebug("low %d, high %d", low, high);
        if (low > high) {
            PRINT_ERR_HEAD
            print_err("config error.low[%d] high[%d]", low, high);
            return false;
        }
        if (action) {
            for (int i = 0; i < m_vecint.size(); ++i) {
                if (!INT_INRANGE(low, high, m_vecint[i])) {
                    goto _out;
                }
            }
            ret = true;
        } else {
            for (int i = 0; i < m_vecint.size(); ++i) {
                if (INT_INRANGE(low, high, m_vecint[i])) {
                    ret = true;
                    goto _out;
                }
            }
        }
        break;
    }
    case POINT_BOOL: {
        int n = atoi(para2);
        if (action) {
            for (int i = 0; i < m_vecbool.size(); ++i) {
                if (m_vecbool[i] != n) {
                    goto _out;
                }
            }
            ret = true;
        } else {
            for (int i = 0; i < m_vecbool.size(); ++i) {
                if (m_vecbool[i] == n) {
                    ret = true;
                    goto _out;
                }
            }
        }
        break;
    }
    case POINT_FLOAT: {
        double low = 0, high = 0;
        const char *p = strchr(para2, '-');
        if (p == NULL) {
            low = high = atof(para2);
        } else {
            low = atof(para2);
            high = atof(p + 1);
        }
        SCLogDebug("low %f, high %f", low, high);
        if (low > high) {
            PRINT_ERR_HEAD
            print_err("config error.low[%f] high[%f]", low, high);
            return false;
        }
        if (action) {
            for (int i = 0; i < m_vecfloat.size(); ++i) {
                if (!FLOAT_INRANGE(low, high, m_vecfloat[i])) {
                    goto _out;
                }
            }
            ret = true;
        } else {
            for (int i = 0; i < m_vecfloat.size(); ++i) {
                if (FLOAT_INRANGE(low, high, m_vecfloat[i])) {
                    ret = true;
                    goto _out;
                }
            }
        }
        break;
    }
    default:
        PRINT_ERR_HEAD
        print_err("ignore pointtype [0x%04x]", m_pointtype);
        break;
    }
_out:
    return ret;
}

/**
 * [CCIP::Filter 过滤命令]
 * @param  cherror [出错返回信息 出参]
 * @return         [允许通过返回true]
 */
bool CCIP::Filter(char *cherror)
{
    bool bflag = m_service->m_IfExec;
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (strcasecmp(m_chcmd, m_service->m_cmd[i]->m_cmd) == 0) {
            if (m_common.casestrstr((const unsigned char *)m_chpara,
                                    (const unsigned char *)m_service->m_cmd[i]->m_parameter, 0,
                                    strlen(m_chpara)) == E_COMM_OK) {
                if ((strcmp(m_chcmd, CIP_WRITE_STR) != 0)
                    || MatchValue(m_service->m_cmd[i]->m_sign, m_service->m_cmd[i]->m_action)) {
                    bflag = m_service->m_cmd[i]->m_action;
                    break;
                }
            }
        }
    }

    if (!bflag) {
        sprintf(cherror, "%s", CIP_PERM_FORBID);
        PRINT_ERR_HEAD
        print_err("cip cmd[%s] para[%s] not allow to pass.queuenum[%d]", m_chcmd, m_chpara,
                  m_service->GetQueueNum());
    }
    return bflag;
}

/**
 * [CCIP::DoSrcMsg 处理应用信息 来自服务器的响应]
 * @param  sdata     [IP头开始的数据]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [数据包是否改变了]
 * @return           [允许通过返回true]
 */
bool CCIP::DoDstMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange)
{
    return DoSrcMsg(sdata, slen, cherror, pktchange);
}

