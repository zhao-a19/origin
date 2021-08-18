/*******************************************************************************************
*文  件:  FCIEC104.cpp
*描  述:  IEC104模块
*作  者:  王君雷
*日  期:  2017-11-24
*修  改:
*       修改strchr等系统函数返回值类型错误;引入zlog记录日志             ------> 2018-04-09
*       C_IC_NA_1、C_CI_NA_1、C_RD_NA_1、C_CS_NA_1都归类到读命令        ------> 2018-12-29
*******************************************************************************************/
#include "FCIEC104.h"
#include "debugout.h"

IEC104TYPEDEFINE::IEC104TYPEDEFINE(unsigned char incmd, char *inenglish, int inrw, char *inchinese)
{
    cmd = incmd;
    rw = inrw;
    memset(english, 0, sizeof(english));
    memset(chinese, 0, sizeof(chinese));
    if (strlen(inenglish) >= sizeof(english)) {
        memcpy(english, inenglish, sizeof(english) - 1);
        PRINT_ERR_HEAD
        print_err("inenglish[%d] too long, cut it!sizeof(english)[%d]", (int)strlen(inenglish), (int)sizeof(english));
    } else {
        strcpy(english, inenglish);
    }

    if (strlen(inchinese) >= sizeof(chinese)) {
        memcpy(chinese, inchinese, sizeof(chinese) - 1);
        PRINT_ERR_HEAD
        print_err("inchinese[%d] too long, cut it!sizeof(chinese)[%d]", (int)strlen(inchinese), (int)sizeof(chinese));
    } else {
        strcpy(chinese, inchinese);
    }
}

IEC104TYPEDEFINE::~IEC104TYPEDEFINE()
{
}

//--------------------------------------------------------------------

CIEC104::CIEC104()
{
    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));

    m_code = -1;
    m_addr = -1;
    m_point = -1;
    m_rw = PROTO_RWNULL;
    InitCodeDefine();
}

CIEC104::~CIEC104()
{
}

#define ONENAMEVALUE(c, rw, cname) c, #c, rw, cname
void CIEC104::InitCodeDefine()
{
    m_codedefine.clear();
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_SP_NA_1, PROTO_READ, "单点信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_SP_TA_1, PROTO_READ, "带时标单点信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_DP_NA_1, PROTO_READ, "双点信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_DP_TA_1, PROTO_READ, "带时标双点信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ST_NA_1, PROTO_READ, "步位置信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ST_TA_1, PROTO_READ, "带时标步位置信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_BO_NA_1, PROTO_READ, "32比特串")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_BO_TA_1, PROTO_READ, "带时标32比特串")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_NA_1, PROTO_READ, "测量值，规一化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_TA_1, PROTO_READ, "测量值，带时标规一化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_NB_1, PROTO_READ, "测量值，标度化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_TB_1, PROTO_READ, "测量值，带时标标度化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_NC_1, PROTO_READ, "测量值，短浮点数")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_TC_1, PROTO_READ, "测量值，带时标短浮点数")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_IT_NA_1, PROTO_READ, "累计量")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_IT_TA_1, PROTO_READ, "带时标累计量")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_EP_TA_1, PROTO_READ, "带时标继电保护装置事件")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_EP_TB_1, PROTO_READ, "带时标继电保护装置成组启动事件")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_EP_TC_1, PROTO_READ, "带时标继电保护装置成组输出电路信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_PS_NA_1, PROTO_READ, "具有状态变位检出的成组单点信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_ND_1, PROTO_READ, "测量值，不带品质描述的规一化值")));

    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_SP_TB_1, PROTO_READ, "带时标CP56TimE2A的单点信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_DP_TB_1, PROTO_READ, "带时标CP56TimE2A的双点信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ST_TB_1, PROTO_READ, "带时标CP56TimE2A的步位信息")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_BO_TB_1, PROTO_READ, "带时标CP56TimE2A的32位串")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_TD_1, PROTO_READ, "带时标CP56TimE2A的规一化测量值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_TE_1, PROTO_READ, "测量值，带时标CP56TimE2A的标度化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_ME_TF_1, PROTO_READ, "测量值，带时标CP56TimE2A的短浮点数")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_IT_TB_1, PROTO_READ, "带时标CP56TimE2A的累计值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_EP_TD_1, PROTO_READ, "带时标CP56TimE2A的继电保护装置事件")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_EP_TE_1, PROTO_READ, "带时标的成组继电保护装置成组启动事件")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_EP_TF_1, PROTO_READ, "带时标的继电保护装置成组输出电路信息")));

    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(M_EI_NA_1, PROTO_READ, "初始化结束")));

    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_SC_NA_1, PROTO_WRITE, "单命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_DC_NA_1, PROTO_WRITE, "双命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_RC_NA_1, PROTO_WRITE, "升降命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_SE_NA_1, PROTO_WRITE, "设定值命令，规一化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_SE_NB_1, PROTO_WRITE, "设定值命令，标度化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_SE_NC_1, PROTO_WRITE, "设定值命令，短浮点数")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_BO_NA_1, PROTO_WRITE, "32比特串")));

    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_SC_TA_1, PROTO_WRITE, "带时标CP56TimE2A的单命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_DC_TA_1, PROTO_WRITE, "带时标CP56TimE2A的双命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_RC_TA_1, PROTO_WRITE, "带时标CP56TimE2A的升降命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_SE_TA_1, PROTO_WRITE, "带时标CP56TimE2A的设定值命令，规一化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_SE_TB_1, PROTO_WRITE, "带时标CP56TimE2A的设定值命令，标度化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_SE_TC_1, PROTO_WRITE, "带时标CP56TimE2A的设定值命令，短浮点数")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_BO_TA_1, PROTO_WRITE, "带时标CP56TimE2A的32比特串")));

    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_IC_NA_1, PROTO_READ, "总召唤命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_CI_NA_1, PROTO_READ, "电能脉冲召唤命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_RD_NA_1, PROTO_READ, "读命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_CS_NA_1, PROTO_READ, "时钟同步命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_TS_NA_1, PROTO_WRITE, "测试命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_RP_NA_1, PROTO_WRITE, "复位进程命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_CD_NA_1, PROTO_WRITE, "延时传输命令")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(C_TS_TA_1, PROTO_WRITE, "带时标CP56TimE2A的测试命令")));

    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(P_ME_NA_1, PROTO_WRITE, "测量值参数，规一化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(P_ME_NB_1, PROTO_WRITE, "测量值参数，标度化值")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(P_ME_NC_1, PROTO_WRITE, "测量值参数，短浮点数")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(P_AC_NA_1, PROTO_WRITE, "参数激活")));

    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(F_FR_NA_1, PROTO_RWNULL, "文件准备好")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(F_SR_NA_1, PROTO_RWNULL, "节已准备好")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(F_SC_NA_1, PROTO_RWNULL, "召唤目录，选择文件，召唤文件，召唤节")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(F_LS_NA_1, PROTO_RWNULL, "最后的节，最后的度")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(F_AF_NA_1, PROTO_RWNULL, "确认文件，确认节")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(F_SG_NA_1, PROTO_RWNULL, "段")));
    m_codedefine.push_back(IEC104TYPEDEFINE(ONENAMEVALUE(F_DR_TA_1, PROTO_RWNULL, "目录")));
}

bool CIEC104::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        //return DoDstMsg(sdata, slen, cherror);
        return DoSrcMsg(sdata, slen, cherror);
    }
}

bool CIEC104::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    if (datalen <= 0) {
        return true;
    }

    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));

    //校验长度
    if (datalen < (int)sizeof(IECAPCI)) {
        sprintf(cherror, "%s[%d]", IEC104_DATALEN_ERROR, datalen);
        RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
        PRINT_ERR_HEAD
        print_err("%s", cherror);
        return false;
    }

    IECAPCI head;
    memcpy(&head, sdata + hdlen, sizeof(head));

    //协议启动字符检查、APDU长度检查
    if ((head.head != IEC104_HEAD)
        || (head.len < IEC104_MINLEN)
        || (head.len > IEC104_MAXLEN)
        || (datalen < head.len + 2)) {
        sprintf(cherror, "%s", IEC104_PROTO_ERROR);
        RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
        PRINT_ERR_HEAD
        print_err("%s", cherror);
        return false;
    }

    //控制域是什么类型格式？ I？ S？ U？
    int type = getframe(head);
    if (type == I_FRAME) {
        if (DecodeRequest(sdata + hdlen + sizeof(head),
                          slen - hdlen - sizeof(head),
                          head.len,
                          cherror)) {
            if (FilterCode(cherror)) {
                RecordCallLog(sdata, m_chcmd, m_chpara, cherror, true);
            } else {
                RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
                PRINT_ERR_HEAD
                print_err("%s", cherror);
                return false;
            }
        } else {
            PRINT_ERR_HEAD
            print_err("decode request fail");
        }
    } else {
        //I格式之外的，直接放过
        PRINT_DBG_HEAD
        print_dbg("frame type = %d, NOT I frame", type);
    }

    return true;
}

bool CIEC104::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/*******************************************************************************************
*功  能:  分析APDU控制域是什么类型格式
*参  数:
*         head      APCI(应用规约控制单元)，即APDU的头部
*返回值:  I_FRAME  I格式
*         U_FRAME  U格式
*         S_FRAME  S格式
*         UN_FRAME 未知的格式
*******************************************************************************************/
int CIEC104::getframe(IECAPCI &head)
{
    int ret = UN_FRAME;
    if (head.len == 4) { //S_FRAME & U_FRAME
        if ((head.ctrl_st.ctrl1 & 0x03) == 0x01) { //第一个八位组的第一个比特位为1  第二个比特位为0
            ret = S_FRAME;
        } else if ((head.ctrl_st.ctrl1 & 0x03) == 0x03) {
            ret = U_FRAME;
        } else {
            PRINT_ERR_HEAD
            print_err("head.len = %d, head.ctrl_st.ctrl1 = %d", head.len, head.ctrl_st.ctrl1);
        }
    } else if (head.len > 4) {
        if ((head.ctrl_st.ctrl1 & 0x01) == 0x00) { //第一个八位组的第一个比特位为0
            ret = I_FRAME;
        } else {
            PRINT_ERR_HEAD
            print_err("head.len = %d, head.ctrl_st.ctrl1 = %d", head.len, head.ctrl_st.ctrl1);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("head.len = %d", head.len);
    }

    return ret;
}

/*******************************************************************************************
*功  能:  解码请求
*参  数:
*         sdata      APCI之后的数据
*         slen       APCI之后的数据的长度
*         apcilen    APCI字段指示的长度
*         cherror    出错信息，出参
*返回值:  true  解码成功
*         false 解码失败
*******************************************************************************************/
bool CIEC104::DecodeRequest(unsigned char *sdata, int slen, int apcilen, char *cherror)
{
    if ((sdata == NULL) || (cherror == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    if ((slen < (int)sizeof(IECASDU_E))
        || (apcilen < (int)(IEC104_MINLEN + sizeof(IECASDU_E)))) {
        PRINT_ERR_HEAD
        print_err("slen = %d, apcilen = %d, sizeof(IECASDU_E) = %d", slen, apcilen, (int)sizeof(IECASDU_E));
        return false;
    }

    IECASDU_E asdu;
    memcpy(&asdu, sdata, sizeof(asdu));

    m_code = asdu.idtype;
    m_rw = PROTO_RWNULL;

    if (getval((unsigned char *)&asdu.station, (int)sizeof(asdu.station), m_addr)
        && getval((unsigned char *)&asdu.point, (int)sizeof(asdu.point), m_point)) {
        GetIECString();
        PRINT_DBG_HEAD
        print_dbg("Code: %s %s", m_chcmd, m_chpara);
        return true;
    } else {
        return false;
    }
}

/*******************************************************************************************
*功  能:  取得数值
*参  数:
*         data      数据开始地址
*         len       取值的长度
*         val       值，出参
*返回值:  成功返回true 失败返回false
*******************************************************************************************/
bool CIEC104::getval(unsigned char *data, int len, unsigned int &val)
{
    if (len == 2) {
        val = (data[0] + data[1] * 256);
    } else if (len == 3) {
        val = (data[0] + data[1] * 256 + data[2] * 256 * 256);
    } else {
        PRINT_ERR_HEAD
        print_err("Warn: len = %d", len);
        return false;
    }
    return true;
}

/*******************************************************************************************
*功  能:  根据解码出的命令等信息，取得对应的描述信息，存入成员变量
*参  数:
*返回值:  void
*******************************************************************************************/
void CIEC104::GetIECString()
{
    GetIECCodeString();
    sprintf(m_chpara, "公共地址[%d]点号[%d]", m_addr, m_point);
}

void CIEC104::GetIECCodeString()
{
    bool find = false;
    for (int i = 0; i < (int)m_codedefine.size(); i++) {
        if (m_codedefine[i].cmd == m_code) {
            m_rw = m_codedefine[i].rw;
            sprintf(m_chcmd, "[类型%d]%s", m_codedefine[i].cmd, m_codedefine[i].chinese);
            find = true;
        }
    }

    if (!find) {
        sprintf(m_chcmd, "[类型%d]", m_code);
    }
}

bool CIEC104::FilterCode(char *cherror)
{
    bool result = m_service->m_IfExec;
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        //匹配类型标识
        if (MatchCode(m_service->m_cmd[i]->m_cmd)) {
            //匹配公共地址
            if (MatchAddr(m_service->m_cmd[i]->m_parameter)) {
                //匹配点号
                if (MatchPoint(m_service->m_cmd[i]->m_sign)) {
                    result = m_service->m_cmd[i]->m_action;
                    break;
                }
            }
        }
    }

    if (!result) {
        sprintf(cherror, "%s", IEC104_PERM_FORBID);
    }

    return result;
}

/*******************************************************************************************
*功能:  匹配类型标识
*参数:
*       chcmd      前台配置的命令字符串
*注释:  返回值 true匹配   false不匹配
*******************************************************************************************/
bool CIEC104::MatchCode(const char *chcmd)
{
    if (((strcmp(chcmd, "allread") == 0) && (m_rw == PROTO_READ))
        || ((strcmp(chcmd, "allwrite") == 0) && (m_rw == PROTO_WRITE))) {
        return true;
    }

    if (isdigit(chcmd[0])) {
        return (m_code == (unsigned int)atoi(chcmd));
    }

    return false;
}

/*******************************************************************************************
*功能:  匹配类型标识
*参数:
*       chaddr      前台配置的公共地址
*注释:  返回值 true匹配   false不匹配
*******************************************************************************************/
bool CIEC104::MatchAddr(const char *chaddr)
{
    if (isdigit(chaddr[0])) {
        const char *ptr = strchr(chaddr, '-');
        if (NULL == ptr) {
            return (m_addr == (unsigned int)atoi(chaddr));
        } else {
            unsigned int leftval = atoi(chaddr);
            unsigned int rightval = atoi(ptr + 1);
            if (leftval <= rightval) {
                return ((m_addr >= leftval) && (m_addr <= rightval));
            }
        }
    } else if (chaddr[0] == '\0') { //为空匹配所有
        return true;
    }

    PRINT_ERR_HEAD
    print_err("para wrong![%s]", chaddr);
    return false;
}

/*******************************************************************************************
*功能:  匹配点号（即：信息对象地址  信息体地址）
*参数:
*       chpoint      前台配置的点号
*注释:  返回值 true匹配   false不匹配
*******************************************************************************************/
bool CIEC104::MatchPoint(const char *chpoint)
{
    if (isdigit(chpoint[0])) {
        const char *ptr = strchr(chpoint, '-');
        if (NULL == ptr) {
            return (m_point == (unsigned int)atoi(chpoint));
        } else {
            unsigned int leftval = atoi(chpoint);
            unsigned int rightval = atoi(ptr + 1);
            if (leftval <= rightval) {
                return ((m_point >= leftval) && (m_point <= rightval));
            }
        }
    } else if (chpoint[0] == '\0') { //为空匹配所有
        return true;
    }

    PRINT_ERR_HEAD
    print_err("para wrong![%s]", chpoint);
    return false;
}
