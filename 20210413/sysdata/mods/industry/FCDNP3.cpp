/*******************************************************************************************
*文件:  FCDNP3.cpp
*描述:  DNP3模块
*作者:  王君雷
*日期:  2017-11-09
*修改:
*******************************************************************************************/
#include <stdlib.h>
#include "FCDNP3.h"

DNP3CMDDEFINE::DNP3CMDDEFINE(unsigned char incmd, int inrw, char *inchremark)
{
    cmd = incmd;
    rw = inrw;
    memset(chremark, 0, sizeof(chremark));
    if (strlen(inchremark) >= sizeof(chremark))
    {
        memcpy(chremark, inchremark, sizeof(chremark) - 1);
        printf("%s[%d]inchremark too long, cut it![%s]\n", __FUNCTION__, __LINE__, inchremark);
    }
    else
    {
        strcpy(chremark, inchremark);
    }
}

DNP3CMDDEFINE::~DNP3CMDDEFINE()
{
}

AQDEFINE::AQDEFINE(unsigned char inaq, unsigned char inar_len, bool inmode)
{
    aq = inaq;
    if ((inar_len == 0) || (inar_len == 1) || (inar_len == 2) || (inar_len == 4))
    {
        ar_len = inar_len;
    }
    else
    {
        printf("%s[%d]Warn: inar_len is [%d]\n", __FUNCTION__, __LINE__, inar_len);
        ar_len = 0;
    }

    mode = inmode;
}

AQDEFINE::~AQDEFINE()
{
}

//----------------------------------------------------------------------------
CDNP3::CDNP3()
{
    InitCmdDefine();
    InitAQDefine();
    m_rw = PROTO_RWNULL;
    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));
}

CDNP3::~CDNP3()
{
    m_cmddefine.clear();
    m_aqdefine.clear();
}

void CDNP3::InitCmdDefine()
{
    m_cmddefine.clear();
    m_cmddefine.push_back(DNP3CMDDEFINE(0, PROTO_WRITE , "确认"));
    m_cmddefine.push_back(DNP3CMDDEFINE(1, PROTO_READ, "读"));
    m_cmddefine.push_back(DNP3CMDDEFINE(2, PROTO_WRITE, "写"));
    m_cmddefine.push_back(DNP3CMDDEFINE(3, PROTO_RWNULL, "选择"));
    m_cmddefine.push_back(DNP3CMDDEFINE(4, PROTO_RWNULL, "操作"));
    m_cmddefine.push_back(DNP3CMDDEFINE(5, PROTO_RWNULL, "直接操作ACK"));
    m_cmddefine.push_back(DNP3CMDDEFINE(6, PROTO_RWNULL, "直接操作NO ACK"));
    m_cmddefine.push_back(DNP3CMDDEFINE(7, PROTO_WRITE, "立即冻结ACK"));
    m_cmddefine.push_back(DNP3CMDDEFINE(8, PROTO_WRITE, "立即冻结NO ACK"));
    m_cmddefine.push_back(DNP3CMDDEFINE(9, PROTO_WRITE, "冻结同时清除ACK"));
    m_cmddefine.push_back(DNP3CMDDEFINE(10, PROTO_WRITE, "冻结同时清除NO ACK"));
    m_cmddefine.push_back(DNP3CMDDEFINE(11, PROTO_WRITE, "在特定的时间或间隔冻结ACK"));
    m_cmddefine.push_back(DNP3CMDDEFINE(12, PROTO_WRITE, "在特定的时间或间隔冻结NO ACK"));
    m_cmddefine.push_back(DNP3CMDDEFINE(13, PROTO_RWNULL, "冷启动"));
    m_cmddefine.push_back(DNP3CMDDEFINE(14, PROTO_RWNULL, "热启动"));
    m_cmddefine.push_back(DNP3CMDDEFINE(15, PROTO_RWNULL, "用缺省值初始化数据"));
    m_cmddefine.push_back(DNP3CMDDEFINE(16, PROTO_RWNULL, "应用初始化"));
    m_cmddefine.push_back(DNP3CMDDEFINE(17, PROTO_RWNULL, "开始应用"));
    m_cmddefine.push_back(DNP3CMDDEFINE(18, PROTO_RWNULL, "停止应用"));
    m_cmddefine.push_back(DNP3CMDDEFINE(19, PROTO_RWNULL, "存储组态"));
    m_cmddefine.push_back(DNP3CMDDEFINE(20, PROTO_WRITE, "使能非请求信息"));
    m_cmddefine.push_back(DNP3CMDDEFINE(21, PROTO_WRITE, "禁止非请求信息"));
    m_cmddefine.push_back(DNP3CMDDEFINE(22, PROTO_RWNULL, "分类"));
    m_cmddefine.push_back(DNP3CMDDEFINE(23, PROTO_RWNULL, "测量延时"));
    m_cmddefine.push_back(DNP3CMDDEFINE(24, PROTO_RWNULL, "记录当前时间"));
    m_cmddefine.push_back(DNP3CMDDEFINE(25, PROTO_RWNULL, "打开文件"));
    m_cmddefine.push_back(DNP3CMDDEFINE(26, PROTO_RWNULL, "关闭文件"));
    m_cmddefine.push_back(DNP3CMDDEFINE(27, PROTO_RWNULL, "文件日期"));
    m_cmddefine.push_back(DNP3CMDDEFINE(28, PROTO_RWNULL, "文件信息"));
    m_cmddefine.push_back(DNP3CMDDEFINE(29, PROTO_RWNULL, "文件认证"));
    m_cmddefine.push_back(DNP3CMDDEFINE(30, PROTO_RWNULL, "终止文件"));
    m_cmddefine.push_back(DNP3CMDDEFINE(129, PROTO_RWNULL, "响应"));
    m_cmddefine.push_back(DNP3CMDDEFINE(130, PROTO_RWNULL, "主动发送"));
}

void CDNP3::InitAQDefine()
{
    m_aqdefine.clear();
    m_aqdefine.push_back(AQDEFINE(0, 1, true));
    m_aqdefine.push_back(AQDEFINE(1, 2, true));
    m_aqdefine.push_back(AQDEFINE(2, 4, true));
    m_aqdefine.push_back(AQDEFINE(6, 0, false));
    m_aqdefine.push_back(AQDEFINE(7, 1, false));
    m_aqdefine.push_back(AQDEFINE(8, 2, false));
    m_aqdefine.push_back(AQDEFINE(9, 4, false));
    m_aqdefine.push_back(AQDEFINE(17, 1, false));
    m_aqdefine.push_back(AQDEFINE(18, 2, false));
    m_aqdefine.push_back(AQDEFINE(19, 4, false));
    m_aqdefine.push_back(AQDEFINE(27, 1, false));
    m_aqdefine.push_back(AQDEFINE(28, 2, false));
    m_aqdefine.push_back(AQDEFINE(29, 4, false));
    m_aqdefine.push_back(AQDEFINE(37, 1, false));
    m_aqdefine.push_back(AQDEFINE(38, 2, false));
    m_aqdefine.push_back(AQDEFINE(39, 4, false));
    m_aqdefine.push_back(AQDEFINE(40, 2, false));
}

bool CDNP3::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1)
    {
        return DoSrcMsg(sdata, slen, cherror);
    }
    else
    {
        //return DoDstMsg(sdata, slen, cherror);
        return DoSrcMsg(sdata, slen, cherror);
    }
}

bool CDNP3::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    if (slen - hdlen <= 0)
    {
        //printf("%s[%d]Warn: slen = %d, hdlen = %d\n\n", __FUNCTION__, __LINE__, slen, hdlen);
        return true;
    }

    printf("\n%s[%d]==========================\n",__FUNCTION__, __LINE__);

    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));
    m_rw = PROTO_RWNULL;
    memset(&m_pdu, 0, sizeof(m_pdu));
    m_firstblock = true;

    //获取和校验DNP3链路层信息
    if (getlpdu(sdata + hdlen, slen - hdlen, cherror) < 0)
    {
        RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
        printf("%s[%d]%s\n",__FUNCTION__, __LINE__, cherror);
        return false;
    }

    //获取和校验DNP3应用层信息
    if (getapdu(sdata + hdlen, slen - hdlen, cherror) < 0)
    {
        RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
        printf("%s[%d]%s\n",__FUNCTION__, __LINE__, cherror);
        return false;
    }

    //如果只有链路层报文头 就放过
    if (PDU_ONLYLPDU == m_pdu.status)
    {
        if (g_debug)
        {
            printf("%s[%d]ONLY LPDU!\n\n", __FUNCTION__, __LINE__);
        }
        return true;
    }

    //本帧是本用户数据传输的第一帧
    if (m_firstblock)
    {
        //过滤命令
        if (FilterCode(cherror))
        {
            RecordCallLog(sdata, m_chcmd, m_chpara, cherror, true);
        }
        else
        {
            RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
            printf("%s[%d]%s\n",__FUNCTION__, __LINE__, cherror);
            return false;
        }
    }

    return true;
}

bool CDNP3::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/*******************************************************************************************
*功能:  获取和校验DNP3链路层信息
*参数:
*       sdata      DNP3链路层数据(即 TCPIP协议的应用层数据)
*       slen       数据长度
*       cherror    出错信息  出参
*注释:  返回值-1失败  0成功
*******************************************************************************************/
int CDNP3::getlpdu(const unsigned char *sdata, int slen, char *cherror)
{
    DNP3LPDU lpdu;
    if (slen < (int)sizeof(lpdu))
    {
        sprintf(cherror, "%s[%d]", DNP3_DATALEN_ERROR, slen);
        printf("%s[%d]%s\n", __FUNCTION__, __LINE__, cherror);
        return -1;
    }

    memcpy(&lpdu, sdata, sizeof(lpdu));

    //校验DNP3链路层头部
    if ((lpdu.identifier[0] != DNP3_HEAD1) || (lpdu.identifier[1] != DNP3_HEAD2))
    {
        sprintf(cherror, "%s[0x%2X 0x%2X]", DNP3_LHEAD_ERROR, lpdu.identifier[0], lpdu.identifier[1]);
        printf("%s[%d]%s\n", __FUNCTION__, __LINE__, cherror);
        return -1;
    }

    //校验DNP3链路层长度字段
    if ((lpdu.length > (int)DNP3_MAXSIZE)
        || (lpdu.length < (int)DNP3_MINSIZE))
    {
        sprintf(cherror, "%s[%d]", DNP3_LLEN_ERROR, lpdu.length);
        printf("%s[%d]%s\n", __FUNCTION__, __LINE__, cherror);
        return -1;
    }

    //根据链路层长度字段的值计算出数据包应为多长
    if (slen < (int)(DNP3_LEN2SIZE(lpdu.length)))
    {
        sprintf(cherror, "%s", DNP3_PROTO_ERROR);
        printf("%s[%d]%s slen = %d, DNP3_LEN2SIZE = %d\n",
            __FUNCTION__, __LINE__, cherror, slen, DNP3_LEN2SIZE(lpdu.length));
        return -1;
    }

    //校验DNP3链路层头部CRC
    unsigned short crctmp = GetCRC16_DNP(sdata, sizeof(lpdu) - sizeof(lpdu.crc));
    if (memcmp(&crctmp, lpdu.crc, 2) != 0)
    {
        sprintf(cherror, "%s", DNP3_CRC_ERROR);
        printf("%s[%d]%s crctmp = %02x%02x, lpdu.crc = %02x%02x\n",
            __FUNCTION__, __LINE__, cherror,
            *(((unsigned char*)(&crctmp))),
            *(((unsigned char*)(&crctmp)) + 1),
            lpdu.crc[0], lpdu.crc[1]);
        return -1;
    }

    //校验DNP3应用层数据CRC
    if (data_crc_check(sdata, lpdu.length) == 0)
    {
        m_pdu.lctrl = lpdu.ctrl;
        m_pdu.len = lpdu.length;
        return 0;
    }
    else
    {
        sprintf(cherror, "%s", DNP3_CRC_ERROR);
        printf("%s[%d]%s\n", __FUNCTION__, __LINE__, cherror);
        return -1;
    }
}

/**
 * [GetCRC16_DNP description]
 * @param  buf [数据源]
 * @param  len [数据长度]
 * @return     [校验值]
 */
unsigned short CDNP3::GetCRC16_DNP(const unsigned char *buf, int len)
{
    if (g_debug)
    {
        printf("%s[%d] len = %d\n", __FUNCTION__, __LINE__, len);
        for (int i = 0; i < len; i++)
        {
            printf("%02x ", buf[i]);
        }
        printf("\n");
    }
    unsigned char i;
    unsigned short crc = 0;            // Initial value
    unsigned char *data = (unsigned char *)buf;
    while (len--)
    {
        crc ^= *data++;            // crc ^= *data; data++;
        for (i = 0; i < 8; ++i)
        {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xA6BC;        // 0xA6BC = reverse 0x3D65
            else
                crc = (crc >> 1);
        }
    }

    //printf("%s[%d] ~crc %x\n", __FUNCTION__, __LINE__, ~crc);
    return ~crc;                // crc^Xorout
}

/*******************************************************************************************
*功能:  校验DNP3应用层数据CRC
*参数:
*       data       DNP3链路层数据
*       len        DNP3链路层头部中指示的长度
*注释:  返回值-1失败  0成功
*******************************************************************************************/
int CDNP3::data_crc_check(const unsigned char *data, int len)
{
    unsigned short crc = 0;
    int length = len - DNP3LPDU_LEN;
    int offset = sizeof(DNP3LPDU);

    while (length >= DNP3_USERSIZE)
    {
        memcpy(&crc, data + offset + DNP3_USERSIZE, sizeof(crc));

        if (GetCRC16_DNP(data + offset, DNP3_USERSIZE) == crc)
        {
            offset = offset + DNP3_USERSIZECRC;
            length = length - DNP3_USERSIZE;
        }
        else
        {
            printf("%s[%d]The CRC is wrong, fact_crc=0x%04x, crc=0x%04x\n",
                   __FUNCTION__, __LINE__, GetCRC16_DNP(data + offset, DNP3_USERSIZE), crc);
            return -1;
        }
    }

    if (length > 0)
    {
        memcpy(&crc, data + offset + length, sizeof(crc));
        if (GetCRC16_DNP(data + offset, length) != crc)
        {
            printf("%s[%d]The CRC is wrong, fact_crc=0x%04x, crc=0x%04x\n",
                   __FUNCTION__, __LINE__, GetCRC16_DNP(data + offset, length), crc);
            return -1;
        }
    }

    return 0;
}

/*******************************************************************************************
*功能:  解析DNP3应用层信息
*参数:
*       sdata      DNP3链路层数据(即 TCPIP协议的应用层数据)
*       slen       数据长度
*       cherror    出错信息  出参
*注释:  返回值-1失败  0成功
*******************************************************************************************/
int CDNP3::getapdu(const unsigned char *sdata, int slen, char *cherror)
{
    int ret = 0;
    if (m_pdu.len < DNP3LPDU_LEN)
    {
        sprintf(cherror, "%s", DNP3_PROTO_ERROR);
        printf("%s[%d]%s, m_pdu.len=%d\n", __FUNCTION__, __LINE__, cherror, m_pdu.len);
        ret = -1;
    }
    else if (m_pdu.len == DNP3LPDU_LEN)
    {
        m_pdu.status = PDU_ONLYLPDU;//仅存在链路层
    }
    else//存在应用层
    {
        m_firstblock = FirstBlock(sdata[sizeof(DNP3LPDU)]);
        if (m_firstblock)
        {
            int len = 0;
            if (SendByMaster())//主站发送
            {
                if (m_pdu.len < (DNP3LPDU_LEN + offsetof(DNP3APDU, object)))
                {
                    //只有链路层头部时m_pdu.len的值为5
                    //有应用层数据时m_pdu.len的值至少为8
                    //如果m_pdu.len的值大于5、小于8，则非法
                    sprintf(cherror, "%s", DNP3_PROTO_ERROR);
                    printf("%s[%d]%s, m_pdu.len=%d\n", __FUNCTION__, __LINE__, cherror, m_pdu.len);
                    ret = -1;
                }
                else
                {
                    m_pdu.acmd = *(sdata + sizeof(DNP3LPDU) + offsetof(DNP3APDU, cmd));
                    GetCmdString(m_pdu.acmd);
                    if (m_pdu.len < (DNP3LPDU_LEN + sizeof(DNP3APDU))) //仅存在应用层，不存在数据对象部分
                    {
                        m_pdu.status = PDU_APDUACMD;
                    }
                    else
                    {
                        m_pdu.aq = *(sdata + sizeof(DNP3LPDU) + offsetof(DNP3APDU, aq));
                        len = sizeof(DNP3APDU);
                    }
                }
            }
            else//从站发送
            {
                if (m_pdu.len < (DNP3LPDU_LEN + offsetof(DNP3APDU_IIN, object)))
                {
                    //只有链路层头部时m_pdu.len的值为5
                    //有应用层数据时m_pdu.len的值至少为10
                    //如果m_pdu.len的值大于5、小于10，则非法
                    sprintf(cherror, "%s", DNP3_PROTO_ERROR);
                    printf("%s[%d]%s, m_pdu.len=%d\n", __FUNCTION__, __LINE__, cherror, m_pdu.len);
                    ret = -1;
                }
                else
                {
                    m_pdu.acmd = *(sdata + sizeof(DNP3LPDU) + offsetof(DNP3APDU_IIN, cmd));
                    GetCmdString(m_pdu.acmd);
                    if (m_pdu.len < (DNP3LPDU_LEN + sizeof(DNP3APDU_IIN))) //仅存在应用层,不存在数据对象部分
                    {
                        m_pdu.status = PDU_APDUACMD;
                    }
                    else
                    {
                        m_pdu.aq = *(sdata + sizeof(DNP3LPDU) + offsetof(DNP3APDU_IIN, aq));
                        len = sizeof(DNP3APDU_IIN);
                    }
                }
            }

            if (len != 0) //判断数据对象是否存在
            {
                bool find = false;
                for (int i = 0; i < (int)m_aqdefine.size(); i++)
                {
                    if (m_aqdefine[i].aq == m_pdu.aq)
                    {
                        if (m_aqdefine[i].ar_len == 0)
                        {
                            m_pdu.status = PDU_APDUAQ;//不存在变程
                            sprintf(m_chpara, "限定词[%d]", m_pdu.aq);
                        }
                        else
                        {
                            m_pdu.status = PDU_APDUAR;//存在变程部分

                            if (m_aqdefine[i].mode)//起止模式
                            {
                                m_pdu.ar_start =
                                    GetARValue(sdata + sizeof(DNP3LPDU) + len,
                                               m_aqdefine[i].ar_len);

                                m_pdu.ar_end =
                                    GetARValue(sdata + sizeof(DNP3LPDU) + len + m_aqdefine[i].ar_len,
                                               m_aqdefine[i].ar_len);

                                sprintf(m_chpara, "限定词[%d], 变程[%d-%d]",
                                        m_pdu.aq, m_pdu.ar_start, m_pdu.ar_end);

                                if (m_pdu.ar_start > m_pdu.ar_end)
                                {
                                    sprintf(cherror, "%s", DNP3_RANGE_ERROR);
                                    printf("%s[%d]%s %s\n", __FUNCTION__, __LINE__, m_chpara, cherror);
                                    ret = -1;
                                }
                            }
                            else//数量模式
                            {
                                m_pdu.ar_end = m_pdu.ar_start =
                                                   GetARValue(sdata + sizeof(DNP3LPDU) + len, m_aqdefine[i].ar_len);

                                sprintf(m_chpara, "限定词[%d], 变程[%d]",
                                        m_pdu.aq, m_pdu.ar_end);
                            }
                        }
                        find = true;
                        break;
                    }
                }

                if (!find)
                {
                    printf("%s[%d]Warn undefined aq[%d]\n", __FUNCTION__, __LINE__, m_pdu.aq);
                    m_pdu.status = PDU_APDUAQ;//对于未定义的限定词，忽略应用层变程部分
                    sprintf(m_chpara, "限定词[%d]", m_pdu.aq);
                }
            }//len
        }//m_firstblock
    }

    return ret;
}

bool CDNP3::FirstBlock(unsigned char c)
{
    return (0x40 & c);
}

void CDNP3::GetCmdString(unsigned char c)
{
    bool find = 0;
    for (int i = 0; i < (int)m_cmddefine.size(); i++)
    {
        if (m_cmddefine[i].cmd == c)
        {
            find = true;
            strcpy(m_chcmd, m_cmddefine[i].chremark);
            m_rw = m_cmddefine[i].rw;
        }
    }

    if (!find)
    {
        sprintf(m_chcmd, "%d", c);
        m_rw = PROTO_RWNULL;
    }
    return;
}

bool CDNP3::SendByMaster()
{
    return ((m_pdu.lctrl & 0x80) > 0);
}

bool CDNP3::FilterCode(char *cherror)
{
    bool result = m_service->m_IfExec;
    if (PDU_APDUACMD == m_pdu.status)   //解析出了 功能码
    {
        for (int i = 0; i < m_service->m_cmdnum; i++)
        {
            //功能码匹配
            if (MatchCode(m_service->m_cmd[i]->m_cmd))
            {
                result = m_service->m_cmd[i]->m_action;
                break;
            }
        }
    }
    else if (PDU_APDUAQ == m_pdu.status)//解析出了 功能码 限定词
    {
        for (int i = 0; i < m_service->m_cmdnum; i++)
        {
            //功能码匹配
            if (MatchCode(m_service->m_cmd[i]->m_cmd))
            {
                //限定词匹配
                if (MatchAQ(m_service->m_cmd[i]->m_parameter))
                {
                    result = m_service->m_cmd[i]->m_action;
                    break;
                }
            }
        }
    }
    else if (PDU_APDUAR == m_pdu.status)//解析出了 功能码 限定词 变程
    {
        for (int i = 0; i < m_service->m_cmdnum; i++)
        {
            //功能码匹配
            if (MatchCode(m_service->m_cmd[i]->m_cmd))
            {
                //限定词匹配
                if (MatchAQ(m_service->m_cmd[i]->m_parameter))
                {
                    //变程匹配
                    if (MatchAR(m_service->m_cmd[i]->m_sign, m_service->m_cmd[i]->m_action))
                    {
                        result = m_service->m_cmd[i]->m_action;
                        break;
                    }

                }
            }
        }
    }

    if (!result)
    {
        sprintf(cherror, "%s", DNP3_PERM_FORBID);
    }
    return result;
}

int CDNP3::GetARValue(const unsigned char *buff, const unsigned char len)
{
    int ret = 0;
    if (buff != NULL)
    {
        if (len == 1)
        {
            ret = buff[0];
        }
        else if (len == 2)
        {
            ret = buff[0] * 256
                  + buff[1];
        }
        else if (len == 4)
        {
            ret = buff[0] * 256 * 256 * 256
                  + buff[1] * 256 * 256
                  + buff[2] * 256
                  + buff[3];
        }
        else
        {
            printf("%s[%d]invalid len %d\n", __FUNCTION__, __LINE__, len);
        }
    }
    else
    {
        printf("%s[%d]para null!\n", __FUNCTION__, __LINE__);
    }

    return ret;
}

/*******************************************************************************************
*功能:  匹配功能码
*参数:
*       chcmd      前台配置的命令字符串
*注释:  返回值 true匹配   false不匹配
*******************************************************************************************/
bool CDNP3::MatchCode(const char *chcmd)
{
    if (((strcmp(chcmd, "allread") == 0) && (m_rw == PROTO_READ))
            || ((strcmp(chcmd, "allwrite") == 0) && (m_rw == PROTO_WRITE)))
    {
        return true;
    }

    if (isdigit(chcmd[0]))
    {
        return (m_pdu.acmd == atoi(chcmd));
    }

    return false;
}

/*******************************************************************************************
*功能:  匹配限定词
*参数:
*       chcmd      前台配置的命令的参数字符串
*注释:  返回值 true匹配   false不匹配
*******************************************************************************************/
bool CDNP3::MatchAQ(const char *chcmd)
{
    if (isdigit(chcmd[0]))
    {
        const char *ptr = strchr(chcmd, '-');
        if (NULL == ptr)
        {
            return (m_pdu.aq == atoi(chcmd));
        }
        else
        {
            int leftval = atoi(chcmd);
            int rightval = atoi(ptr + 1);
            if (leftval <= rightval)
            {
                return ((m_pdu.aq >= leftval) && (m_pdu.aq <= rightval));
            }
        }
    }
    else if (chcmd[0] == '\0')//为空匹配所有
    {
        return true;
    }

    printf("%s[%d] para wrong![%s]\n", __FUNCTION__, __LINE__, chcmd);
    return false;
}

/*******************************************************************************************
*功能:  匹配变程
*参数:
*       chcmd      前台配置的命令的附加参数字符串
*       action     动作, true表示白名单, false表示黑名单
*注释:  返回值 true匹配   false不匹配
*******************************************************************************************/
bool CDNP3::MatchAR(const char *chcmd, bool action)
{
    if (isdigit(chcmd[0]))
    {
        int leftval = 0;
        int rightval = 0;
        const char *ptr = strchr(chcmd, '-');
        if (NULL == ptr)
        {
            leftval = rightval = atoi(chcmd);
        }
        else
        {
            leftval = atoi(chcmd);
            rightval = atoi(ptr + 1);
        }

        if (leftval <= rightval)
        {
            if (action)
            {
                //白名单匹配
                return (m_pdu.ar_start >= leftval) && (m_pdu.ar_end <= rightval);
            }
            else
            {
                //黑名单匹配 只要有交集就认为匹配上了
                return (!((m_pdu.ar_end < leftval) || (m_pdu.ar_start > rightval)));
            }
        }
    }
    else if (chcmd[0] == '\0')//为空匹配所有
    {
        return true;
    }

    printf("%s[%d] para wrong![%s]\n", __FUNCTION__, __LINE__, chcmd);
    return false;
}
