/*******************************************************************************************
*文件:  FCSingle.cpp
*描述:  应用模块基类
*作者:  王君雷
*日期:  2016
*
*修改:
*        文件类型过滤，比较时忽略大小写                               ------> 2018-03-03
*        记录内容审查日志使用宏 LOG_TYPE_FILTER_FILE解决日志乱码问题  ------> 2018-07-18
*        iptables 多队列支持，开发过程版                              ------> 2019-01-30
*        完善IPV6记录数据包日志功能                                   ------> 2019-02-16
*        修改文件后缀过滤，目录中含点号时解析不准确的BUG              ------> 2019-05-12
*        访问日志支持记录MAC字段,暂设置为空                           ------> 2020-01-16 wjl
*        可以过滤中文邮件主题                                        ------> 2020-08-31 wjl
*        文件类型过滤，支持分模块生效                                 ------> 2020-11-03
*        数据库访问模块，添加英文的中括号为合法的表名组成部分           ------> 2020-12-30 wjl
*******************************************************************************************/
#include "FCSingle.h"
#include "struct_info.h"
#include "FCMsgAck.h"
#include "FCMailCoder.h"
#include "FCLogContainer.h"
#include "network.h"
#include "debugout.h"
#include "filetype_mg.h"

extern bool g_ckauth;

CSINGLE::CSINGLE(void)
{
    m_service = NULL;
    m_ipv6_offsetlen = 0;
    m_ipportmap.clear();
}

CSINGLE::~CSINGLE(void)
{
}

/**
 * [CSINGLE::IsTCP 是否为TCP应用]
 * @return  [是返回true]
 */
bool CSINGLE::IsTCP(void)
{
    const char *proto = m_service->GetProtocol();
    if (proto == NULL) {
        PRINT_ERR_HEAD
        print_err("get protocol fail");
        return false;
    }

    return (strcasecmp("TCP", proto) == 0);
}

/**
 * [CSINGLE::IsUDP 是否为UDP应用]
 * @return  [是返回true]
 */
bool CSINGLE::IsUDP(void)
{
    const char *proto = m_service->GetProtocol();
    if (proto == NULL) {
        PRINT_ERR_HEAD
        print_err("get protocol fail");
        return false;
    }

    return (strcasecmp("UDP", proto) == 0);
}

/**
 * [CSINGLE::IsICMP 是否为ICMP应用]
 * @return  [是返回true]
 */
bool CSINGLE::IsICMP(void)
{
    const char *proto = m_service->GetProtocol();
    if (proto == NULL) {
        PRINT_ERR_HEAD
        print_err("get protocol fail");
        return false;
    }

    return (strcasecmp("ICMP", proto) == 0);
}

/**
 * [CSINGLE::IsICMPV6 是否为ICMPV6应用]
 * @return  [是返回true]
 */
bool CSINGLE::IsICMPV6(void)
{
    const char *proto = m_service->GetProtocol();
    if (proto == NULL) {
        PRINT_ERR_HEAD
        print_err("get protocol fail");
        return false;
    }

    return (strcasecmp("ICMPV6", proto) == 0);
}

/**
 * [CSINGLE::GetHeadLenIPv4 获取应用层内容相对于IP头部开始位置的偏移长度]
 * @param  sdata [IP头开始的数据包]
 * @return       [偏移长度 失败返回负值]
 */
int CSINGLE::GetHeadLenIPv4(unsigned char *sdata)
{
    switch (IPV4_PROTO(sdata)) {
    case TCP:
        return IPV4_IPTCP_HEADER_LEN(sdata);
    case UDP:
        return IPV4_IPUDP_HEADER_LEN(sdata);
    case ICMP:
        return _ipheadlen(sdata);
    default:
        PRINT_ERR_HEAD
        print_err("unknown ipv4 proto. %d", IPV4_PROTO(sdata));
        return -1;
    }
}

/**
 * [CSINGLE::GetHeadLenIPv6 获取应用层内容相对于IP头部开始位置的偏移长度]
 * @param  sdata [网络层开始的数据包]
 * @return       [偏移长度 失败返回负值]
 */
int CSINGLE::GetHeadLenIPv6(unsigned char *sdata)
{
    int ret = m_ipv6_offsetlen;
    if (IsTCP()) {
        ret += _tcpheadlen(sdata + ret);
    } else if (IsUDP()) {
        ret += _udpheadlen(sdata + ret);
    } else if (IsICMPV6()) {
    } else {
        PRINT_ERR_HEAD
        print_err("unknown ipv6 proto[%s]", m_service->GetProtocol());
        return -1;
    }
    return ret;
}

/**
 * [CSINGLE::GetHeadLen 获取应用层内容相对于IP头部开始位置的偏移长度]
 * @param  sdata [网络层开始的数据包]
 * @return       [偏移长度 失败返回负值]
 */
int CSINGLE::GetHeadLen(unsigned char *sdata)
{
    if (_ipv4(sdata)) {
        return GetHeadLenIPv4(sdata);
    } else if (_ipv6(sdata)) {
        return GetHeadLenIPv6(sdata);
    } else {
        PRINT_ERR_HEAD
        print_err("unknown proto in get head len func");
        return -1;
    }
}

/**
 * [CSINGLE::SetRecordFlag 设置是否记录日志]
 * @param  bflag [是否记录]
 */
void  CSINGLE::SetRecordFlag(bool bflag)
{
    m_recordlog = bflag;
}

/**
 * [CSINGLE::GetIPPortFromPack 从数据包中解析出IP端口信息]
 * @param sdata [网络层开头的数据包]
 * @param sip   [源IP]
 * @param dip   [目的IP]
 * @param sport [源端口]
 * @param dport [目的端口]
 */
void CSINGLE::GetIPPortFromPack(const unsigned char *sdata, char *sip, char *dip, char *sport, char *dport)
{
    if ((sdata == NULL) || (sip == NULL) || (dip == NULL)) {
        PRINT_ERR_HEAD
        print_err("get ip port from pack para null");
        return;
    }

    if (_ipv4(sdata)) {
        inet_ntop(AF_INET, IPV4_SIP(sdata), sip, IP_STR_LEN);
        inet_ntop(AF_INET, IPV4_DIP(sdata), dip, IP_STR_LEN);
        if (IS_IPV4TCP(sdata)) {
            PTCP_HEADER ptcp = _tcpipdata(sdata);
            if (sport != NULL) {
                sprintf(sport, "%d", ntohs(ptcp->th_sport));
            }
            if (dport != NULL) {
                sprintf(dport, "%d", ntohs(ptcp->th_dport));
            }
        } else if (IS_IPV4UDP(sdata)) {
            PUDP_HEADER pudp = _udpipdata(sdata);
            if (sport != NULL) {
                sprintf(sport, "%d", ntohs(pudp->uh_sport));
            }
            if (dport != NULL) {
                sprintf(dport, "%d", ntohs(pudp->uh_dport));
            }
        }
    } else if (_ipv6(sdata)) {
        inet_ntop(AF_INET6, IPV6_SIP(sdata), sip, IP_STR_LEN);
        inet_ntop(AF_INET6, IPV6_DIP(sdata), dip, IP_STR_LEN);
        if (IsTCP()) {
            PTCP_HEADER ptcp = (PTCP_HEADER)(sdata + m_ipv6_offsetlen);
            if (sport != NULL) {
                sprintf(sport, "%d", ntohs(ptcp->th_sport));
            }
            if (dport != NULL) {
                sprintf(dport, "%d", ntohs(ptcp->th_dport));
            }
        } else if (IsUDP()) {
            PUDP_HEADER pudp = (PUDP_HEADER)(sdata + m_ipv6_offsetlen);
            if (sport != NULL) {
                sprintf(sport, "%d", ntohs(pudp->uh_sport));
            }
            if (dport != NULL) {
                sprintf(dport, "%d", ntohs(pudp->uh_dport));
            }
        }
    }
}

/**
 * [CSINGLE::MidIPToTIP 把输入的内部跳转IP替换为对应的代理IP 因为内部跳转IP不能出现在日志中
 * 代理模式时需要调用]
 * @param  ip [输入的IP  既是入参又是出参]
 * @return    [成功返回true]
 */
bool CSINGLE::MidIPToTIP(char *ip)
{
    if (ip == NULL) {
        PRINT_ERR_HEAD
        print_err("midip to tip para null.");
        return false;
    }

    for (int j = 0; j < (int)m_ipportmap.size(); j++) {
        if (m_ipportmap[j].MidIPEqual(ip)) {
            strcpy(ip, m_ipportmap[j].GetTIP());
            return true;
        }
    }
    return false;
}

/**
 * [CSINGLE::RecordCallLog 写访问日志]
 * @param sdata   [IP头开始的数据包]
 * @param chcmd   [命令]
 * @param chpara  [参数]
 * @param cherror [出错信息]
 * @param result  [日志结果类型 成功 or 失败]
 */
void CSINGLE::RecordCallLog(unsigned char *sdata, const char *chcmd, const char *chpara,
                            const char *cherror, bool result)
{
    if (!((g_iflog && m_recordlog) || g_syslog)) {
        return;
    }

    char authname[AUTH_NAME_LEN] = {0};
    char tmpsip[IP_STR_LEN] = {0};
    char tmpdip[IP_STR_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};

    GetIPPortFromPack(sdata, tmpsip, tmpdip, tmpsport, tmpdport);

    if (g_workflag == WORK_MODE_PROXY) { //内部跳转IP需替换为代理IP
        if (MidIPToTIP(tmpdip) || MidIPToTIP(tmpsip)) {
        }
    }

    if (g_ckauth && (g_workflag != WORK_MODE_TRANSPARENT)) { //透明模式时不认证
        if ((GetAuthName(tmpsip, authname, sizeof(authname)) == 0)
            || (GetAuthName(tmpdip, authname, sizeof(authname)) == 0)) {
        }
    }

    CallLogPara *p = new CallLogPara;
    if (p != NULL) {
        if (p->SetValues(authname, tmpsip, tmpdip, tmpsport, tmpdport, "", "", m_service->m_asservice,
                         chcmd, chpara, result ? D_SUCCESS : D_REFUSE, cherror)) {
            LogContainer &s1 = LogContainer::GetInstance();
            s1.PutPara(p);
        } else {
            PRINT_ERR_HEAD
            print_err("set values fail[authname %s, sip %s, dip %s, sport %s, dport %s, %s:%s:%s:%s]",
                      authname, tmpsip, tmpdip, tmpsport, tmpdport, m_service->m_asservice,
                      chcmd, chpara, cherror);
            delete p;
        }
    }
}

#if 0
bool CSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    return true;
}
#endif

/**
 * [CSINGLE::DoMsgIPV6 处理数据包 IPV6]
 * @param  sdata     [网络层开始的数据包]
 * @param  slen      [数据包长度]
 * @param  offsetlen [传输层头部相对于网络层头部的偏移量]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [数据包是否被改变了]
 * @param  bFromSrc  [是否来自客户端方向]
 * @return           [允许通过返回true]
 */
bool CSINGLE::DoMsgIPV6(unsigned char *sdata, int slen, int offsetlen, char *cherror, int *pktchange, int bFromSrc)
{
    m_ipv6_offsetlen = offsetlen; //把该偏移量保存到成员变量 因为IPV6可能有好多扩展头部 计算该数值比较费时 以后使用不必再计算一遍了
    return DoMsg(sdata, slen, cherror, pktchange, bFromSrc);
}

bool CSINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    return true;
}

bool CSINGLE::DecodeRequest(unsigned char *sdata, int slen, char *cherror)
{
    return false;
}

bool CSINGLE::DecodeReply(unsigned char *sdata, int slen, char *cherror)
{
    return false;
}

/**
 * [GetTableName 取得表名]
 * @param  ch    [语句]
 * @param  len   [语句长度]
 * @param  param [存放解析出的表名]
 * @return       [成功返回true]
 * 当ch中有空格回车换行等无效字符时会忽略掉
 * 如：ch为"sudb.    table1","sudb .table1","sudb . \r\n table1"
 * 最后取出的表名都是:"sudb.table1",便于命令和参数的过滤
 *
 * 当sql语句中有子查询时
 * 如:"select * from tab1,(select * from test) bb where (1=1);"
 * 调用函数时ch指向的位置为tab1的't'
 * 取出的结果:tab1,(select * from test)bb
 *
 * mod 20141224 带括号的不记录表名
 */
bool GetTableName(const char *ch, int len, char *param)
{
    if ((ch == NULL) || (len < 0) || (param == NULL)) {
        PRINT_ERR_HEAD
        print_err("get table name para err.sql[%s] len[%d]", ch, len);
        return false;
    }

    for (int k = 0; k < len; k++) {
        if ((ch[k] == ' ')
            || (ch[k] == '\r')
            || (ch[k] == '\n')
            || (ch[k] == '\t')) {//遇到这些字符时认为 表名已经取完了
            PRINT_DBG_HEAD
            print_dbg("get table name over.last character[%d] tabname[%s]", ch[k], param);
            break;
        } else if (isdigit(ch[k])
                   || isalpha(ch[k])
                   || (ch[k] == '.')
                   || (ch[k] == '_')
                   || (ch[k] == '$')
                   || (ch[k] == '@')
                   || (ch[k] == '*')
                   || (ch[k] == '[')
                   || (ch[k] == ']')) { //表名中合法的字符
            if (strlen(param) >= C_MAX_TABLENAMELEN - 1) {
                PRINT_DBG_HEAD
                print_dbg("tabname too long cut it.character[%d] tabname[%s]", ch[k], param);
                break;
            }
            strncat(param, ch + k, 1);
        } else if (ch[k] == '\"'
                   || ch[k] == '\''
                   || ch[k] == '`') {//取表名时忽略并继续查找的字符
        } else { //其他未明确的字符 按表名取完了处理
            PRINT_DBG_HEAD
            print_dbg("get table name over. find other character[%d] tabname[%s]", ch[k], param);
            break;
        }
    }
    return true;
}

/**
 * [CSINGLE::IsSYN 判断是否为SYN包]
 * @param  sdata [IP头开始的数据包]
 * @return       [是返回true]
 */
bool CSINGLE::IsSYN(unsigned char *sdata)
{
    if (_ipv4(sdata)) {
        return IS_IPV4_TCP_SYN(sdata);
    } else if (_ipv6(sdata)) {
        return IsTCP() && ((((TCP_HEADER *)(sdata + m_ipv6_offsetlen))->th_flags & TH_SYN) > 0);
    }
    return false;
}

/**
 * [CSINGLE::IsFIN 判断是否为FIN包]
 * @param  sdata [IP头开始的数据包]
 * @return       [是返回true]
 */
bool CSINGLE::IsFIN(unsigned char *sdata)
{
    if (_ipv4(sdata)) {
        return IS_IPV4_TCP_FIN(sdata);
    } else if (_ipv6(sdata)) {
        return IsTCP() && ((((TCP_HEADER *)(sdata + m_ipv6_offsetlen))->th_flags & TH_FIN) > 0);
    }
    return false;
}

/**
 * [CSINGLE::IsRST 判断是否为RST包]
 * @param  sdata [IP头开始的数据包]
 * @return       [是返回true]
 */
bool CSINGLE::IsRST(unsigned char *sdata)
{
    if (_ipv4(sdata)) {
        return IS_IPV4_TCP_RST(sdata);
    } else if (_ipv6(sdata)) {
        return IsTCP() && ((((TCP_HEADER *)(sdata + m_ipv6_offsetlen))->th_flags & TH_RST) > 0);
    }
    return false;
}

/**
 * [CSINGLE::FilterFileType 文件类型过滤]
 * @param  fname   [文件名]
 * @param  cherror [返回出错信息]
 * @return         [允许通过返回true]
 */
bool CSINGLE::FilterFileType(const char *fname, char *cherror)
{
    FileTypeMG &s1 = FileTypeMG::GetInstance();
    return s1.Filter(fname, cherror);
}

/*****************************************************************************
 * 将一个字符的Unicode(UCS-2和UCS-4)编码转换成UTF-8编码.
 *
 * 参数:
 *    unic     字符的Unicode编码值
 *    pOutput  指向输出的用于存储UTF8编码值的缓冲区的指针
 *    outsize  pOutput缓冲的大小
 *
 * 返回值:
 *    返回转换后的字符的UTF8编码所占的字节数, 如果出错则返回 0 .
 *
 * 注意:
 *     1. UTF8没有字节序问题, 但是Unicode有字节序要求;
 *        字节序分为大端(Big Endian)和小端(Little Endian)两种;
 *        在Intel处理器中采用小端法表示, 在此采用小端法表示. (低地址存低位)
 *     2. 请保证 pOutput 缓冲区有最少有 6 字节的空间大小!
 ****************************************************************************/
int CSINGLE::EncUnicodeToUTF8(unsigned long unic, unsigned char *pOutput, int outSize)
{
    if (pOutput == NULL) {
        PRINT_ERR_HEAD
        print_err("unicode to utf8 para null.");
        return 0;
    }

    if (outSize < 6) {
        PRINT_ERR_HEAD
        print_err("outSize too small[%d]", outSize);
        return 0;
    }

    if ( unic <= 0x0000007F ) {
        // * U-00000000 - U-0000007F:  0xxxxxxx
        *pOutput     = (unic & 0x7F);
        return 1;
    } else if ( unic >= 0x00000080 && unic <= 0x000007FF ) {
        // * U-00000080 - U-000007FF:  110xxxxx 10xxxxxx
        *(pOutput + 1) = (unic & 0x3F) | 0x80;
        *pOutput     = ((unic >> 6) & 0x1F) | 0xC0;
        return 2;
    } else if ( unic >= 0x00000800 && unic <= 0x0000FFFF ) {
        // * U-00000800 - U-0000FFFF:  1110xxxx 10xxxxxx 10xxxxxx
        *(pOutput + 2) = (unic & 0x3F) | 0x80;
        *(pOutput + 1) = ((unic >>  6) & 0x3F) | 0x80;
        *pOutput     = ((unic >> 12) & 0x0F) | 0xE0;
        return 3;
    } else if ( unic >= 0x00010000 && unic <= 0x001FFFFF ) {
        // * U-00010000 - U-001FFFFF:  11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
        *(pOutput + 3) = (unic & 0x3F) | 0x80;
        *(pOutput + 2) = ((unic >>  6) & 0x3F) | 0x80;
        *(pOutput + 1) = ((unic >> 12) & 0x3F) | 0x80;
        *pOutput     = ((unic >> 18) & 0x07) | 0xF0;
        return 4;
    } else if ( unic >= 0x00200000 && unic <= 0x03FFFFFF ) {
        // * U-00200000 - U-03FFFFFF:  111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
        *(pOutput + 4) = (unic & 0x3F) | 0x80;
        *(pOutput + 3) = ((unic >>  6) & 0x3F) | 0x80;
        *(pOutput + 2) = ((unic >> 12) & 0x3F) | 0x80;
        *(pOutput + 1) = ((unic >> 18) & 0x3F) | 0x80;
        *pOutput     = ((unic >> 24) & 0x03) | 0xF8;
        return 5;
    } else if ( unic >= 0x04000000 && unic <= 0x7FFFFFFF ) {
        // * U-04000000 - U-7FFFFFFF:  1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
        *(pOutput + 5) = (unic & 0x3F) | 0x80;
        *(pOutput + 4) = ((unic >>  6) & 0x3F) | 0x80;
        *(pOutput + 3) = ((unic >> 12) & 0x3F) | 0x80;
        *(pOutput + 2) = ((unic >> 18) & 0x3F) | 0x80;
        *(pOutput + 1) = ((unic >> 24) & 0x3F) | 0x80;
        *pOutput     = ((unic >> 30) & 0x01) | 0xFC;
        return 6;
    }

    return 0;
}

/**
 * [CSINGLE::RecordFilterLog 写内容过滤日志]
 * @param sdata  [IP头开始的数据包]
 * @param fname  [内容]
 * @param remark [备注]
 */
void CSINGLE::RecordFilterLog(unsigned char *sdata, const char *fname, const char *remark)
{
    if (!(g_iflog && m_recordlog)) { return; }
    char authname[AUTH_NAME_LEN] = {0};
    char tmpsip[IP_STR_LEN] = {0};
    char tmpdip[IP_STR_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    const char *tfname = fname;

    GetIPPortFromPack(sdata, tmpsip, tmpdip, tmpsport, tmpdport);

    if (g_workflag == WORK_MODE_PROXY) { //内部跳转IP需替换为代理IP
        if (MidIPToTIP(tmpdip) || MidIPToTIP(tmpsip)) {
        }
    }
    if (g_ckauth && (g_workflag != WORK_MODE_TRANSPARENT)) { //透明模式时不认证
        if ((GetAuthName(tmpsip, authname, sizeof(authname)) == 0)
            || (GetAuthName(tmpdip, authname, sizeof(authname)) == 0)) {
        }
    }

    if (tfname != NULL) {
        if (*tfname == '.') {
            tfname++;
        }
    }

    FilterLogPara *p = new FilterLogPara;
    if (p != NULL) {
        if (p->SetValues(authname, (tfname == NULL) ? "" : tfname , remark,
                         m_service->m_asservice, tmpsip, tmpdip, tmpsport, tmpdport)) {
            LogContainer &s1 = LogContainer::GetInstance();
            s1.PutPara(p);
        } else {
            PRINT_ERR_HEAD
            print_err("set values fail[authname %s, filename %s]", authname, fname);
            delete p;
        }
    }
    return;
}

/**
 * [CSINGLE::GetAttachInfo 从sdata中获取附件信息]
 * @param  sdata    [IP头开始的数据包]
 * @param  slen     [长度]
 * @param  para     [出参]
 * @param  parasize [出参缓冲区长度]
 * @return          [获取成功返回true]
 */
bool CSINGLE::GetAttachInfo(const char *sdata, int slen, char *para, int parasize)
{
    if ((sdata == NULL) || (slen < 0) || (para == NULL) || (parasize < 0)) {
        PRINT_ERR_HEAD
        print_err("get attach info para err.sdata[%s] slen[%d] parasize[%d]", sdata, slen, parasize);
        return false;
    }

    char attachstr[] = "Content-Disposition: attachment;";
    char fname[] = "filename=\"";
    char semicolon[] = "\"";
    int offset_attach = 0;
    int offset_fname = 0;
    int offset_semicolon = 0;
    char tmpfname[512] = {0};
    CMailCoder coder;

    //查找attachment串
    const char *pattach = m_common.FindString(sdata, slen, 0, attachstr, strlen(attachstr), offset_attach);
    if (pattach == NULL) {
        return false;
    }
    PRINT_DBG_HEAD
    print_dbg("datalen %d, offset attach %d", slen, offset_attach);

    //查找filename串
    const char *pfilename = m_common.FindString(sdata, slen, offset_attach + strlen(attachstr), fname,
                            strlen(fname), offset_fname);
    if (pfilename == NULL) {
        PRINT_ERR_HEAD
        print_err("attachment is find while filename not find");
        return false;
    }
    PRINT_DBG_HEAD
    print_dbg("datalen %d, offset filename %d", slen, offset_fname);

    //查找与filename配对的双引号
    const char *psemicolon = m_common.FindString(sdata, slen, offset_fname + strlen(fname), semicolon,
                             strlen(semicolon), offset_semicolon);
    if (psemicolon == NULL) {
        PRINT_ERR_HEAD
        print_err("attachment and filename find while semicolon not find");
        return false;
    }
    PRINT_DBG_HEAD
    print_dbg("datalen %d, offset semicolon %d", slen, offset_semicolon);

    char *pname_begin = (char *)(sdata + offset_fname + strlen(fname));
    char *pname_end = (char *)(sdata + offset_semicolon);
    int flen = pname_end - pname_begin;

    if ((flen > 0) && (flen < (int)sizeof(tmpfname))) {
        if ((flen > 13)
            && (memcmp(pname_begin, "=?GB2312?B?", 11) == 0)
            && (memcmp(pname_end - 2, "?=", 2) == 0)) {
            int ret = coder.base64_decode(pname_begin + 11, flen - 13, tmpfname);
            if (ret > 0) {
                memcpy(para, tmpfname, MIN(ret, parasize));
                PRINT_DBG_HEAD
                print_dbg("file name = [%s]", para);
                return true;
            } else {
                PRINT_ERR_HEAD
                print_err("base64 decode err %d", ret);
            }
        } else {
            memcpy(para, pname_begin, MIN(flen, parasize));
            PRINT_DBG_HEAD
            print_dbg("file name = [%s]", para);
            return true;
        }
    } else {
        PRINT_ERR_HEAD
        print_err("filename len err %d", flen);
    }
    return false;
}

/**
 * [CSINGLE::CheckSubject 检查邮件主题]
 * @param  sdata   [应用层数据]
 * @param  slen    [长度]
 * @param  cherror [错误信息  出参]
 * @return         [阻止返回false 放过返回true]
 */
bool CSINGLE::CheckSubject(const char *sdata, int slen, char *cherror)
{
    if (!g_ckkey) {
        return true;
    }

    PRINT_DBG_HEAD
    print_dbg("begin to check subject key");

    CCommon common;
    char chcmd[CMD_BUF_LEN] = {0};
    int ret = 0;
    const char *q = NULL;
    const char *p = strcasestr(sdata, "Subject:");
    if (p != NULL) {
        p += strlen("Subject:");
        while (*p == ' ') p++;
        if (strncasecmp(p, "=?GB2312?B?", strlen("=?GB2312?B?")) == 0) {
            p += strlen("=?GB2312?B?");
            q = strstr(p, "?=");
            if ((q != NULL) && (q < sdata + slen) && ((q - p) % 4 == 0)) {
                ret = common.base64_decode(p, q - p, (unsigned char *)chcmd, sizeof(chcmd));
                if (ret < 0) {
                    PRINT_ERR_HEAD
                    print_err("decode base64 fail");
                } else {
                    PRINT_DBG_HEAD
                    print_dbg("base64 decode result[%s]", chcmd);
                    if (!filter_key(chcmd, cherror)) {
                        return false;
                    }
                }
            } else {
                PRINT_DBG_HEAD
                print_dbg("not find end of subject line");
            }
        } else {
            PRINT_DBG_HEAD
            print_dbg("not find GB2312");
        }
    }
    return true;
}

/**
 * [CSINGLE::QueueNumEqual 判断当前服务对应的队列号 与 输入的号是否相等]
 * @param  queuenum [队列号]
 * @return          [相等返回true]
 */
bool CSINGLE::QueueNumEqual(int queuenum)
{
    if (m_service == NULL) {
        PRINT_ERR_HEAD
        print_err("service is null while compare queuenum");
        return false;
    }
    return (m_service->GetQueueNum() == queuenum);
}

/**
 * [CSINGLE::Match 判断输入的地址端口 是否匹配本应用]
 * @param  dport [端口]
 * @param  dip   [地址]
 * @param  sport [端口]
 * @param  sip   [地址]
 * @param  fromsrc [出参 是请求则置为1 是响应则置为0 只有在返回值为true的时候有意义]
 * @return      [匹配返回true]
 */
bool CSINGLE::Match(unsigned short dport, struct in_addr dip,
                    unsigned short sport, struct in_addr sip, int &fromsrc)
{
    for (int j = 0; j < (int)(m_ipportmap.size()); j++) {
        if (m_ipportmap[j].IfMatch(dport, dip)) {
            fromsrc = 1;
            return true;
        }

        if (m_ipportmap[j].IfMatch(sport, sip)) {
            fromsrc = 0;
            return true;
        }
    }
    return false;
}

/**
 * [CSINGLE::MatchIPv6 判断输入的地址端口 是否匹配本应用]
 * @param  dport [端口]
 * @param  dip   [地址]
 * @param  sport [端口]
 * @param  sip   [地址]
 * @param  fromsrc [出参 是请求则置为1 是响应则置为0 只有在返回值为true的时候有意义]
 * @return      [匹配返回true]
 */
bool CSINGLE::MatchIPv6(unsigned short dport, struct in6_addr dip,
                        unsigned short sport, struct in6_addr sip, int &fromsrc)
{
    for (int j = 0; j < (int)(m_ipportmap.size()); j++) {
        if (m_ipportmap[j].IfMatchIPv6(dport, dip)) {
            fromsrc = 1;
            return true;
        }

        if (m_ipportmap[j].IfMatchIPv6(sport, sip)) {
            fromsrc = 0;
            return true;
        }
    }
    return false;
}

/**
 * [CSINGLE::SetService 设置服务模块]
 * @param pserv [服务结构指针]
 */
void CSINGLE::SetService(CSERVICECONF *pserv)
{
    if (pserv == NULL) {
        PRINT_ERR_HEAD
        print_err("para null while set service");
    } else {
        m_service = pserv;
    }
}

/**
 * [CSINGLE::GetService 获取服务模块]
 * @return  [服务结构指针]
 */
CSERVICECONF *CSINGLE::GetService(void)
{
    return m_service;
}

/**
 * [CSINGLE::AddToMap 把一个地址端口映射 加到成员变量中]
 * @param val [地址端口映射对象的引用]
 */
void CSINGLE::AddToMap(IpPortMap &val)
{
    if (val.AppNameEqual(m_service->m_name)) {
        m_ipportmap.push_back(val);
    }
}

/**
 * [filter_key 过滤关键字]
 * @param  chcmd   [待过滤的内容]
 * @param  cherror [出错信息 出参]
 * @return         [发现关键字返回false]
 */
bool filter_key(const char *chcmd, char *cherror)
{
    for (int i = 0; i < g_vec_FilterKey.size(); ++i) {
        if ((strstr(chcmd, g_vec_FilterKey[i].c_str()) != NULL)
            || (strstr(chcmd, g_vec_FilterKeyUTF8[i].c_str()) != NULL)) {

            strcpy(cherror, g_vec_FilterKey[i].c_str());
            PRINT_ERR_HEAD
            print_err("find key word[%s]", cherror);
            return false;
        }
    }
    return true;
}
