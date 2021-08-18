#include "FCMMS.h"

#define PKTP_HEADER_SIZE 4
#define COTP_HEADER_SIZE 3
//#define SESSION_HEADER_SIZE 4
//#define MMS_PDU_LEN 4096
#define strempty(s) (strcmp(s, "") == 0)
extern bool g_debug;

/**
 * [传输层协议处理：获取 TPKT 数据包长度
 * @param  pkt     [数据包]
 * @param  pktlen  [数据包长度]
 * @param  protolen[根据协议解出的长度]
 * @return       [获取成功返回true]
 */
static bool read_pktp_len(const unsigned char *pkt, int pktlen, unsigned int &protolen)
{
    if (pktlen < PKTP_HEADER_SIZE)
    {
        printf("%s[%d]pktlen too short[%d], PKTP_HEADER_SIZE[%d]!\n",
               __FUNCTION__, __LINE__, pktlen, PKTP_HEADER_SIZE);
        return false;
    }
    else
    {
        protolen = pkt[2] * 256 + pkt[3]; //大端数据
        return true;
    }
}

/**
 * [传输层协议处理：判断数据是否收完, 借鉴于库函数CotpConnection_readToTpktBuffer]
 * @param  pkt   [数据包]
 * @param  len   [数据大小]
 * @return       [如果此帧数据完整收完，则返回TPKT_PACKET_COMPLETE；如果发生了拼包或者拆包，则不解析次包]
 */
static TpktState read_pktp(const unsigned char *pkt, unsigned int len)
{
    unsigned int data_len = 0;

    read_pktp_len(pkt, len, data_len); //大端数据

    //拼包的情况在外面已经处理了
    /*发生了拆包*/
    if (data_len > len)
    {
        printf("%s[%d]protocal len:%d, actully len:%d\n",
               __FUNCTION__, __LINE__, data_len, len);
        return TPKT_WAITING;
    }
    return TPKT_PACKET_COMPLETE; /*收完了所有数据*/
}

/**
 * [read_cotp: 传输层协议处理，借鉴于库函数 CotpConnection_parseIncomingMessage]
 * @param  buffer   [数据包]
 * @param  len      [数据大小]
 * @return          [返回连接类型：连接或数据]
 */
static CotpIndication read_cotp(const unsigned char *buffer, unsigned int len)
{
    unsigned char flowControl;
    switch (buffer[1])
    {
    case 0xe0:
        return COTP_CONNECT_INDICATION;
    case 0xd0:
        return COTP_CONNECT_INDICATION;
    case 0xf0:
        flowControl = buffer[2];
        if (flowControl & 0x80)
            return COTP_DATA_INDICATION;
        else
            return COTP_MORE_FRAGMENTS_FOLLOW;
    default:
        return COTP_ERROR;
    }

    return COTP_ERROR;
}

/**
 * [parseAccept 会话层Accept连接参数处理函数, 借鉴于库函数 parseAcceptParameters]
 * @param  buffer   [数据包]
 * @param  parameterLength   [数据大小]
 * @return        [成功返回下一层数据偏移地址；失败则返回-1]
 */
static int32_t parseAccept(const uint8_t *buffer, uint32_t parameterLength)
{
    uint8_t pi;
    uint8_t param_len;
    uint8_t param_val;
    uint8_t hasProtocolOptions = 0;
    uint8_t hasProtocolVersion = 0;
    int startOffset = 0;
    int offset = startOffset;
    int maxOffset = offset + parameterLength;

    while (offset < maxOffset)
    {
        pi = buffer[offset++];
        param_len = buffer[offset++];

        switch (pi)
        {
        case 19: /* Protocol options */
            if (param_len != 1)
                return -1;
            offset++;
            hasProtocolOptions = 1;
            break;
        case 21: /* TSDU Maximum Size */
            offset += 4;
            break;
        case 22: /* Version Number */
            param_val = buffer[offset++];
            if (param_val != 2)
                return -1;
            hasProtocolVersion = 1;
            break;
        case 23: /* Initial Serial Number */
            offset += param_len;
            break;
        case 26: /* Token Setting Item */
            param_val = buffer[offset++];
            break;
        case 55: /* Second Initial Serial Number */
            offset += param_len;
            break;
        case 56: /* Upper Limit Serial Number */
            offset += param_len;
            break;
        case 57: /* Large Initial Serial Number */
            offset += param_len;
            break;
        case 58: /* Large Second Initial Serial Number */
            offset += param_len;
            break;
        default:
            break;
        }
    }

    if (hasProtocolOptions && hasProtocolVersion)
        return offset - startOffset;
    else
        return -1;
}

/**
 * [parseSessionPara 解析会话层协议参数, 借鉴于库函数 parseSessionHeaderParameters]
 * @param  buffer   [数据包]
 * @param  parametersOctets   [数据大小]
 * @return        [成功则返回下一层数据便宜量；失败则返回0]
 */
static unsigned int parseSessionPara(const unsigned char *buffer, unsigned int parametersOctets)
{
    unsigned int offset = 0;
    unsigned char pgi;
    unsigned char parameterLength;
    int32_t connectAcceptLen;

    while (offset < parametersOctets)
    {
        pgi = buffer[offset++];
        parameterLength = buffer[offset++];

        switch (pgi)
        {
        case 1: /* Connection Identifier */
            offset += parameterLength;
            break;
        case 5: /* Connection/Accept Item */
            connectAcceptLen = parseAccept(buffer + offset, parameterLength);
            if (connectAcceptLen == -1)
                return 0;

            offset += connectAcceptLen;
            break;
        case 17: /* Transport disconnect */
            offset += parameterLength;
            break;
        case 20: /* Session User Requirements */
            if (parameterLength != 2)
                return 0;
            offset += parameterLength;
            break;
        case 25: /* Enclosure item */
            offset += parameterLength;
            break;
        case 49:
            offset += parameterLength;
            break;
        case 51: /* Calling Session Selector */
            if (parameterLength > 16)
                return 0;
            offset += parameterLength;
            break;
        case 52: /* Called Session Selector */
            if (parameterLength > 16)
                return 0;
            offset += parameterLength;
            break;
        case 60: /* Data Overflow */
            offset += parameterLength;
            break;
        case 193: /* User Data */
            /* here we should return - the remaining data is for upper layers ! */
            return offset;
        case 194: /* Extended User Data */
            offset += parameterLength;
            break;
        default:
            offset += parameterLength;
            break;
        }
    }

    return 0;
}

/**
 * [read_session 解析session头，借鉴于库函数 IsoSession_parseMessage]
 * @param  buffer   [数据包]
 * @param  len      [数据大小]
 * @param  offset   [返回下一层协议数据的偏移量]
 * @return          [返回会话层协议类型]
 */
static IsoSessionIndication read_session(const unsigned char *buffer, unsigned int len, unsigned int *offset)
{

    unsigned char id = buffer[0];
    unsigned char length = buffer[1];
    unsigned char off = 0;

    switch (id)
    {
    case 13:
    case 14:
        off = parseSessionPara(buffer + 2, length);
        if (off > 0)
        {
            *offset = off + 2;
            return SESSION_CONNECT;
        }
        return SESSION_ERROR;
    case 1:
        if ((length == 0) && (buffer[2] == 1) && (buffer[3] == 0))
        {
            *offset = 4;
            return SESSION_DATA;
        }
        return SESSION_ERROR;
    case 8:
        return SESSION_NOT_FINISHED;
    case 9:
        return SESSION_FINISH;
    case 10:
        return SESSION_DISCONNECT;
    case 25:
        return SESSION_ABORT;
    default:
        return SESSION_ERROR;
    }

    return SESSION_ERROR;
}

/**
 * [authenticator 表示层需要用到的授权管理函数]
 * @param  n1   [没有意义]
 * @param  n2   [没有意义]
 * @param  n3   [没有意义]
 * @return      [表示层需要使用授权信息判断连接的合法性，但mms解析程序不需要参与此判断
 *              ，直接认为成功；如果不接管此函数，则需要mms解析程序维护整个会话过程。]
 */
static bool authenticator(void *n1, void *n2, void *n3)
{
    return true;
}

/**
 * [pres_des 从表示层数据中取出应用层数据]
 * @param  Buffer       [数据包]
 * @param  maxBufPos    [数据大小]
 * @param  sIndication  [会话层消息类型：连接或者数据]
 * @return              [成功时返回应用层数据；失败则返回NULL]
 */
static const unsigned char *pres_des(const unsigned char *Buffer, unsigned int maxBufPos,
                                     IsoSessionIndication sIndication)
{
    unsigned char tag;
    int32_t len = 0;
    unsigned int bufPos = 0, modeSelector;
    unsigned char *buffer = (unsigned char *)Buffer;

    IsoPresentation self;
    AcseConnection acseConnection;
    AcseIndication aIndication;
    acseConnection.authenticator = (AcseAuthenticator) authenticator;

    if (sIndication == SESSION_CONNECT)
    {
        if (buffer[bufPos++] != 0x31) // not CP type
            return NULL;
        bufPos = BerDecoder_decodeLength(buffer, &len, bufPos, maxBufPos);
        if (bufPos < 0)
            return NULL;

        while (bufPos < maxBufPos)
        {
            tag = buffer[bufPos++];
            bufPos = BerDecoder_decodeLength(buffer, &len, bufPos, maxBufPos);
            if (bufPos < 0)
                return NULL;
            switch (tag)
            {
            case 0xA0:
                if (buffer[bufPos++] != 0x80)
                    return NULL;
                bufPos = BerDecoder_decodeLength(buffer, &len, bufPos, maxBufPos);
                modeSelector = BerDecoder_decodeUint32(buffer, len, bufPos);
                bufPos += len;
                break;
            case 0xA2:
                bufPos = parseNormalModeParameters(&self, buffer, len, bufPos);
                if (bufPos < 0)
                    return NULL;
                break;
            default:
                bufPos += len;
                break;
            }
        }

        aIndication = AcseConnection_parseMessage(&acseConnection, &self.nextPayload);
        if (aIndication != ACSE_ASSOCIATE)
            return NULL;
        return acseConnection.userDataBuffer;
    }
    else if (sIndication == SESSION_DATA)
    {
        if (buffer[bufPos++] != 0x61)
            return NULL;
        bufPos = BerDecoder_decodeLength(buffer, &len, bufPos, maxBufPos);
        if (buffer[bufPos++] != 0x30)
            return NULL;
        bufPos = BerDecoder_decodeLength(buffer, &len, bufPos, maxBufPos);
        if (buffer[bufPos++] != 0x02)
            return NULL;
        if (buffer[bufPos++] != 0x01)
            return NULL;
        bufPos++;
        if (buffer[bufPos++] != 0xa0)
            return NULL;

        int userDataLength;
        bufPos = BerDecoder_decodeLength(buffer, &userDataLength, bufPos, maxBufPos);
        return buffer + bufPos;
    }

    return NULL;
}

/**
 * [mms_des  解析mms报文]
 * @param  pkt   [数据包]
 * @param  len   [数据大小]
 * @param  buf   [用于保存解析完后的xml格式的mms报文缓冲区，数据格式为4B size + 4B len + mms报文]
 * @param  buf_len [缓存区大小]
 * @return        [返回指向mms报文缓存区的指针, 即buf+8的地址；返回NULL表示解析失败]
 */
static unsigned char *mms_des(const unsigned char *pkt, unsigned int len, unsigned char *buf, int buf_len)
{
    unsigned int offset = 0;
    MmsPdu_t *mmspdu = 0;

    TpktState tpktState = read_pktp(pkt, len);
    if (tpktState != TPKT_PACKET_COMPLETE)
    {
        printf("%s[%d]recv un-complate tpkt package, tpktstate = %d\n",
               __FUNCTION__, __LINE__, tpktState);
        return NULL;
    }

    CotpIndication cotpIndication = read_cotp(pkt + PKTP_HEADER_SIZE, len - PKTP_HEADER_SIZE);
    if (cotpIndication != COTP_DATA_INDICATION)
    {
        printf("%s[%d]recv un-complate cotp package, cotpIndication = %d\n",
               __FUNCTION__, __LINE__, cotpIndication);
        return NULL;
    }

    IsoSessionIndication sIndication = read_session(pkt + PKTP_HEADER_SIZE + COTP_HEADER_SIZE,
                                       len - PKTP_HEADER_SIZE - COTP_HEADER_SIZE, &offset);
    if (sIndication != SESSION_DATA && sIndication != SESSION_CONNECT)
    {
        printf("%s[%d]recv un-complate session package, sIndication = %d\n",
               __FUNCTION__, __LINE__, sIndication);
        return NULL;
    }

    const unsigned char *mms_data = pres_des(pkt + PKTP_HEADER_SIZE + COTP_HEADER_SIZE + offset,
                                    len - PKTP_HEADER_SIZE - COTP_HEADER_SIZE - offset, sIndication);
    if (mms_data == NULL)
    {
        printf("%s[%d]recv un-complate presentation package\n",
               __FUNCTION__, __LINE__);
        return NULL;
    }

    asn_dec_rval_t rval;
    rval = ber_decode(NULL, &asn_DEF_MmsPdu, (void **)&mmspdu, mms_data, CONFIG_MMS_MAXIMUM_PDU_SIZE);
    if (rval.code != RC_OK)
    {
        asn_DEF_MmsPdu.free_struct(&asn_DEF_MmsPdu, mmspdu, 0);
        printf("%s[%d]ber_docode failed.\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    unsigned char *p = xer_sprint(buf, buf_len, &asn_DEF_MmsPdu, mmspdu);
    //xer_fprint(stderr, &asn_DEF_MmsPdu, mmspdu);
    asn_DEF_MmsPdu.free_struct(&asn_DEF_MmsPdu, mmspdu, 0);
    return p;
}

//--------------------------------------------------------
CMMS::CMMS()
{
    memset(&m_cmdrule, 0, sizeof(m_cmdrule));
    memset(m_chpara, 0, sizeof(m_chpara));
}

CMMS::~CMMS()
{
}

bool CMMS::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1)
    {
        return DoSrcMsg(sdata, slen, cherror);
    }
    else
    {
        return DoDstMsg(sdata, slen, cherror);
    }
}

bool CMMS::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    if (datalen <= 0)
    {
        return true;
    }

    //printf("\n");

    Memory_reset(); //首次调用MALLOC前必须调用这个初始化函数
    unsigned char *mmspdustr = (unsigned char *)MALLOC(CONFIG_MMS_MAXIMUM_PDU_SIZE);
    unsigned char *pstr = NULL;
    int offset = 0;
    unsigned int tpkt_len;
    bool bret = true;
    CMDPARAM cmdrule;

    memset(&m_cmdrule, 0, sizeof(m_cmdrule));
    do
    {
        tpkt_len = 0;
        if (read_pktp_len(sdata + hdlen + offset, slen - hdlen - offset, tpkt_len))
        {
            if ((pstr = mms_des(sdata + hdlen + offset, slen - hdlen - offset,
                                mmspdustr, CONFIG_MMS_MAXIMUM_PDU_SIZE)) == NULL)
            {
                //解析报文失败
                printf("%s[%d]mms_des fail! size = %d\n", __FUNCTION__, __LINE__, slen - hdlen - offset);
                break;
            }
            else
            {
                //printf("%s[%d]after des[%d][%s]\n", __FUNCTION__, __LINE__, strlen((const char *)pstr), pstr);

                //从xml中提取要过滤的信息
                memset(&cmdrule, 0, sizeof(cmdrule));
                if (xmltorule(pstr, cmdrule))
                {
                    if (FilterCmd(cmdrule))
                    {
                        //只要有允许通过的命令，就放过，不再过滤后续命令
                        MakeParaString(cmdrule);
                        RecordCallLog(sdata, cmdrule.request, m_chpara, cherror, true);
                        break;
                    }
                    else
                    {
                        //过滤失败，保存到成员变量，供写日志使用
                        memcpy(&m_cmdrule, &cmdrule, sizeof(cmdrule));
                    }
                }
                else
                {
                    //提取失败
                    printf("%s[%d]xmltorule fail!\n", __FUNCTION__, __LINE__);
                }
                offset += tpkt_len;
                if (offset >= slen - hdlen)
                {
                    if (!strempty(m_cmdrule.request))
                    {
                        //数据包已经分析到结尾，并且上次过滤时有禁止通过的命令
                        MakeParaString(m_cmdrule);
                        strcpy(cherror, MMS_PERM_FORBID);
                        RecordCallLog(sdata, m_cmdrule.request, m_chpara, cherror, false);
                        bret = false;
                    }
                    break;
                }
            }
        }
        else
        {
            printf("%s[%d]read_pktp_len fail!\n", __FUNCTION__, __LINE__);
            break;
        }
    }
    while (1);

    FREEMEM(mmspdustr);
    return bret;
}

bool CMMS::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/*******************************************************************************************
*功  能:  xml中提取出要过滤的命令和参数信息 保存到参数cmdrule
*参  数:
*         pstr      MMS解码之后的xml格式的信息
*         cmdrule   从xml中提取出与过滤有关的信息，保存到该变量
*返回值:  true  提取成功 (至少提取出request才认为成功)
*         false 提取失败
*pstr示例:<MmsPdu><confirmedRequestPdu><invokeID>5</invokeID><confirmedServiceRequest>
*         <getVariableAccessAttributes><name><domainspecific><domainId>IEDRelay1</domainId>
*         <itemId>LLN0$BR$brcbST</itemId></domainspecific></name></getVariableAccessAttributes>
*         </confirmedServiceRequest></confirmedRequestPdu></MmsPdu>
*******************************************************************************************/
bool CMMS::xmltorule(unsigned char *pstr, CMDPARAM &cmdrule)
{
    char request[] = "<confirmedServiceRequest>";
    char domainid[] = "<domainId>";
    char domainid_end[] = "</domainId>";
    char itemid[] = "<itemId>";
    char itemid_end[] = "</itemId>";
    int len = 0;

    const char *ptr_req = strstr((const char *)pstr, request);
    if (ptr_req != NULL)
    {
        const char *ptrl = strchr(ptr_req + strlen(request), '<');
        const char *ptrr = strchr(ptr_req + strlen(request), '>');
        if ((ptrl != NULL) && (ptrr != NULL) && (ptrr - ptrl - 1 > 0))
        {
            //提取出request
            len = (ptrr - ptrl - 1) < ((int)sizeof(cmdrule.request) - 1) ?
                  (ptrr - ptrl - 1) : ((int)sizeof(cmdrule.request) - 1);
            memcpy(&cmdrule.request, ptrl + 1, len);

            const char *ptr_dom = strstr(ptrr, domainid);
            const char *ptr_dom_end = strstr(ptrr, domainid_end);
            if ((ptr_dom != NULL) && (ptr_dom_end != NULL)
                    && (ptr_dom_end - ptr_dom - strlen(domainid) > 0))
            {
                //提取domain
                len = ptr_dom_end - ptr_dom - strlen(domainid);
                len = len < ((int)sizeof(cmdrule.domainid) - 1) ? len : ((int)sizeof(cmdrule.domainid) - 1);
                memcpy(&cmdrule.domainid, ptr_dom + strlen(domainid), len);

                const char *ptr_item = strstr(ptr_dom_end, itemid);
                const char *ptr_item_end = strstr(ptr_dom_end, itemid_end);
                if ((ptr_item != NULL) && (ptr_item_end != NULL)
                        && (ptr_item_end - ptr_item - strlen(itemid) > 0))
                {
                    //提取itemid
                    len = ptr_item_end - ptr_item - strlen(itemid);
                    len = len < ((int)sizeof(cmdrule.itemid) - 1) ? len : ((int)sizeof(cmdrule.itemid) - 1);
                    memcpy(&cmdrule.itemid, ptr_item + strlen(itemid), len);
                }
            }

            if (g_debug)
            {
                printf("%s[%d]request:[%s], domainid:[%s], itemid:[%s]\n",
                       __FUNCTION__, __LINE__, cmdrule.request, cmdrule.domainid, cmdrule.itemid);
            }
            return true;
        }
        else
        {
            printf("%s[%d]get request fail!\n", __FUNCTION__, __LINE__);
        }
    }
    return false;
}

/*******************************************************************************************
*功  能:  过滤命令和参数信息
*参  数:
*         cmdrule   从应用数据中解析出的命令参数信息
*返回值:  true  放过
*         false 阻止
*******************************************************************************************/
bool CMMS::FilterCmd(CMDPARAM &cmdrule)
{
    bool result = m_service->m_IfExec;

    for (int i = 0; i < m_service->m_cmdnum; i++)
    {
        //匹配命令
        if (strcmp(m_service->m_cmd[i]->m_cmd, cmdrule.request) == 0)
        {
            //匹配domainid
            if (strempty(m_service->m_cmd[i]->m_parameter)
                    || (strcmp(m_service->m_cmd[i]->m_parameter, cmdrule.domainid) == 0))
            {
                //匹配itemid
                if (strempty(m_service->m_cmd[i]->m_sign)
                        || (strcmp(m_service->m_cmd[i]->m_sign, cmdrule.itemid) == 0))
                {
                    result = m_service->m_cmd[i]->m_action;
                    break;
                }
            }
        }
    }

    return result;
}

/*******************************************************************************************
*功  能:  组参数字符串 写日志时使用
*参  数:
*         cmdrule   从应用数据中解析出的命令参数信息
*返回值:  void
*******************************************************************************************/
void CMMS::MakeParaString(CMDPARAM &cmdrule)
{
    if (strempty(cmdrule.domainid))
    {
        m_chpara[0] = '\0';
    }
    else
    {
        if (strempty(cmdrule.itemid))
        {
            sprintf(m_chpara, "%s", cmdrule.domainid);
        }
        else
        {
            sprintf(m_chpara, "%s[%s]", cmdrule.domainid, cmdrule.itemid);
        }
    }

    return;
}
