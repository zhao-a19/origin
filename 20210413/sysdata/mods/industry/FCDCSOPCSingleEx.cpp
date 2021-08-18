/*******************************************************************************************
*文件:  FCDCSOPCSingleEx.cpp
*描述:  OPC模块 扩展文件
*作者:  王君雷
*日期:  2018-02-28
*修改:
*         添加函数getport                                           ------> 2018-02-28
*         根据五元组追踪每一个连接,解决读写控制不住的问题,日志易读  ------> 2018-03-30
*         使用IPTABLES宏                                            ------> 2018-08-13
*         动态端口匹配时使用结构                                    ------> 2018-12-28
*         把printf输出改为zlog                                      ------> 2019-09-10
*******************************************************************************************/
#include "FCDCSOPCSingle.h"
#include "FCPeerExecuteCMD.h"
#include "dcom.h"
#include "opc-da.h"
#include "debugout.h"
#include "network.h"

/**
 * [CDCSOPCSINGLE::getport 查找端口信息，UNICODE编码]
 * @param  data [数据指针]
 * @param  len  [数据大小]
 * @return      [端口号，0失败]
 */
uint16 CDCSOPCSINGLE::getport(unsigned char *data, int len)
{
    if (data == NULL) { return 0; }

    uint16 port = 0;
    while (len >= 2) {
        if ((*data == '[') && (*(data + 1) == 0)) {  //开始'['
            data += 2;
            len -= 2;
            port = 0;

            while (len >= 2) {
                if ((*data >= '0') && (*data <= '9') && (*(data + 1) == 0)) {
                    port = port * 10 + (*data - '0');
                    data += 2;
                    len -= 2;
                    continue;
                } else if ((*data == ']') && (*(data + 1) == 0)) {   //结束']'
                    data += 2;
                    len -= 2;
                    if ((len >= 2) && (*data == 0) && (*(data + 1) == 0)) {
                        //匹配结束退出
                        return port;
                    }
                }
                break;
            }

        } else if (*(data + 1) != '[') {
            data += 2;
            len -= 2;
        } else {
            data += 1;
            len -= 1;
        }
    }

    return 0;
}

/**
 * [CDCSOPCSINGLE::GetStaticHandle 获取静态DCERPC句柄]
 * @param  sdata [IP数据包]
 * @param  slen  [IP数据包长度]
 * @return       [成功返回DCERPCState类型指针，失败返回NULL]
 */
#define _addrequal(a1, a2) ((memcmp(&(a1), &(a2), sizeof(DATANETADDR)) == 0) || \
                        ((a1.srcaddr == a2.dstaddr) && (a1.srcport == a2.dstport) && \
                        (a1.dstaddr == a2.srcaddr) && (a1.dstport == a2.srcport)))
#define CLEAR_FLOW(flow) \
    { \
        DCERPCCleanup(&(flow).dcerpchandle.dcerpc); \
        memset(&(flow), 0, sizeof(flow)); \
        DCERPCInit(&(flow).dcerpchandle.dcerpc); \
    }
DCERPCState *CDCSOPCSINGLE::GetStaticHandle(unsigned char *sdata, int slen)
{
    DCERPCState *p = NULL;
    DATANETADDR addr;
    int i, j = -1;

    BIN2IP(addr.srcaddr, &(((PIP_HEADER)sdata)->ip_src));
    BIN2IP(addr.dstaddr, &(((PIP_HEADER)sdata)->ip_dst));
    addr.srcport = ntohs((_tcpipdata(sdata))->th_sport);
    addr.dstport = ntohs((_tcpipdata(sdata))->th_dport);

    //是否为已建连接
    for (i = 0; i < MAX_OPC_STATIC_SIZE; i++) {
        if (_addrequal(m_staticflow[i].addr, addr)) {
            m_staticflow[i].timestamp = time(NULL);
            p = &(m_staticflow[i].dcerpchandle);
            break;
        }

        if ((m_staticflow[i].timestamp != 0)
            && (time(NULL) - m_staticflow[i].timestamp > OPC_TIME_OUT_SECOND)) {

            CLEAR_FLOW(m_staticflow[i]);
            if (j == -1) { j = i; }
        } else if (m_staticflow[i].timestamp == 0) {
            if (j == -1) { j = i; }
        }
    }
    if (p == NULL) {
        //有可用的
        if (j > -1) {
            memcpy(&(m_staticflow[j].addr), &addr, sizeof(addr));
            m_staticflow[j].timestamp = time(NULL);
            p = &(m_staticflow[j].dcerpchandle);
        } else {
            PRINT_ERR_HEAD
            print_err("reach max support num %d", MAX_OPC_STATIC_SIZE);
        }
    }
    return p;
}

/**
 * [CDCSOPCSINGLE::DoMsgDY 处理动态连接信息]
 * @param  sdata     [IP数据包]
 * @param  slen      [IP数据包长度]
 * @param  cherror   [用于返回出错信息]
 * @param  pktchange [数据包是否被改变了 暂未使用]
 * @param  index     [动态连接对应的flow下标]
 * @return           [true表示允许通过]
 */
bool CDCSOPCSINGLE::DoMsgDY(unsigned char *sdata, int slen, char *cherror, int *pktchange, int index)
{
    if ((index < 0) || (index >= MAX_OPC_DYNAMIC_SIZE)) {
        PRINT_ERR_HEAD
        print_err("index error %d", index);
        return false;
    }
    return DoSrcMsg(sdata, slen, cherror, &(m_dynamicflow[index].dcerpchandle));
}

/**
 * [CDCSOPCSINGLE::getport 获取动态端口]
 * @param  item [接口对象指针]
 * @return      [端口号，0失败]
 */
uint16 CDCSOPCSINGLE::getport(DCERPCUuidEntry *item, DCERPCState *phandle)
{
    if (item == TAILQ_END(0)) { return 0; }

    //ISystemActivator:RemoteCreateInstance
    static const uint8 syncportif [16] = uuid_l("000001a0-0000-0000-c000-000000000046");    //接口定义，客户端
    //IID_IObjectExporter:ResolveOxid2
    static const uint8 syncportif_1 [16] = uuid_l("99fcfec4-5260-101b-bbcb-00aa0021347a");    //接口定义, 服务端

    PRINT_DBG_HEAD
    print_dbg("item %u = %u, %s:%u", item->ctxid, _DCEMEM_REQ_(*phandle, ctxid), m_uuidstr,
              _DCEMEM_REQ_(*phandle, opnum));

    //对应上下文，方法，接口
    if ((item->ctxid == _DCEMEM_REQ_(*phandle, ctxid))
        && (_DCEMEM_REQ_(*phandle, opnum) == 4) //方法定义
        && (uuidequal(item->uuid, syncportif) || uuidequal(item->uuid, syncportif_1))) {

        return getport(_DCEMEM_RSP_(*phandle, stub_data_buffer), _DCEMEM_RSP_(*phandle, stub_data_buffer_len));
    }
    return 0;
}

/**
 * [CDCSOPCSINGLE::setiptables 根据输入参数 添加动态iptables]
 * @param paddr [地址结构指针]
 * @param badd  [true表示添加 false表示删除]
 */
void CDCSOPCSINGLE::setiptables(PDATANETADDR paddr, bool badd)
{
    CCommon common;
    char ipstr[2][40] = {{0}};
    char oper = badd ? 'I' : 'D';
    char chcmd[200] = {0};

    if (paddr != NULL) {
        common.ip2str(paddr->srcaddr, ipstr[0]);
        common.ip2str(paddr->dstaddr, ipstr[1]);

        sprintf(chcmd, "%s -%c FORWARD -s %s -d %s -p tcp --dport %d -j ACCEPT",
                IPTABLES, oper, ipstr[0], ipstr[1], paddr->dstport);
        PeerExecuteCMD(chcmd);
        PRINT_DBG_HEAD
        print_dbg("peer[%s]", chcmd);

        sprintf(chcmd, "%s -%c FORWARD -d %s -s %s -p tcp --sport %d -j ACCEPT",
                IPTABLES, oper, ipstr[0], ipstr[1], paddr->dstport);
        PeerExecuteCMD(chcmd);
        PRINT_DBG_HEAD
        print_dbg("peer[%s]", chcmd);

        sprintf(chcmd, "%s -%c FORWARD -s %s -d %s -p tcp --dport %d -j NFQUEUE --queue-num %d",
                IPTABLES, oper, ipstr[0], ipstr[1], paddr->dstport, m_service->GetQueueNum());
        system(chcmd);
        PRINT_DBG_HEAD
        print_dbg("self[%s]", chcmd);

        sprintf(chcmd, "%s -%c FORWARD -d %s -s %s -p tcp --sport %d -j NFQUEUE --queue-num %d",
                IPTABLES, oper, ipstr[0], ipstr[1], paddr->dstport, m_service->GetQueueNum());
        system(chcmd);
        PRINT_DBG_HEAD
        print_dbg("self[%s]", chcmd);
    }
}

/**
 * [CDCSOPCSINGLE::CmdMatch 判断当前的命令参数 是否匹配上命令规则]
 * @param  pcmd [用户定制的一条命令规则的指针]
 * @return      [匹配上返回true]
 */
#define str_equal(s1,s2) (strcasecmp((s1), (s2)) == 0)
bool CDCSOPCSINGLE::CmdMatch(const CCMDCONF *pcmd)
{
    if (((m_rw == PROTO_READ) && (strcasecmp("allread", pcmd->m_cmd) == 0))
        || ((m_rw == PROTO_WRITE) && (strcasecmp("allwrite", pcmd->m_cmd) == 0))) {

        return true;
    }

    if (str_equal(m_chcmd, pcmd->m_cmd) || str_equal(m_uuidstr, pcmd->m_cmd)) {
        if (str_equal(pcmd->m_parameter, "")
            || str_equal(pcmd->m_parameter, m_chpara)
            || (atoi(pcmd->m_parameter) == m_opnum)) {
            return true;
        }
    }

    return false;
}
