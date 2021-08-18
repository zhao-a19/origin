/*******************************************************************************************
*文件:  FCDCSOPCSingle.cpp
*描述:  OPC模块
*作者:  王君雷
*日期:  2016-03
*修改:
*         查找动态端口算法有误，改用getport函数                     ------> 2018-02-28
*         根据五元组追踪每一个连接,解决读写控制不住的问题,日志易读  ------> 2018-03-30
*         加入zlog记录日志                                          ------> 2018-04-09
*         动态端口匹配时使用结构                                    ------> 2018-12-28
*         把printf输出改为zlog                                      ------> 2019-09-10
*******************************************************************************************/
#include "FCDCSOPCSingle.h"
#include "FCPeerExecuteCMD.h"
#include "dcom.h"
#include "opc-da.h"
#include "common.h"
#include "debugout.h"
#include "network.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

CDCSOPCSINGLE::CDCSOPCSINGLE()
{
    memset(&m_dynamicflow, 0, sizeof(m_dynamicflow));
    memset(&m_staticflow, 0, sizeof(m_staticflow));
    for (int i = 0; i < MAX_OPC_DYNAMIC_SIZE; i++) {
        DCERPCInit(&(m_dynamicflow[i].dcerpchandle.dcerpc));
    }

    for (int i = 0; i < MAX_OPC_STATIC_SIZE; i++) {
        DCERPCInit(&(m_staticflow[i].dcerpchandle.dcerpc));
    }

    memset(m_uuid, 0, sizeof(m_uuid));
    memset(m_uuidstr, 0, sizeof(m_uuidstr));
    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));
    m_rw = PROTO_RWNULL;
    m_bsys = false;
    m_opnum = 0;
}

CDCSOPCSINGLE::~CDCSOPCSINGLE()
{
}

bool CDCSOPCSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    return DoSrcMsg(sdata, slen, cherror, GetStaticHandle(sdata, slen));
}

/**
 * [CDCSOPCSINGLE::DoSrcMsg 处理IP数据包]
 * @param  sdata   [IP数据包]
 * @param  slen    [IP数据包长度]
 * @param  cherror [出错信息]
 * @param  phandle [DCERPCState句柄]
 * @return         [允许通过返回true]
 */
bool CDCSOPCSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror, DCERPCState *phandle)
{
    if ((sdata == NULL) || (phandle == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    bool pass = true;
    uint16 dyport = 0;

    int ret = DCERPCParser(&(phandle->dcerpc), (const puint8)sdata + hdflag, slen - hdflag);
    if (ret == -1) {

        PRINT_ERR_HEAD
        print_err("DCERPCParser fail");
    } else if (_DCEMEM_REQ_(*phandle, first_request_seen)) {

        PRINT_DBG_HEAD
        print_dbg("OPC type:%d ,ctxid:%d", _DCEMEM_H_(*phandle, type), _DCEMEM_REQ_(*phandle, ctxid));

        switch (_DCEMEM_H_(*phandle, type)) {
        case REQUEST:
        case RESPONSE: {
            DCERPCUuidEntry *item = TAILQ_END(0);
            bool banalys = false;//解析成功?

            TAILQ_FOREACH(item, &_DCEMEM_(*phandle, dcerpcbindbindack.accepted_uuid_list), next) {

                PRINT_DBG_HEAD
                print_dbg("OPC item = %u, flags = 0x%02x, result = %u, version = 0x%02x",
                          item->ctxid, item->flags, item->result, item->version);

                if (!(item->flags & DCERPC_UUID_ENTRY_FLAG_FF)) { continue; }

                /* if the uuid has been rejected(item->result == 1), we skip to the
                 * next uuid */
                if (item->result != 0) { continue; }

                //保存uuid到成员变量
                memcpy(m_uuid, item->uuid, sizeof(m_uuid));

                //把uuid转换为十六进制字符串保存到成员变量
                printstrUUID(item->uuid, m_uuidstr, sizeof(m_uuidstr));

                if (_DCEMEM_H_(*phandle, type) == RESPONSE) {

                    PRINT_DBG_HEAD
                    print_dbg("RESPONSE,begin getport");

                    if ((dyport = getport(item, phandle)) != 0) {

                        PRINT_DBG_HEAD
                        print_dbg("find dyport[%d]", dyport);

                        DATANETADDR addr;
                        memset(&addr, 0, sizeof(addr));
                        BIN2IP(addr.srcaddr, sdata + 16);
                        BIN2IP(addr.dstaddr, sdata + 12);
                        addr.dstport = dyport;
                        AddDynamicInfo(&addr);
                        break;
                    }
                } else {
                    //处理用户规则过滤 解析成功?
                    if ((banalys = getusrfilter(item, phandle))) {
                        break;
                    } else {
                        PRINT_ERR_HEAD
                        print_err("getusrfilter fail,continue");
                    }
                }
            }

            if (banalys) {
                pass = m_bsys ? true : AnalyseCmdRule(cherror);
                RecordCallLog(sdata, m_chcmd, m_chpara, cherror, pass);
            }
            break;
        }
        case BIND:      //DCERPC 处理的类型
        case BIND_ACK:
        case ALTER_CONTEXT:
        case ALTER_CONTEXT_RESP:
        default: {
            break;
        }
        }
    } else {
        PRINT_DBG_HEAD
        print_dbg("no first request seen");
    }

    PRINT_DBG_HEAD
    print_dbg("%s", pass ? "pakt pass" : "pakt drop");
    return pass;
}

bool CDCSOPCSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/**
 * [CDCSOPCSINGLE::AddDynamicInfo 添加动态信息]
 * @param paddr [地址端口结构指针]
 */

#define CLEAR_DY_FLOW(flow) \
    { \
        DCERPCCleanup(&(flow).dcerpchandle.dcerpc); \
        setiptables(&(flow).addr, false); \
        memset(&(flow), 0, sizeof(flow)); \
        DCERPCInit(&(flow).dcerpchandle.dcerpc); \
    }
void CDCSOPCSINGLE::AddDynamicInfo(PDATANETADDR paddr)
{
    if (paddr == NULL) {
        PRINT_ERR_HEAD
        print_err("add dynamic info para null");
        return ;
    }

    int i, j = -1;
    for (i = 0; i < MAX_OPC_DYNAMIC_SIZE; i++) {
        if (memcmp(&(m_dynamicflow[i].addr), paddr, sizeof(m_dynamicflow[i].addr)) == 0) {
            break ;
        }

        if ((m_dynamicflow[i].timestamp != 0)
            && (time(NULL) - m_dynamicflow[i].timestamp > OPC_TIME_OUT_SECOND)) {
            PRINT_DBG_HEAD
            print_dbg("clear dy flow begin index[%d]...", i);
            CLEAR_DY_FLOW(m_dynamicflow[i]);
            if (j == -1) { j = i; }
        } else if (m_dynamicflow[i].timestamp == 0) {
            if (j == -1) { j = i; }
        }
    }

    if (i < MAX_OPC_DYNAMIC_SIZE) {
        //已经存在
        m_dynamicflow[i].timestamp = time(NULL);
        PRINT_DBG_HEAD
        print_dbg("already in dynamic flow.indix %d, port %d", i, paddr->dstport);
        return ;
    }

    if (j > -1) {

        DCERPCInit(&(m_dynamicflow[j].dcerpchandle.dcerpc));
        memcpy(&(m_dynamicflow[j].addr), paddr, sizeof(m_dynamicflow[j].addr));
        m_dynamicflow[j].timestamp = time(NULL);
        PRINT_DBG_HEAD
        print_dbg("add dynamic flow port %d", paddr->dstport);
        setiptables(paddr, true);
        return ;
    }

    PRINT_ERR_HEAD
    print_err("add dynamic flow fail,is full port[%d]", paddr->dstport);
    return ;
}

/**
 * [CDCSOPCSINGLE::IfMatchDynamic 判断IP数据包是否属于OPC动态连接]
 * @param  sdata [IP数据包]
 * @param  index [匹配上时 用于返回动态结构下标]
 * @return       [true表示匹配上了]
 */
#define _dy_addrequal(a1, a2) \
    ((a1.srcaddr==a2.srcaddr) && (a1.dstaddr==a2.dstaddr) && (a1.dstport==a2.dstport)) \
    || ((a1.srcaddr==a2.dstaddr) &&(a1.dstaddr==a2.srcaddr) &&(a1.dstport==a2.srcport))

bool CDCSOPCSINGLE::IfMatchDynamic(unsigned char *sdata, int &index)
{
    bool bflag = false;
    DATANETADDR addr;

    if (_ipv4(sdata)) {
        BIN2IP(addr.srcaddr, &(((PIP_HEADER)sdata)->ip_src));
        BIN2IP(addr.dstaddr, &(((PIP_HEADER)sdata)->ip_dst));
        addr.srcport = ntohs((_tcpipdata(sdata))->th_sport);
        addr.dstport = ntohs((_tcpipdata(sdata))->th_dport);

        for (int i = 0; i < MAX_OPC_DYNAMIC_SIZE; i++) {
            if (_dy_addrequal(m_dynamicflow[i].addr, addr)) {
                m_dynamicflow[i].timestamp = time(NULL);
                index = i;
                bflag = true;
                break;
            }
        }

        return bflag;
    } else if (_ipv6(sdata)) {
        //......
        return false;
    } else {
        //......
        return false;
    }
}

#if 0
bool CDCSOPCSINGLE::IfNumber(char *istr, int len)
{
    for (int i = 0; i < len; i++) {
        if (istr[i] < '0' || istr[i] > '9') {
            return false;
        }
    }
    return true;
}
#endif

/**
 * [COPC::printstrUUID 打印UUID格式字符串]
 * @param  uuid    [description]
 * @param  strout  [输出字符串]
 * @param  lstrout [输出字符串空间]
 * @return         [UUID格式串长度，0错误]
 */
#define UUID_STRLEN (16*2+4)
int CDCSOPCSINGLE::printstrUUID(const unsigned char *uuid, char *strout, int lstrout)
{
    if ((strout == NULL) || (uuid == NULL)) {
        PRINT_ERR_HEAD
        print_err("para is null");
        return 0;
    }

    memset(strout, 0, lstrout);
    if (lstrout < (UUID_STRLEN + 1)) {
        PRINT_ERR_HEAD
        print_err("lstrout too short[%d]", lstrout);
        return 0;      //错误返回
    }

    for (int32 i = 0; i < 16; i++) {

        if ((i == 4) || (i == 6) || (i == 8) || (i == 10)) {
            strcat(strout, "-");
        }

#if 0
        if (i < 4) {
            sprintf(strout + strlen(strout), "%02x", uuid[3 - i]);
        } else if (i < 6) {
            sprintf(strout + strlen(strout), "%02x", uuid[2 * 4 + 1 - i]);
        } else if (i < 8) {
            sprintf(strout + strlen(strout), "%02x", uuid[2 * 6 + 1 - i]);
        } else if (i < 10) {
            sprintf(strout + strlen(strout), "%02x", uuid[2 * 8 + 1 - i]);
        } else {
            sprintf(strout + strlen(strout), "%02x", uuid[i]);
        }
#else
        sprintf(strout + strlen(strout), "%02x", uuid[i]);
#endif
    }

    PRINT_DBG_HEAD
    print_dbg("UUID = %s", strout);
    return UUID_STRLEN;        //UUID 字符串长度
}

/**
 * [CDCSOPCSINGLE::getusrfilter 解析命令信息]
 * @param  item    [结构指针]
 * @param  phandle [结构指针]
 * @return         [解析成功返回true]
 */
bool CDCSOPCSINGLE::getusrfilter(DCERPCUuidEntry *item, DCERPCState *phandle)
{
    if (item == TAILQ_END(0)) {
        PRINT_ERR_HEAD
        print_err("para is null");
        return false;
    }

    bool find = false;
    m_bsys = false;
    m_rw = PROTO_RWNULL;
    m_opnum = 0;
    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));

    PRINT_DBG_HEAD
    print_dbg("ctxid is %d %d", item->ctxid, _DCEMEM_REQ_(*phandle, ctxid));

    //对应上下文，方法，接口
    if (item->ctxid == _DCEMEM_REQ_(*phandle, ctxid)) {
        //系统默认规则，必须通过
        static const POPCDATA sysdef[] = {(POPCDATA)DCOMSET, (POPCDATA)OPCDASET, NULL};
        int32 j = 0;

        m_opnum = _DCEMEM_REQ_(*phandle, opnum);

        while (sysdef[j] != NULL) {
            int32 i = 0;
            while (sysdef[j][i].ifname != NULL) {
                if (uuidequal(sysdef[j][i].uuid, item->uuid)) {
                    if ((sysdef[j][i].opname[0] == 0) || (sysdef[j][i].opnum == m_opnum)) {
                        m_rw = sysdef[j][i].rw;
                        m_bsys = (sysdef[j][i].flag == 0);
                        sprintf(m_chcmd, m_bsys ? "[SYS]%s" : "%s", sysdef[j][i].ifname);
                        strcpy(m_chpara, sysdef[j][i].opname);
                        find = true;
                        break;
                    }
                }
                i++;
            }

            if (find) { break; }
            j++;
        }

        //如果列表中没有
        if (!find) {
            strcpy(m_chcmd, m_uuidstr);
            if (m_opnum > 0) {
                sprintf(m_chpara, "%d", m_opnum);
            }

            PRINT_DBG_HEAD
            print_dbg("FILTER SYS UNKNOWN %u = %u, %s:%u",
                      item->ctxid, _DCEMEM_REQ_(*phandle, ctxid), m_uuidstr, m_opnum);
        }
        return true;
    }

    PRINT_ERR_HEAD
    print_err("get usr filter fail");
    return false;
}

/**
 * [CDCSOPCSINGLE::AnalyseCmdRule 分析命令规则 判断是否放行]
 * @param  cherror [返回出错信息]
 * @return         [允许通过返回true]
 */
bool CDCSOPCSINGLE::AnalyseCmdRule(char *cherror)
{
    bool bflag = m_service->m_IfExec;
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (CmdMatch(m_service->m_cmd[i])) {
            bflag = m_service->m_cmd[i]->m_action;
            break;
        }
    }

    if (!bflag) {
        PRINT_ERR_HEAD
        print_err("opc perm forbid");
        sprintf(cherror, "%s", OPC_PERM_FORBID);
    }
    return bflag;
}
