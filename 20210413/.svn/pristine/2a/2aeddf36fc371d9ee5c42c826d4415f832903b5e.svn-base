/*******************************************************************************************
*文件:  FCOpcuaSingle.cpp
*描述:  OPCUA模块
*作者:dzj
*日期:  2019-09
*修改:
*          解决在V6环境下编辑不过问题                               ------> 2019-10-08-dzj
*          解决在V6环境下编辑不过问题                               ------> 2019-10-08-dzj
*          解决OPCUA端口改变不可解析的问题                          ------> 2019-10-10 -dzj
*          解决在V6环境下编辑不过问题                               ------> 2019-11-21-dzj
*          解决OPCUA匹配后不跳出的问题                              ------> 2020-01-17 -dzj
*          支持解析IPV6                                             ------> 2020-01-18 -dzj
*          修改接口参数命名和中文日志问题                           ------> 2020-02-13 -dzj
*          修改opcua日志信息                                        ------> 2020-02-18 -dzj
*******************************************************************************************/
#include "FCOpcuaSingle.h"
#include "debugout.h"
#include "datatype.h" //for MIN
#include <sys/socket.h>
#include <string>
#include <iostream>
using namespace std;

COPCUASINGLE::COPCUASINGLE(const char *dport)
{
    mapOpcua[397] = "ServiceFault";
    mapOpcua[422] = "FindServersRequest";
    mapOpcua[425] = "FindServersResponse";
    mapOpcua[12208] = "FindServersOnNetworkRequest";
    mapOpcua[12209] = "FindServersOnNetworkResponse";
    mapOpcua[428] = "GetEndpointsRequest";
    mapOpcua[431] = "GetEndpointsResponse";
    mapOpcua[437] = "RegisterServerRequest";
    mapOpcua[440] = "RegisterServerResponse";
    mapOpcua[12211] = "RegisterServer2Request" ;
    mapOpcua[12212] = "RegisterServer2Response" ;
    mapOpcua[446] = "OpenSecureChannelRequest" ;
    mapOpcua[449] = "OpenSecureChannelResponse" ;
    mapOpcua[452] = "CloseSecureChannelRequest" ;
    mapOpcua[455] = "CloseSecureChannelResponse" ;
    mapOpcua[461] = "CreateSessionRequest" ;
    mapOpcua[464] = "CreateSessionResponse" ;
    mapOpcua[467] = "ActivateSessionRequest" ;
    mapOpcua[470] = "ActivateSessionResponse" ;
    mapOpcua[473] = "CloseSessionRequest" ;
    mapOpcua[476] = "CloseSessionResponse" ;
    mapOpcua[479] = "CancelRequest" ;
    mapOpcua[482] = "CancelResponse" ;
    mapOpcua[488] = "AddNodesRequest" ;
    mapOpcua[491] = "AddNodesResponse" ;
    mapOpcua[494] = "AddReferencesRequest" ;
    mapOpcua[497] = "AddReferencesResponse" ;
    mapOpcua[500] = "DeleteNodesRequest" ;
    mapOpcua[503] = "DeleteNodesResponse" ;
    mapOpcua[506] = "DeleteReferencesRequest" ;
    mapOpcua[509] = "DeleteReferencesResponse" ;
    mapOpcua[527] = "BrowseRequest" ;
    mapOpcua[530] = "BrowseResponse" ;
    mapOpcua[533] = "BrowseNextRequest" ;
    mapOpcua[536] = "BrowseNextResponse" ;
    mapOpcua[554] = "TranslateBrowsePathsToNodeIdsRequest" ;
    mapOpcua[557] = "TranslateBrowsePathsToNodeIdsResponse" ;
    mapOpcua[560] = "RegisterNodesRequest" ;
    mapOpcua[563] = "RegisterNodesResponse" ;
    mapOpcua[566] = "UnregisterNodesRequest" ;
    mapOpcua[569] = "UnregisterNodesResponse" ;
    mapOpcua[615] = "QueryFirstRequest" ;
    mapOpcua[618] = "QueryFirstResponse" ;
    mapOpcua[621] = "QueryNextRequest" ;
    mapOpcua[624] = "QueryNextResponse" ;
    mapOpcua[631] = "ReadRequest" ;
    mapOpcua[634] = "ReadResponse" ;
    mapOpcua[664] = "HistoryReadRequest" ;
    mapOpcua[667] = "HistoryReadResponse" ;
    mapOpcua[673] = "WriteRequest" ;
    mapOpcua[676] = "WriteResponse" ;
    mapOpcua[700] = "HistoryUpdateRequest" ;
    mapOpcua[703] = "HistoryUpdateResponse" ;
    mapOpcua[712] = "CallRequest" ;
    mapOpcua[715] = "CallResponse" ;
    mapOpcua[751] = "CreateMonitoredItemsRequest" ;
    mapOpcua[754] = "CreateMonitoredItemsResponse" ;
    mapOpcua[763] = "ModifyMonitoredItemsRequest" ;
    mapOpcua[766] = "ModifyMonitoredItemsResponse" ;
    mapOpcua[769] = "SetMonitoringModeRequest" ;
    mapOpcua[772] = "SetMonitoringModeResponse" ;
    mapOpcua[775] = "SetTriggeringRequest" ;
    mapOpcua[778] = "SetTriggeringResponse" ;
    mapOpcua[781] = "DeleteMonitoredItemsRequest" ;
    mapOpcua[784] = "DeleteMonitoredItemsResponse" ;
    mapOpcua[787] = "CreateSubscriptionRequest" ;
    mapOpcua[790] = "CreateSubscriptionResponse" ;
    mapOpcua[793] = "ModifySubscriptionRequest" ;
    mapOpcua[796] = "ModifySubscriptionResponse" ;
    mapOpcua[799] = "SetPublishingModeRequest" ;
    mapOpcua[802] = "SetPublishingModeResponse" ;
    mapOpcua[826] = "PublishRequest" ;
    mapOpcua[829] = "PublishResponse" ;
    mapOpcua[832] = "RepublishRequest" ;
    mapOpcua[835] = "RepublishResponse" ;
    mapOpcua[841] = "TransferSubscriptionsRequest" ;
    mapOpcua[844] = "TransferSubscriptionsResponse" ;
    mapOpcua[847] = "DeleteSubscriptionsRequest" ;
    mapOpcua[850] = "DeleteSubscriptionsResponse" ;
    mapOpcua[410] = "TestStackRequest" ;
    mapOpcua[413] = "TestStackResponse" ;
    mapOpcua[416] = "TestStackExRequest" ;
    mapOpcua[419] = "TestStackExResponse" ;
    mapOpcua[396] = "ServiceFault" ;
    mapOpcua[421] = "FindServersRequest" ;
    mapOpcua[424] = "FindServersResponse" ;
    mapOpcua[12196] = "FindServersOnNetworkRequest" ;
    mapOpcua[12197] = "FindServersOnNetworkResponse" ;
    mapOpcua[427] = "GetEndpointsRequest" ;
    mapOpcua[430] = "GetEndpointsResponse" ;
    mapOpcua[436] = "RegisterServerRequest" ;
    mapOpcua[439] = "RegisterServerResponse" ;
    mapOpcua[12199] = "RegisterServer2Request" ;
    mapOpcua[12200] = "RegisterServer2Response" ;
    mapOpcua[445] = "OpenSecureChannelRequest" ;
    mapOpcua[448] = "OpenSecureChannelResponse" ;
    mapOpcua[451] = "CloseSecureChannelRequest" ;
    mapOpcua[454] = "CloseSecureChannelResponse" ;
    mapOpcua[460] = "CreateSessionRequest" ;
    mapOpcua[463] = "CreateSessionResponse" ;
    mapOpcua[468] = "ActivateSessionRequest" ;
    mapOpcua[469] = "ActivateSessionResponse" ;
    mapOpcua[472] = "CloseSessionRequest" ;
    mapOpcua[475] = "CloseSessionResponse" ;
    mapOpcua[478] = "CancelRequest" ;
    mapOpcua[481] = "CancelResponse" ;
    mapOpcua[487] = "AddNodesRequest" ;
    mapOpcua[490] = "AddNodesResponse" ;
    mapOpcua[493] = "AddReferencesRequest" ;
    mapOpcua[496] = "AddReferencesResponse" ;
    mapOpcua[499] = "DeleteNodesRequest" ;
    mapOpcua[502] = "DeleteNodesResponse" ;
    mapOpcua[505] = "DeleteReferencesRequest" ;
    mapOpcua[508] = "DeleteReferencesResponse" ;
    mapOpcua[526] = "BrowseRequest" ;
    mapOpcua[529] = "BrowseResponse" ;
    mapOpcua[532] = "BrowseNextRequest" ;
    mapOpcua[535] = "BrowseNextResponse" ;
    mapOpcua[553] = "TranslateBrowsePathsToNodeIdsRequest" ;
    mapOpcua[556] = "TranslateBrowsePathsToNodeIdsResponse" ;
    mapOpcua[559] = "RegisterNodesRequest" ;
    mapOpcua[562] = "RegisterNodesResponse" ;
    mapOpcua[565] = "UnregisterNodesRequest" ;
    mapOpcua[568] = "UnregisterNodesResponse" ;
    mapOpcua[614] = "QueryFirstRequest" ;
    mapOpcua[617] = "QueryFirstResponse" ;
    mapOpcua[620] = "QueryNextRequest" ;
    mapOpcua[623] = "QueryNextResponse" ;
    mapOpcua[630] = "ReadRequest" ;
    mapOpcua[633] = "ReadResponse" ;
    mapOpcua[663] = "HistoryReadRequest" ;
    mapOpcua[666] = "HistoryReadResponse" ;
    mapOpcua[672] = "WriteRequest" ;
    mapOpcua[675] = "WriteResponse" ;
    mapOpcua[699] = "HistoryUpdateRequest" ;
    mapOpcua[702] = "HistoryUpdateResponse" ;
    mapOpcua[711] = "CallRequest" ;
    mapOpcua[714] = "CallResponse" ;
    mapOpcua[750] = "CreateMonitoredItemsRequest" ;
    mapOpcua[753] = "CreateMonitoredItemsResponse" ;
    mapOpcua[762] = "ModifyMonitoredItemsRequest" ;
    mapOpcua[765] = "ModifyMonitoredItemsResponse" ;
    mapOpcua[768] = "SetMonitoringModeRequest" ;
    mapOpcua[771] = "SetMonitoringModeResponse" ;
    mapOpcua[774] = "SetTriggeringRequest" ;
    mapOpcua[777] = "SetTriggeringResponse" ;
    mapOpcua[780] = "DeleteMonitoredItemsRequest" ;
    mapOpcua[783] = "DeleteMonitoredItemsResponse" ;
    mapOpcua[786] = "CreateSubscriptionRequest" ;
    mapOpcua[789] = "CreateSubscriptionResponse" ;
    mapOpcua[792] = "ModifySubscriptionRequest" ;
    mapOpcua[795] = "ModifySubscriptionResponse" ;
    mapOpcua[798] = "SetPublishingModeRequest" ;
    mapOpcua[801] = "SetPublishingModeResponse" ;
    mapOpcua[825] = "PublishRequest" ;
    mapOpcua[828] = "PublishResponse" ;
    mapOpcua[831] = "RepublishRequest" ;
    mapOpcua[834] = "RepublishResponse" ;
    mapOpcua[840] = "TransferSubscriptionsRequest" ;
    mapOpcua[843] = "TransferSubscriptionsResponse" ;
    mapOpcua[846] = "DeleteSubscriptionsRequest" ;
    mapOpcua[849] = "DeleteSubscriptionsResponse" ;
    mapOpcua[409] = "TestStackRequest" ;
    mapOpcua[412] = "TestStackResponse" ;
    mapOpcua[415] = "TestStackExRequest" ;
    mapOpcua[418] = "TestStackExResponse" ;

#if (SUOS_V!=6)
    su_epan_set_port("opcua", atoi(dport));
#endif

}

COPCUASINGLE::~COPCUASINGLE(void)
{
}

/**
 * [COPCUASINGLE::DoMsg 处理数据包]
 * @param  sdata     [IP开头的数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [包是否发送改变]
 * @param  bFromSrc  [1为来自源对象 否则来自目的对象]
 * @return           [允许通过返回true]
 */
bool COPCUASINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}
#if (SUOS_V!=6)
/**
 * [COPCUASINGLE::AnalyseCmdRule 过滤命令]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool COPCUASINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    bool bflag = m_service->m_IfExec;
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0) {
                bflag = m_service->m_cmd[i]->m_action;
                break;
        }
    }

    if (!bflag) {
        sprintf(cherror, "%s", OPCUA_PERM_FORBID);
        PRINT_ERR_HEAD
        print_err("opcua cmd forbid[%s:%s]", chcmd, chpara);
    }

    return bflag;
}
#endif
/**
 * [COPCUASINGLE::DoSrcMsg 处理来自源对象的请求]
 * @param  sdata   [IP开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool COPCUASINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    int16 i = 0;
    int32 ret = 0;
    string value;
    bool pass = true;
    int cmd_count = 0;
#if (SUOS_V!=6)
    //char rule_str_with_sep[4096] = {0};
    GSList *kvs[OPCUA_MAX_CMD] = {NULL};
    GSList *kvl = NULL;
    int kvs_list_length = 0;
    int servernode_id_index = 0;
    static struct su_protocol_define_t protocol = {"opcua", 4, 0, PROTOCOL_FLAG_FROM_SHOW,
        {"op_desc", "opcua.servicenodeid.numeric", NULL}, (GHashTable *)0};

    /******************开始进行数据包的处理******************/
    //data是三层数据，而Wireshark分析的是含2层以上的数据，因此需要通过拿到三层的协议类型，
    //重新封装一个含二层的数据包
    int32_t t_data_len = slen + 14;
    //动态分配内存，需要手动释放-只要 try_dissector 执行完就可以释放!
    uint8_t *t_data = (uint8_t *)malloc(t_data_len);

    struct mac_hdr_t *mac_hdr = (struct mac_hdr_t *)t_data;
    if (_ipv4(sdata)) {
        mac_hdr->l2_protocol = ntohs(0x0800);
    } else if (_ipv6(sdata)) {
        mac_hdr->l2_protocol = ntohs(0x86dd);
    } else {
        PRINT_INFO_HEAD;
        print_dbg("This pkg is neither IPV4 nor IPV6");
        return true;
    }
    memcpy(t_data+14, sdata, slen);

    if (!protocol.key_map) {
        protocol.key_map = g_hash_table_new(g_str_hash, g_str_equal);
        if ( !protocol.key_map ) {
            PRINT_DBG_HEAD;
            print_dbg("create protocol key_map failed");
            return false;
        }
        for (i = 0; protocol.keys[i] != NULL; i++) {
            g_hash_table_insert(protocol.key_map, (gpointer)protocol.keys[i], GINT_TO_POINTER(i));
        }
        PRINT_DBG_HEAD;
        print_dbg("create protocol key_map success");
    }

    ret = try_dissect(pSuEpanSession->edt, t_data, t_data_len,
                    pSuEpanSession->pkg_num++, &protocol, kvs);
    if (ret == 0) {
        PRINT_DBG_HEAD;
        print_dbg("OPCUA pkg key found");

        servernode_id_index = get_key_index(&protocol, "opcua.servicenodeid.numeric");
        kvl = kvs[servernode_id_index];
        kvs_list_length = g_slist_length(kvl);

        if (kvs_list_length > 0){
            GSList *node = NULL;
            for (node = kvs[servernode_id_index]; node != NULL; node = node->next) {
                strcpy(m_para[cmd_count], (char *)node->data);
                PRINT_DBG_HEAD;
                print_dbg("OPCUA cmd = %s", (char *)node->data);
                cmd_count++;
                if(cmd_count >= OPCUA_MAX_CMD){
                    PRINT_INFO_HEAD;
                    print_info("one packet cmd is too many %d",cmd_count);
                }
            }
        }
        for(i = 0; i < cmd_count; i++){
            value = mapOpcua[atoi(m_para[i])];
            strcpy(m_cmd[i], value.data());
            if (AnalyseCmdRule(m_cmd[i], m_para[i], cherror)) {
                PRINT_DBG_HEAD;
                print_dbg("OPCUA cmd = %s, m_para = %s, ACCEPT", m_cmd[i], m_para[i]);
                RecordCallLog(sdata, m_cmd[i], m_para[i], "", true);
            } else {
                PRINT_DBG_HEAD;
                print_dbg("OPCUA cmd = %s, m_para = %s, REJECT", m_cmd[i], m_para[i]);
                RecordCallLog(sdata, m_cmd[i], m_para[i], cherror, false);
                pass = false;
            }
        }
    } else {
        PRINT_INFO_HEAD
        print_info("opcua decode request fail. exec default action");
        RecordCallLog(sdata, "", "", cherror, m_service->m_IfExec);
    }

    if (t_data) {
        free(t_data);
        t_data = NULL;
    }

    for (i = 0;  i < OPCUA_MAX_CMD; i++) {
        if (kvs[i]) {
            g_slist_free_full(kvs[i], g_free);
            kvs[i] = NULL;
        }
    }

    if (protocol.key_map) {
        g_hash_table_destroy(protocol.key_map);
        protocol.key_map = NULL;
    }

    epan_dissect_reset(pSuEpanSession->edt);
#endif
    return pass;
}

/**
 * [COPCUASINGLE::DoDstMsg 处理来自目的对象的请求]
 * @param  sdata   [IP开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool COPCUASINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }
    return true;
}
