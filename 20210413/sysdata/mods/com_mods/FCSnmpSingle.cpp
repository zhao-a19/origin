/*******************************************************************************************
*文件:  FCSnmpSingle.cpp
*描述:  SNMP模块
*作者:dzj
*日期:  2020-01
*修改:
*          支持解析IPV6                                             ------> 2020-01-18 -dzj
*          修改接口参数命名和中文日志问题                           ------> 2020-02-13 -dzj
*          修改snmp日志信息                                         ------> 2020-02-18 -dzj
*******************************************************************************************/
#include "FCSnmpSingle.h"
#include "debugout.h"
#include "datatype.h" //for MIN
#include <sys/socket.h>
#include <string>
#include <strings.h>
#include <iostream>
using namespace std;

CSNMP::CSNMP(const char *dport)
{
#if (SUOS_V!=6)
    su_epan_set_port("snmp", atoi(dport));
#endif

}

CSNMP::~CSNMP(void)
{
}

/**
 * [CSNMP::DoMsg 处理数据包]
 * @param  sdata     [IP开头的数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [包是否发送改变]
 * @param  bFromSrc  [1为来自源对象 否则来自目的对象]
 * @return           [允许通过返回true]
 */
bool CSNMP::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}
#if (SUOS_V!=6)
/**
 * [CSNMP::AnalyseCmdRule 过滤命令]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CSNMP::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    bool bflag = m_service->m_IfExec;
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0) {
            if(0 == m_service->m_cmd[i]->m_parameter) {
                bflag = m_service->m_cmd[i]->m_action;
                break;
            }
            if (strncasecmp(m_service->m_cmd[i]->m_parameter, chpara,
                    strlen(m_service->m_cmd[i]->m_parameter)) == 0) {
                bflag = m_service->m_cmd[i]->m_action;
                break;
            }
        }
    }

    if (!bflag) {
        sprintf(cherror, "%s", SNMP_PERM_FORBID);
        PRINT_ERR_HEAD
        print_err("SNMP cmd forbid[%s:%s]", chcmd, chpara);
    }

    return bflag;
}
#endif
/**
 * [CSNMP::DoSrcMsg 处理来自源对象的请求]
 * @param  sdata   [IP开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CSNMP::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    int16 i = 0;
    int32 ret = 0;
    bool pass = true;
    int cmd_count = 0;
    char snmp_ver_id[MAX_CMD_NAME_LEN] = {0};
    char snmp_cmd_id[MAX_CMD_NAME_LEN] = {0};
    char snmp_oid[MAX_PARA_NAME_LEN] = {0};
    char snmp_cmd[MAX_CMD_NAME_LEN] = {0};
#if (SUOS_V!=6)
    GSList *snmp[SNMP_REQ_MAX_OID] = {NULL};
    GSList *snmp_node = NULL;
    int snmp_id = 0, snmp_oid_list_length = 0;
    static struct su_protocol_define_t protocol = {"snmp", 4, 0, PROTOCOL_FLAG_FROM_SHOW,
        {"op_desc", "snmp.version", "snmp.msgVersion", "snmp.name", "snmp.data", NULL}, (GHashTable *)0};

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
        print_info("This pkg is neither IPV4 nor IPV6");
        return true;
    }
    memcpy(t_data+14, sdata, slen);

    if (!protocol.key_map) {
        protocol.key_map = g_hash_table_new(g_str_hash, g_str_equal);
        if ( !protocol.key_map ) {
            PRINT_ERR_HEAD;
            print_err("create protocol key_map failed");
            return false;
        }
        for (i = 0; protocol.keys[i] != NULL; i++) {
            g_hash_table_insert(protocol.key_map, (gpointer)protocol.keys[i], GINT_TO_POINTER(i));
        }
        PRINT_DBG_HEAD;
        print_dbg("create protocol key_map sucess");
    }

    ret = try_dissect(pSuEpanSession->edt, t_data, t_data_len,
                        pSuEpanSession->pkg_num++, &protocol, snmp);
    if (ret == 0) {
        PRINT_DBG_HEAD;
        print_dbg("SNMP pkg key found");

        snmp_id = get_key_index(&protocol, "snmp.version");
        if (snmp_id > 0){
            snmp_node = snmp[snmp_id];
            if (NULL != snmp_node) {
                strcpy(snmp_ver_id, (char *)snmp_node->data);
                PRINT_DBG_HEAD;
                print_dbg("SNMP ver = %s", snmp_ver_id);
            }
        }

        snmp_id = get_key_index(&protocol, "snmp.msgVersion");
        if (snmp_id > 0){
            snmp_node = snmp[snmp_id];
            if (NULL != snmp_node) {
                strcpy(snmp_ver_id, (char *)snmp_node->data);
                PRINT_DBG_HEAD;
                print_dbg("SNMP ver = %s", snmp_ver_id);
            }
        }

        snmp_id = get_key_index(&protocol, "snmp.data");
        if (snmp_id > 0){
            snmp_node = snmp[snmp_id];
            if (NULL != snmp_node) {
                strcpy(snmp_cmd_id, (char *)snmp_node->data);
                if (strcmp(SNMP_VERSION_1, snmp_ver_id) == 0) {
                    strcpy(snmp_cmd, SNMPV1_RE_CMD[atoi(snmp_cmd_id)]);
                } else if (strcmp(SNMP_VERSION_2C, snmp_ver_id) == 0) {
                    strcpy(snmp_cmd, SNMPV2C_RE_CMD[atoi(snmp_cmd_id)]);
                } else {
                    strcpy(snmp_cmd, SNMPV3_RE_CMD[atoi(snmp_cmd_id)]);
                }
                PRINT_DBG_HEAD;
                print_dbg("SNMP cmd = %s", snmp_cmd);
            }
        }

        snmp_id = get_key_index(&protocol, "snmp.name");
        snmp_node = snmp[snmp_id];
        snmp_oid_list_length = g_slist_length(snmp_node);
        if (snmp_oid_list_length > 0){
            for (snmp_node = snmp[snmp_id]; snmp_node != NULL; snmp_node = snmp_node->next) {
                strcpy(snmp_oid, (char *)snmp_node->data);
                if (AnalyseCmdRule(snmp_cmd, snmp_oid, cherror)) {
                    PRINT_DBG_HEAD;
                    print_dbg("SNMP request version = %s, cmd = %s, m_oid = %s, ACCEPT", snmp_ver_id, snmp_cmd, snmp_oid);
                    RecordCallLog(sdata, snmp_cmd, snmp_oid, "", true);
                } else {
                    PRINT_DBG_HEAD;
                    print_dbg("SNMP request version = %s, cmd = %s, m_oid = %s, REJECT", snmp_ver_id, snmp_cmd, snmp_oid);
                    RecordCallLog(sdata, snmp_cmd, snmp_oid, cherror, false);
                    pass = false;
                }
                cmd_count++;
                if(cmd_count >= SNMP_REQ_MAX_OID){
                    PRINT_INFO_HEAD;
                    print_info("one packet cmd is too many %d",cmd_count);
                    break;
                }
            }
        }

    } else {
        PRINT_INFO_HEAD
        print_info("SNMP decode request fail. exec default action");
        RecordCallLog(sdata, "", "", cherror, m_service->m_IfExec);
    }

    if (t_data) {
        free(t_data);
        t_data = NULL;
    }

    for (i = 0;  i < SNMP_REQ_MAX_OID; i++) {
        if (snmp[i]) {
            g_slist_free_full(snmp[i], g_free);
            snmp[i] = NULL;
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
 * [CSNMP::DoDstMsg 处理来自目的对象的请求]
 * @param  sdata   [IP开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CSNMP::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    int16 i = 0;
    int32 ret = 0;
    bool pass = true;
    int cmd_count = 0;
    char snmp_ver_id[MAX_CMD_NAME_LEN] = {0};
    char snmp_cmd_id[MAX_CMD_NAME_LEN] = {0};
    char snmp_oid[MAX_PARA_NAME_LEN] = {0};
    char snmp_cmd[MAX_CMD_NAME_LEN] = {0};
#if (SUOS_V!=6)
    GSList *snmp[SNMP_RES_MAX_OID] = {NULL};
    GSList *snmp_node = NULL;
    int snmp_id = 0, snmp_oid_list_length = 0;
    static struct su_protocol_define_t protocol = {"snmp", 4, 0, PROTOCOL_FLAG_FROM_SHOW,
        {"op_desc", "snmp.version", "snmp.msgVersion", "snmp.name", "snmp.data", NULL}, (GHashTable *)0};

    /******************开始进行数据包的处理******************/
    //data是三层数据，而Wireshark分析的是含2层以上的数据，因此需要通过拿到三层的协议类型，重新封装一个
    //含二层的数据包
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
        print_info("This pkg is neither IPV4 nor IPV6");
        return true;
    }
    memcpy(t_data+14, sdata, slen);

    if (!protocol.key_map) {
        protocol.key_map = g_hash_table_new(g_str_hash, g_str_equal);
        if ( !protocol.key_map ) {
            PRINT_ERR_HEAD;
            print_err("create protocol key_map failed");
            return false;
        }
        for (i = 0; protocol.keys[i] != NULL; i++) {
            g_hash_table_insert(protocol.key_map, (gpointer)protocol.keys[i], GINT_TO_POINTER(i));
        }
        PRINT_DBG_HEAD;
        print_dbg("create protocol key_map success");
    }

    ret = try_dissect(pSuEpanSession->edt, t_data, t_data_len,
                           pSuEpanSession->pkg_num++, &protocol, snmp);
    if (ret == 0) {
        PRINT_DBG_HEAD;
        print_dbg("SNMP pkg key found");

        snmp_id = get_key_index(&protocol, "snmp.version");
        if (snmp_id > 0){
            snmp_node = snmp[snmp_id];
            if (NULL != snmp_node) {
                strcpy(snmp_ver_id, (char *)snmp_node->data);
                PRINT_DBG_HEAD;
                print_dbg("SNMP ver = %s", snmp_ver_id);
            }
        }

        snmp_id = get_key_index(&protocol, "snmp.msgVersion");
        if (snmp_id > 0){
            snmp_node = snmp[snmp_id];
            if (NULL != snmp_node) {
                strcpy(snmp_ver_id, (char *)snmp_node->data);
                PRINT_DBG_HEAD;
                print_dbg("SNMP ver = %s", snmp_ver_id);
            }
        }

        snmp_id = get_key_index(&protocol, "snmp.data");
        if (snmp_id > 0){
            snmp_node = snmp[snmp_id];
            if (NULL != snmp_node) {
                strcpy(snmp_cmd_id, (char *)snmp_node->data);
                if (strcmp(SNMP_VERSION_1, snmp_ver_id) == 0) {
                    strcpy(snmp_cmd, SNMPV1_RE_CMD[atoi(snmp_cmd_id)]);
                } else if (strcmp(SNMP_VERSION_2C, snmp_ver_id) == 0) {
                    strcpy(snmp_cmd, SNMPV2C_RE_CMD[atoi(snmp_cmd_id)]);
                } else {
                    strcpy(snmp_cmd, SNMPV3_RE_CMD[atoi(snmp_cmd_id)]);
                }
                PRINT_DBG_HEAD;
                print_dbg("SNMP cmd = %s", snmp_cmd);
            } else {
                PRINT_DBG_HEAD;
                print_dbg("SNMP cmd is NULL");
            }
        }

        snmp_id = get_key_index(&protocol, "snmp.name");
        snmp_node = snmp[snmp_id];
        snmp_oid_list_length = g_slist_length(snmp_node);
        if (snmp_oid_list_length > 0){
            for (snmp_node = snmp[snmp_id]; snmp_node != NULL; snmp_node = snmp_node->next) {
                strcpy(snmp_oid, (char *)snmp_node->data);
                if (AnalyseCmdRule(snmp_cmd, snmp_oid, cherror)) {
                    PRINT_DBG_HEAD;
                    print_dbg("SNMP response version = %s, cmd = %s, m_oid = %s, ACCEPT", snmp_ver_id, snmp_cmd, snmp_oid);
                    RecordCallLog(sdata, snmp_cmd, snmp_oid, "", true);
                } else {
                    PRINT_DBG_HEAD;
                    print_dbg("SNMP response version = %s, cmd = %s, m_oid = %s, REJECT", snmp_ver_id, snmp_cmd, snmp_oid);
                    RecordCallLog(sdata, snmp_cmd, snmp_oid, cherror, false);
                    pass = false;
                }
                cmd_count++;
                if(cmd_count >= SNMP_RES_MAX_OID){
                    PRINT_INFO_HEAD;
                    print_info("one packet cmd is too many %d",cmd_count);
                    break;
                }
            }
        }

    } else {
        PRINT_INFO_HEAD
        print_info("SNMP decode response fail. exec default action");
        RecordCallLog(sdata, "", "", cherror, m_service->m_IfExec);
    }

    if (t_data) {
        free(t_data);
        t_data = NULL;
    }

    for (i = 0;  i < SNMP_RES_MAX_OID; i++) {
        if (snmp[i]) {
            g_slist_free_full(snmp[i], g_free);
            snmp[i] = NULL;
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
