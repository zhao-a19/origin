/*******************************************************************************************
*文件:  cip_parser.cpp
*描述:  cip解析
*作者:  王君雷
*日期:  2021-02-01
*修改:
*       修改浮点型测点值取值错误问题                             ------> 2021-03-01
*       根据北方管网项目现场测试情况，添加对MSG服务类型的ConnectionManager处理，解决解析不出读
*       写动作的问题                                            ------> 2021-05-13
*******************************************************************************************/
#include "cip_parser.h"
#include "debugout.h"
#include "util-debug.h"

struct _cipcmd_to_desc {
    uint16 cmd;
    char *cmdstr;
} g_cipcmd_to_desc[] = {
    {NOP, "NOP"},
    {LIST_SERVICES, "ListServices"},
    {LIST_IDENTITY, "ListIdentity"},
    {LIST_INTERFACES, "ListInterfaces"},
    {REGISTER_SESSION, "RegisterSession"},
    {UNREGISTER_SESSION, "UnRegisterSession"},
    {SEND_RR_DATA, "SendRRData"},
    {SEND_UNIT_DATA, "SendUnitData"},
    {INDICATE_STATUS, "IndicateStatus"},
    {CANCEL, "Cancel"}
};

CIPParser::CIPParser(void)
{
    clear();
}

CIPParser::~CIPParser(void)
{
}

/**
 * [CIPParser::clear 清空初始化相关成员变量]
 */
void CIPParser::clear(void)
{
    memset(m_pointname, 0, sizeof(m_pointname));
    memset(&m_addritem, 0, sizeof(m_addritem));
    memset(&m_dataitem, 0, sizeof(m_dataitem));
    m_segentry.clear();
    m_attrentry.clear();
    m_vecint.clear();
    m_vecfloat.clear();
    m_vecbool.clear();
    m_pheader = NULL;
    m_pdataheader = NULL;
    m_pconnmanhdr = NULL;
    m_pconnmanmsphdr = NULL;
    m_ptypevalue = NULL;
    m_pciprequestheader = NULL;
    m_action = CIPActionNULL;
}

/**
 * [CIPParser::get_command 获取命令]
 * @param  cmd    [命令 出参]
 * @param  cmdlen [命令长度]
 * @return        [获取成功返回true]
 */
bool CIPParser::get_command(char *cmd, int cmdlen)
{
    //如果分析出是读或写动作  就把读写当命令传输给外部
    //否则把enip中的命令传输给外部
    return (get_action(cmd, cmdlen) || get_enip_command(cmd, cmdlen));
}

/**
 * [CIPParser::get_enip_command 获取命令]
 * @param  cmd    [命令 出参]
 * @param  cmdlen [命令长度]
 * @return        [获取成功返回true]
 */
bool CIPParser::get_enip_command(char *cmd, int cmdlen)
{
    if ((cmd == NULL) || (cmdlen <= 0) || (m_pheader == NULL)) {
        PRINT_ERR_HEAD
        print_err("para error. cmdlen %d", cmdlen);
        return false;
    }
    bool find = false;
    for (int i = 0; i < CIP_ARRAY_SIZE(g_cipcmd_to_desc); ++i) {
        if (m_pheader->command == g_cipcmd_to_desc[i].cmd) {
            snprintf(cmd, cmdlen, "%s", g_cipcmd_to_desc[i].cmdstr);
            find = true;
            break;
        }
    }
    if (!find) {
        PRINT_INFO_HEAD
        print_info("unknown cmd 0x%04x", m_pheader->command);
    }
    return find;
}

/**
 * [CIPParser::get_action 获取读写动作]
 * @param  cmd    [命令 出参]
 * @param  cmdlen [长度]
 * @return        [是读或写操作时返回true]
 */
bool CIPParser::get_action(char *cmd, int cmdlen)
{
    if (m_action == CIPReadAction) {
        snprintf(cmd, cmdlen, CIP_READ_STR);
        return true;
    } else if (m_action == CIPWriteAction) {
        snprintf(cmd, cmdlen, CIP_WRITE_STR);
        return true;
    } else {
        return false;
    }
}

/**
 * [CIPParser::get_para 获取参数]
 * @param  para     [参数  出参]
 * @param  parasize [缓冲区长度]
 * @return          [成功返回true]
 */
bool CIPParser::get_para(char *para, int parasize)
{
    //如果分析出了测点名  就把测点名传输给外部
    //否则把requestheader中的服务传输给外部
    return (get_pointname(para, parasize) || get_service(para, parasize));
}

/**
 * [CIPParser::get_pointname 获取测点名称]
 * @param  name    [测点名称]
 * @param  namelen [缓冲区长度]
 * @return         [成功返回true]
 */
bool CIPParser::get_pointname(char *name, int namelen)
{
    if (m_pointname[0] == 0) {
        PRINT_DBG_HEAD
        print_dbg("not find pointname");
        return false;
    }
    snprintf(name, namelen, "%s", m_pointname);
    return true;
}

/**
 * [CIPParser::get_service 获取服务]
 * @param  service [服务 出参]
 * @param  srvlen  [长度]
 * @return         [成功返回true]
 */
bool CIPParser::get_service(char *service, int srvlen)
{
    if (m_pciprequestheader == NULL) {
        PRINT_DBG_HEAD
        print_dbg("not find service");
        return false;
    }

    switch (m_pciprequestheader->service) {
    case CIP_RESERVED:
        snprintf(service, srvlen, "Reserved");
        break;
    case CIP_GET_ATTR_ALL:
        snprintf(service, srvlen, "GetAttributeAll");
        break;
    case CIP_GET_ATTR_LIST:
        snprintf(service, srvlen, "GetAttributeList");
        break;
    case CIP_SET_ATTR_LIST:
        snprintf(service, srvlen, "SetAttributeList");
        break;
    case CIP_RESET:
        snprintf(service, srvlen, "Reset");
        break;
    case CIP_START:
        snprintf(service, srvlen, "Start");
        break;
    case CIP_STOP:
        snprintf(service, srvlen, "Stop");
        break;
    case CIP_CREATE:
        snprintf(service, srvlen, "Create");
        break;
    case CIP_DELETE:
        snprintf(service, srvlen, "Delete");
        break;
    case CIP_MSP:
        snprintf(service, srvlen, "MultipleServicePacket");
        break;
    case CIP_APPLY_ATTR:
        snprintf(service, srvlen, "ApplyAttribute");
        break;
    case CIP_KICK_TIMER:
        snprintf(service, srvlen, "KickTimer");
        break;
    case CIP_OPEN_CONNECTION:
        snprintf(service, srvlen, "OpenConnection");
        break;
    case CIP_CHANGE_START:
        snprintf(service, srvlen, "ChangeStart");
        break;
    case CIP_GET_STATUS:
        snprintf(service, srvlen, "GetStatus");
        break;
    case CIP_GET_ATTR_SINGLE:
        snprintf(service, srvlen, "GetAttributeSingle");
        break;
    case CIP_SET_ATTR_SINGLE:
        snprintf(service, srvlen, "SetAttributeSingle");
        break;
    case CIP_FORWARD_OPEN:
        snprintf(service, srvlen, "ForwardOpen");
        break;
    case CIP_FORWARD_CLOSE:
        snprintf(service, srvlen, "ForwardClose");
        break;
    case CIP_UNCONNECTED_SEND:
        snprintf(service, srvlen, "UnconnectedSend");
        break;
    default:
        PRINT_INFO_HEAD
        print_info("CIP SERVICE 0x%x", m_pciprequestheader->service);
        return false;
    }

    SCLogDebug("service %s", service);
    return true;
}

/**
 * [CIPParser::get_pointtype 获取测点数据类型]
 * @return  [数据类型]
 */
PointType CIPParser::get_pointtype(void)
{
    PointType t = POINT_UNKNOWN;
    if (m_action == CIPWriteAction) {
        if (m_ptypevalue != NULL) {
            return (PointType)m_ptypevalue->type;
        }
    }
    return t;
}

/**
 *  获取int型测点的值
 */
vector<int> CIPParser::get_vecint(void)
{
    return m_vecint;
}

/**
 *  获取浮点型测点的值
 */
vector<float> CIPParser::get_vecfloat(void)
{
    return m_vecfloat;
}

/**
 *  获取布尔类型的测点的值
 */
vector<int> CIPParser::get_vecbool(void)
{
    return m_vecbool;
}

/**
 * [CIPParser::parser 解析]
 * @param  sdata [应用层开始的数据]
 * @param  slen  [长度]
 * @return       [解析成功返回true 失败返回false.  只解析成功一部分也认为成功了]
 */
bool CIPParser::parser(unsigned char *sdata, int slen)
{
    if (slen < sizeof(EncapsulationHeader)) {
        PRINT_INFO_HEAD
        print_info("too short %d", slen);
        return false;
    }
    clear();
    m_pheader = (PEncapsulationHeader)(sdata);
    SCLogDebug("Command:0x%04x", m_pheader->command);
    SCLogDebug("Length:%d", m_pheader->length);
    SCLogDebug("Session Handle:0x%08x", m_pheader->sesionhandle);
    SCLogDebug("Status:0x%08x", m_pheader->status);
    SCLogDebug("Sender Context:0x%016llx", m_pheader->sendercontext);
    SCLogDebug("Options:0x%08x", m_pheader->options);
    parser_more(sdata, slen);//进一步解析更详细的数据
    return true;
}

/**
 * [CIPParser::parser_more 使用开源程序进一步解析]
 * @param  input [应用层数据]
 * @param  input_len  [长度]
 */
void CIPParser::parser_more(unsigned char *input, int input_len)
{
    switch (m_pheader->command) {
    case NOP:
        SCLogDebug("DecodeENIP - NOP");
        break;
    case LIST_SERVICES:
        SCLogDebug("DecodeENIP - LIST_SERVICES");
        break;
    case LIST_IDENTITY:
        SCLogDebug("DecodeENIP - LIST_IDENTITY");
        break;
    case LIST_INTERFACES:
        SCLogDebug("DecodeENIP - LIST_INTERFACES");
        break;
    case REGISTER_SESSION:
        SCLogDebug("DecodeENIP - REGISTER_SESSION");
        DecodeReqisterSession(input, input_len, sizeof(EncapsulationHeader));
        break;
    case UNREGISTER_SESSION:
        SCLogDebug("DecodeENIP - UNREGISTER_SESSION");
        break;
    case SEND_RR_DATA:
        SCLogDebug("DecodeENIP - SEND_RR_DATA");
        DecodeCommonPacketFormatPDU(input, input_len, sizeof(EncapsulationHeader));
        break;
    case SEND_UNIT_DATA:
        SCLogDebug("DecodeENIP - SEND UNIT DATA");
        DecodeCommonPacketFormatPDU(input, input_len, sizeof(EncapsulationHeader));
        break;
    case INDICATE_STATUS:
        SCLogDebug("DecodeENIP - INDICATE_STATUS");
        break;
    case CANCEL:
        SCLogDebug("DecodeENIP - CANCEL");
        break;
    default:
        SCLogDebug("DecodeENIP - UNSUPPORTED COMMAND 0x%x", m_pheader->command);
    }
    return;
}

/**
 * [CIPParser::DecodeReqisterSession 解析发起会话请求]
 * @param input      [应用层数据]
 * @param  input_len  [长度]
 * @param  offset_len  [偏移长度]
 */
void CIPParser::DecodeReqisterSession(unsigned char *input, int input_len, int offset_len)
{
    if (m_pheader->length != 4) {
        PRINT_ERR_HEAD
        print_err("length %d", m_pheader->length);
        return;
    }

    if (input_len >= offset_len + m_pheader->length) {
        uint16 version;
        memcpy(&version, input + offset_len, sizeof(version));
        if (version == 1) {
            SCLogDebug("protocol version:%d", version);
        } else {
            PRINT_ERR_HEAD
            print_err("protocol version:%d", version);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("input_len %d, less than %d", input_len, offset_len + m_pheader->length);
    }
}

/**
 * [CIPParser::DecodeCommonPacketFormatPDU 解析伪装头部之后的内容]
 * @param  input [应用层数据]
 * @param  input_len  [长度]
 * @param  offset_len  [偏移长度]
 */
void CIPParser::DecodeCommonPacketFormatPDU(unsigned char *input, int input_len, int offset_len)
{
    if (m_pheader->length < sizeof(ENIPEncapDataHdr)) {
        SCLogDebug("DecodeCommonPacketFormat: Malformed ENIP packet");
        return;
    }

    m_pdataheader = (PENIPEncapDataHdr)(input + offset_len);
    offset_len += sizeof(ENIPEncapDataHdr);
    SCLogDebug("Interface handle:0x%08x", m_pdataheader->interface_handle);
    SCLogDebug("Timeout:%d", m_pdataheader->timeout);
    SCLogDebug("Item count:%d", m_pdataheader->item_count);

    //标准要求至少为2
    if (m_pdataheader->item_count < 2) {
        PRINT_ERR_HEAD
        print_err("dataheader item count %d", m_pdataheader->item_count);
        return;
    }

    //拷贝 addritem 信息
    memcpy(&m_addritem.type, input + offset_len, sizeof(m_addritem.type));
    offset_len += sizeof(m_addritem.type);
    SCLogDebug("Type ID:0x%04x", m_addritem.type);

    memcpy(&m_addritem.length, input + offset_len, sizeof(m_addritem.length));
    offset_len += sizeof(m_addritem.length);
    SCLogDebug("Length:%d", m_addritem.length);

    if (m_addritem.type == CONNECTION_BASED) {//连接的地址项目
        // get 4 byte connection id
        memcpy(&m_addritem.conn_id, input + offset_len, sizeof(m_addritem.conn_id));
        offset_len += sizeof(m_addritem.conn_id);
        SCLogDebug("Connection ID:0x%08x", m_addritem.conn_id);
    } else if (m_addritem.type == SEQUENCE_ADDR_ITEM) {//排序的地址项目
        // get 4 byte connection id and 4 byte sequence
        memcpy(&m_addritem.conn_id, input + offset_len, sizeof(m_addritem.conn_id));
        offset_len += sizeof(m_addritem.conn_id);
        SCLogDebug("Connection ID:0x%08x", m_addritem.conn_id);
        memcpy(&m_addritem.sequence_num, input + offset_len, sizeof(m_addritem.sequence_num));
        offset_len += sizeof(m_addritem.sequence_num);
        SCLogDebug("Sequence num:0x%08x", m_addritem.sequence_num);
    } else if (m_addritem.type == NULL_ADDR) {//空地址项目
    } else {
        PRINT_ERR_HEAD
        print_err("addritem type unknown 0x%04x", m_addritem.type );
        return;
    }

    if (offset_len > input_len) {
        PRINT_ERR_HEAD
        print_err("offset_len %d, input_len %d, addritem type %d", offset_len, input_len, m_addritem.type);
        return;
    }

    //拷贝 dataitem 信息
    memcpy(&m_dataitem.type, input + offset_len, sizeof(m_dataitem.type));
    offset_len += sizeof(m_dataitem.type);
    SCLogDebug("Type ID: 0x%04x", m_dataitem.type);
    memcpy(&m_dataitem.length, input + offset_len, sizeof(m_dataitem.length));
    offset_len += sizeof(m_dataitem.length);
    SCLogDebug("Length:%d", m_dataitem.length);
    if (m_dataitem.type == CONNECTED_DATA_ITEM) {//关联的数据项
        memcpy(&m_dataitem.sequence_count, input + offset_len, sizeof(m_dataitem.sequence_count));
        offset_len += sizeof(m_dataitem.sequence_count);
        SCLogDebug("CIP sequence Count:%d", m_dataitem.sequence_count);
    }
    if (offset_len > input_len) {
        PRINT_ERR_HEAD
        print_err("offset_len %d, input_len %d, dataitem type %d", offset_len, input_len, m_dataitem.type);
        return;
    }

    switch (m_dataitem.type) {
    case CONNECTED_DATA_ITEM:
        SCLogDebug("CONNECTED DATA ITEM - parse CIP");
        DecodeCIPPDU(input, input_len, offset_len);
        break;
    case UNCONNECTED_DATA_ITEM:
        SCLogDebug("UNCONNECTED DATA ITEM");
        DecodeCIPPDU(input, input_len, offset_len);
        break;
    default:
        SCLogDebug("UNKNOWN TYPE 0x%04x", m_dataitem.type);
        return;
    }
    return;
}

/**
 * [CIPParser::DecodeCIPPDU 解析CIP内容]
 * @param  input [应用层数据]
 * @param  input_len  [长度]
 * @param  offset_len  [偏移长度]
 */
void CIPParser::DecodeCIPPDU(unsigned char *input, int input_len, int offset_len)
{
    if (m_dataitem.length == 0) {
        SCLogDebug("DecodeCIP: No CIP Data");
        return;
    }

    if (offset_len > (input_len - sizeof(uint8))) {
        SCLogDebug("DecodeCIP: Parsing beyond payload length");
        return;
    }

    uint8 service = 0;
    service = *(input + offset_len);
    //use service code first bit to determine request/response, no need to save or push offset
    if (service >> 7) {
        //对于响应不需要处理
        return;
    }
    SCLogDebug("DecodeCIP: RequestPDU");
    DecodeCIPRequestPDU(input, input_len, offset_len);
    return;
}

/**
 * [CIPParser::DecodeService 根据服务解析更多内容]
 * @param  input [应用层数据]
 * @param  input_len  [长度]
 * @param  offset_len  [偏移长度]
 */
void CIPParser::DecodeService(unsigned char *input, int input_len, int offset_len)
{
    switch (m_pciprequestheader->service) {
    case CIP_RESERVED:
        SCLogDebug("Reserved");
        break;
    case CIP_GET_ATTR_ALL:
        SCLogDebug("GetAttributeAll");
        break;
    case CIP_GET_ATTR_LIST:
        SCLogDebug("GetAttributeList");
        break;
    case CIP_SET_ATTR_LIST:
        SCLogDebug("SetAttributeList");
        break;
    case CIP_RESET:
        SCLogDebug("Reset");
        break;
    case CIP_START:
        SCLogDebug("Start");
        break;
    case CIP_STOP:
        SCLogDebug("Stop");
        break;
    case CIP_CREATE:
        SCLogDebug("Create");
        break;
    case CIP_DELETE:
        SCLogDebug("Delete");
        break;
    case CIP_MSP:
        SCLogDebug("MultipleServicePacket");
        //DecodeCIPRequestMSPPDU(input, input_len, enip_data, offset);
        break;
    case CIP_APPLY_ATTR:
        SCLogDebug("ApplyAttribute");
        break;
    case CIP_KICK_TIMER:
        SCLogDebug("KickTimer");
        break;
    case CIP_OPEN_CONNECTION:
        SCLogDebug("OpenConnection");
        break;
    case CIP_CHANGE_START:
        SCLogDebug("ChangeStart");
        break;
    case CIP_GET_STATUS:
        SCLogDebug("GetStatus");
        break;
    case CIP_GET_ATTR_SINGLE:
        SCLogDebug("GetAttributeSingle");
        break;
    case CIP_SET_ATTR_SINGLE:
        SCLogDebug("SetAttributeSingle");
        break;
    case CIP_FORWARD_OPEN:
        SCLogDebug("ForwardOpen");
        break;
    case CIP_FORWARD_CLOSE:
        SCLogDebug("ForwardClose");
        break;
    case CIP_UNCONNECTED_SEND:
        SCLogDebug("UnconnectedSend");
        DecodeConnectionManager(input, input_len, offset_len);
        break;
    default:
        SCLogDebug("CIP SERVICE 0x%x", m_pciprequestheader->service);
    }
}

/**
 * [CIPParser::DecodeCIPRequestPDU 解析请求类型的CIP内容]
 * @param  input [应用层数据]
 * @param  input_len  [长度]
 * @param  offset_len  [偏移长度]
 */
void CIPParser::DecodeCIPRequestPDU(unsigned char *input, int input_len, int offset_len)
{
    if (m_dataitem.length < sizeof(CIPReqHdr)) {
        SCLogDebug("Malformed CIP Data");
        return;
    }

    m_pciprequestheader = (PCIPReqHdr)(input + offset_len);
    offset_len += sizeof(CIPReqHdr);

    if (m_pciprequestheader->service > MAX_CIP_SERVICE) {
        // service codes of value 0x80 or greater are not permitted because in the CIP protocol
        // the highest order bit is used to flag request(0)/response(1)
        SCLogDebug("INVALID CIP SERVICE 0x%x", m_pciprequestheader->service);
        return;
    }

    DecodeCIPRequestPathPDU(input, input_len, offset_len);
    offset_len += m_pciprequestheader->path_size * sizeof(uint16);
    DecodeService(input, input_len, offset_len);
}

/**
 * [CIPParser::DecodeCIPRequestPathPDU 解析请求类型的CIP Path内容]
 * @param  input [应用层数据]
 * @param  input_len  [长度]
 * @param  offset_len  [偏移长度]
 */
void CIPParser::DecodeCIPRequestPathPDU(unsigned char *input, int input_len, int offset_len)
{
    if (m_pciprequestheader->path_size < 1) {
        SCLogDebug("empty path or CIP Response");
        return;
    }

    int bytes_remain = m_pciprequestheader->path_size;
    SCLogDebug("path size: %d", m_pciprequestheader->path_size);

    while (bytes_remain > 0) {
        uint8 segment = 0;
        segment = input[offset_len];
        offset_len++;
        if (offset_len >= input_len) {
            PRINT_ERR_HEAD
            print_err("offset_len %d, input_len %d", offset_len, input_len);
            return;
        }

        switch (segment) {
        //assume order is class then instance.  Can have multiple
        case PATH_CLASS_8BIT: {
            uint8 req_path_class8 = 0;
            req_path_class8 = input[offset_len];
            offset_len++;
            SCLogDebug("8bit class 0x%02x", req_path_class8);
            SegmentEntry se;
            se.segment = segment;
            se.value = req_path_class8;
            m_segentry.push_back(se);
            bytes_remain--;
            break;
        }
        case PATH_INSTANCE_8BIT: {
            uint8 req_path_instance8;
            req_path_instance8 = input[offset_len];
            offset_len++;
            SCLogDebug("8bit instence 0x%02x", req_path_instance8);
            //skip instance, don't need to store
            bytes_remain--;
            break;
        }
        case PATH_ATTR_8BIT: { //single attribute
            uint8 req_path_attr8;
            req_path_attr8 = input[offset_len];
            offset_len++;
            SCLogDebug("8bit attr 0x%02x", req_path_attr8);
            SegmentEntry se;
            se.segment = segment;
            se.value = req_path_attr8;
            m_segentry.push_back(se);
            bytes_remain--;
            break;
        }
        case PATH_CLASS_16BIT: {
            uint8 reserved; //unused byte reserved by ODVA
            uint16 req_path_class16;
            reserved = input[offset_len];
            offset_len++;
            memcpy(&req_path_class16, input + offset_len, sizeof(req_path_class16));
            offset_len += sizeof(req_path_class16);
            SCLogDebug("16bit class 0x%04x", req_path_class16);
            SegmentEntry se;
            se.segment = segment;
            se.value = req_path_class16;
            m_segentry.push_back(se);
            if (bytes_remain >= 2) {
                bytes_remain = bytes_remain - 2;
            } else {
                bytes_remain = 0;
            }
            break;
        }
        case PATH_INSTANCE_16BIT: {
            uint8 reserved; //unused byte reserved by ODVA
            uint16 req_path_instance16;
            reserved = input[offset_len];
            offset_len++;
            memcpy(&req_path_instance16, input + offset_len, sizeof(req_path_instance16));
            offset_len += sizeof(req_path_instance16);
            SCLogDebug("16bit instance 0x%04x", req_path_instance16);
            //skip instance, don't need to store
            if (bytes_remain >= 2) {
                bytes_remain = bytes_remain - 2;
            } else {
                bytes_remain = 0;
            }
            break;
        }
        default:
            PRINT_ERR_HEAD
            print_err("UNKNOWN SEGMENT 0x%x service 0x%x", segment, m_pciprequestheader->service);
            return;
        }
    }

    if ((m_pciprequestheader->service == CIP_SET_ATTR_LIST)
        || (m_pciprequestheader->service == CIP_GET_ATTR_LIST)) {
        uint16 attr_list_count;

        memcpy(&attr_list_count, input + offset_len, sizeof(attr_list_count));
        offset_len += sizeof(attr_list_count);
        SCLogDebug("attribute list count %d", attr_list_count);
        if (offset_len + attr_list_count * sizeof(AttributeEntry) == input_len) {
            for (int i = 0; i < attr_list_count; i++) {
                uint16 attribute;
                memcpy(&attribute, input + offset_len, sizeof(attribute));
                offset_len += sizeof(attribute);
                SCLogDebug("attribute %d", attribute);
                AttributeEntry at;
                at.attribute = attribute;
                m_attrentry.push_back(at);
            }
        } else {
            PRINT_ERR_HEAD
            print_err("offset_len %d, attr_list_count %d, input_len %d",
                      offset_len, attr_list_count, input_len);
        }
    }
}

/**
 * [CIPParser::DecodeConnectionManager 解析ConnectionManager]
 * @param  input [应用层数据]
 * @param  input_len  [长度]
 * @param  offset_len  [偏移长度]
 */
void CIPParser::DecodeConnectionManager(unsigned char *input, int input_len, int offset_len)
{
    if ((m_segentry.size() == 0)
        || (m_segentry[0].segment != PATH_CLASS_8BIT)
        || (m_segentry[0].value != CLASS_CONNECTION_MANAGER)
        || (offset_len + sizeof(CIPConnectionManagerHdr) > input_len)) {
        return;
    }
    m_pconnmanhdr = (PCIPConnectionManagerHdr)(input + offset_len);
    if (m_pconnmanhdr->service == CIP_MSP) {
        DecodeConnectionManagerMSP(input, input_len, offset_len);
        return;
    }
    SCLogDebug("ticktime:%d", m_pconnmanhdr->ticktime);
    SCLogDebug("timeoutticks:%d", m_pconnmanhdr->timeoutticks);
    SCLogDebug("requestsize:%d", m_pconnmanhdr->requestsize);
    SCLogDebug("service:0x%02x", m_pconnmanhdr->service);
    SCLogDebug("pathsize:%d", m_pconnmanhdr->pathsize);
    SCLogDebug("segmenttype:0x%02x", m_pconnmanhdr->segmenttype);
    SCLogDebug("datasize:%d", m_pconnmanhdr->datasize);
    offset_len += sizeof(CIPConnectionManagerHdr);

    if ((m_pconnmanhdr->service != CONNECTION_MANAGER_READ)
        && (m_pconnmanhdr->service != CONNECTION_MANAGER_WRITE)) {
        PRINT_INFO_HEAD
        print_info("not read or write service 0x%02x", m_pconnmanhdr->service);
        return;
    }

    if (m_pconnmanhdr->segmenttype != ANSI_SEGMENT_TYPE) {
        PRINT_INFO_HEAD
        print_info("not ansi segment type 0x%02x", m_pconnmanhdr->segmenttype);
        return;
    }

    if ((m_pconnmanhdr->datasize <= 0)
        || (m_pconnmanhdr->pathsize * sizeof(uint16) < m_pconnmanhdr->datasize + 2)) {
        PRINT_INFO_HEAD
        print_info("pathsize[%d] or datasize[%d] error", m_pconnmanhdr->pathsize, m_pconnmanhdr->datasize);
        return;
    }

    if (offset_len + CIP_ODD_NUMBER(m_pconnmanhdr->datasize) > input_len) {
        PRINT_INFO_HEAD
        print_info("offset_len[%d] input_len[%d] return",
                   offset_len + CIP_ODD_NUMBER(m_pconnmanhdr->datasize), input_len);
        return;
    }

    if (m_pconnmanhdr->datasize > sizeof(m_pointname) - 1) {
        memcpy(m_pointname, input + offset_len, sizeof(m_pointname) - 1);
        PRINT_INFO_HEAD
        print_info("pointname too long cut it.[%d][%s]", m_pconnmanhdr->datasize, m_pointname);
    } else {
        memcpy(m_pointname, input + offset_len, m_pconnmanhdr->datasize);
        SCLogDebug("pointname:%s", m_pointname);
    }
    offset_len += CIP_ODD_NUMBER(m_pconnmanhdr->datasize);

    if (m_pconnmanhdr->service == CONNECTION_MANAGER_READ) {
        m_action = CIPReadAction;
        return;
    }
    m_action = CIPWriteAction;
    int specificdata_len = m_pconnmanhdr->requestsize
                           - m_pconnmanhdr->pathsize * sizeof(uint16)
                           - sizeof(m_pconnmanhdr->service)
                           - sizeof(m_pconnmanhdr->pathsize);
    if (specificdata_len > sizeof(PointTypeValue)) {
        GetTypeValue(input, input_len, offset_len);
    }
}

/**
 * [CIPParser::DecodeConnectionManagerMSP 解析MSP服务类型的ConnectionManager]
 * @param  input [应用层数据]
 * @param  input_len  [长度]
 * @param  offset_len  [偏移长度]
 */
void CIPParser::DecodeConnectionManagerMSP(unsigned char *input, int input_len, int offset_len)
{
    m_pconnmanmsphdr = (PCIPConnectionManagerMSPHdr)(input + offset_len);
    SCLogDebug("ticktime:%d", m_pconnmanmsphdr->ticktime);
    SCLogDebug("timeoutticks:%d", m_pconnmanmsphdr->timeoutticks);
    SCLogDebug("requestsize:%d", m_pconnmanmsphdr->requestsize);
    SCLogDebug("service:0x%02x", m_pconnmanmsphdr->service);
    SCLogDebug("pathsize:%d", m_pconnmanmsphdr->pathsize);
    SCLogDebug("segmenttype1:0x%02x", m_pconnmanmsphdr->segmenttype1);
    SCLogDebug("classtype1:0x%02x", m_pconnmanmsphdr->classtype1);
    SCLogDebug("segmenttype2:0x%02x", m_pconnmanmsphdr->segmenttype2);
    SCLogDebug("instance:0x%02x", m_pconnmanmsphdr->instance);
    SCLogDebug("servicenum:%d", m_pconnmanmsphdr->servicenum);
    offset_len += sizeof(CIPConnectionManagerMSPHdr);
    offset_len += m_pconnmanmsphdr->servicenum * 2;

    PServicePacketHdr phdr = (PServicePacketHdr)(input + offset_len);
    SCLogDebug("service:0x%02x", phdr->service);
    SCLogDebug("pathsize:0x%02x", phdr->pathsize);
    SCLogDebug("segmenttype:0x%02x", phdr->segmenttype);
    SCLogDebug("datasize:0x%02x", phdr->datasize);
    offset_len += sizeof(ServicePacketHdr);

    if ((phdr->service != CONNECTION_MANAGER_READ) && (phdr->service != CONNECTION_MANAGER_WRITE)) {
        PRINT_INFO_HEAD
        print_info("neither read nor write service 0x%02x", phdr->service);
        return;
    }

    if (phdr->segmenttype != ANSI_SEGMENT_TYPE) {
        PRINT_INFO_HEAD
        print_info("not ansi segment type 0x%02x", phdr->segmenttype);
        return;
    }

    if ((phdr->datasize <= 0) || (phdr->pathsize * sizeof(uint16) < phdr->datasize + 2)) {
        PRINT_INFO_HEAD
        print_info("pathsize[%d] or datasize[%d] error", phdr->pathsize, phdr->datasize);
        return;
    }

    if (offset_len + CIP_ODD_NUMBER(phdr->datasize) > input_len) {
        PRINT_INFO_HEAD
        print_info("offset_len[%d] input_len[%d] return",
                   offset_len + CIP_ODD_NUMBER(phdr->datasize), input_len);
        return;
    }

    if (phdr->datasize > sizeof(m_pointname) - 1) {
        memcpy(m_pointname, input + offset_len, sizeof(m_pointname) - 1);
        PRINT_INFO_HEAD
        print_info("pointname too long cut it.[%d][%s]", phdr->datasize, m_pointname);
    } else {
        memcpy(m_pointname, input + offset_len, phdr->datasize);
        SCLogDebug("pointname:%s", m_pointname);
    }
    offset_len += CIP_ODD_NUMBER(phdr->datasize);

    if (phdr->service == CONNECTION_MANAGER_READ) {
        m_action = CIPReadAction;
        return;
    }
    m_action = CIPWriteAction;
    offset_len += 2;//8bit member segment
    GetTypeValue(input, input_len, offset_len);
}

/**
 * [CIPParser::GetTypeValue 获取测点类型和数值]
 * @param  input [应用层数据]
 * @param  input_len  [长度]
 * @param  offset_len  [偏移长度]
 */
void CIPParser::GetTypeValue(unsigned char *input, int input_len, int offset_len)
{
    m_ptypevalue = (PPointTypeValue)(input + offset_len);
    SCLogDebug("datatype:0x%04x", m_ptypevalue->type);
    SCLogDebug("num:%d", m_ptypevalue->num);
    switch (m_ptypevalue->type) {
    case POINT_INT: {
        uint16 tempint;
        for (int i = 0; i < m_ptypevalue->num; ++i) {
            memcpy(&tempint, m_ptypevalue->ch + i * 2, 2);
            m_vecint.push_back(tempint);
            SCLogDebug("value int: %d", tempint);
        }
        break;
    }
    case POINT_FLOAT: {
        float tempfloat;
        for (int i = 0; i < m_ptypevalue->num; ++i) {
            memcpy(&tempfloat, m_ptypevalue->ch + i * 4, 4);
            m_vecfloat.push_back(tempfloat);
            SCLogDebug("value float: %f", tempfloat);
        }
        break;
    }
    case POINT_BOOL: {
        uint16 tempbool;
        for (int i = 0; i < m_ptypevalue->num; ++i) {
            memcpy(&tempbool, m_ptypevalue->ch + i * 2, 2);
            m_vecbool.push_back(tempbool);
            SCLogDebug("value bool: %d", tempbool);
        }
        break;
    }
    }
}
