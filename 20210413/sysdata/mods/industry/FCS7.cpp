/*******************************************************************************************
*文  件:  FCS7.cpp
*描  述:  S7模块
*作  者:  王君雷
*日  期:  2017-12-12
*修  改:
*         完善命令过滤                                                ------> 2017-12-18 王君雷
*         拼包按第一个完整的信令来处理                                ------> 2019-12-24 wjl
*******************************************************************************************/
#include "FCS7.h"
#include "debugout.h"
#include <arpa/inet.h>

#define TPKT_PACKET_COMPLETE 0  //完整包
#define TPKT_PACKET_PARTIAL  -1 //部分包
#define TPKT_PACKET_MUTIPLE  -2 //黏连包

#define COTP_MIN_SIZE      (3)    //COTP len
#define TPKT_HEADER_SIZE   (4)    //TPKT len
#define S7COMM_PROTOCOL_ID (0x32) //S7comm protocol_id

//PDU types. 目前只控制这4种类型的PDU，程序解析协议使用，界面上不配置
#define S7COMM_ROSCTR_JOB                   (1)//(0x01)
#define S7COMM_ROSCTR_ACK                   (2)//(0x02)
#define S7COMM_ROSCTR_ACK_DATA              (3)//(0x03)
#define S7COMM_ROSCTR_USERDATA              (7)//(0x07)

typedef struct _S7commfuncmap {
    unsigned char func;
    char *name;
    int rw;
} S7COMMFUNCMAP, *PS7COMMFUNCMAP;

//-------------------------------------------------------------命令----
// Function codes in parameter part
#define S7COMM_SERV_CPU                     (0)  //(0x00)
#define S7COMM_SERV_SETUPCOMM               (240)//(0xF0)
#define S7COMM_SERV_READVAR                 (4)  //(0x04)
#define S7COMM_SERV_WRITEVAR                (5)  //(0x05)
#define S7COMM_FUNC_REQUESTDOWNLOAD         (26) //(0x1A)
#define S7COMM_FUNC_DOWNLOADBLOCK           (27) //(0x1B)
#define S7COMM_FUNC_DOWNLOADENDED           (28) //(0x1C)
#define S7COMM_FUNC_STARTUPLOAD             (29) //(0x1D)
#define S7COMM_FUNC_UPLOAD                  (30) //(0x1E)
#define S7COMM_FUNC_ENDUPLOAD               (31) //(0x1F)
#define S7COMM_FUNC_PISERVICE               (40) //(0x28)
#define S7COMM_FUNC_PLCSTOP                 (41) //(0x29)

const S7COMMFUNCMAP g_S7FuncMap[] = {
    { S7COMM_SERV_CPU,             "CPU_services"       , PROTO_RWNULL},
    { S7COMM_SERV_SETUPCOMM,       "Setup_communication", PROTO_WRITE},
    { S7COMM_SERV_READVAR,         "Read_Var"           , PROTO_READ},
    { S7COMM_SERV_WRITEVAR,        "Write_Var"          , PROTO_WRITE},
    { S7COMM_FUNC_REQUESTDOWNLOAD, "Request_download"   , PROTO_WRITE},
    { S7COMM_FUNC_DOWNLOADBLOCK,   "Download_block"     , PROTO_WRITE},
    { S7COMM_FUNC_DOWNLOADENDED,   "Download_ended"     , PROTO_WRITE},
    { S7COMM_FUNC_STARTUPLOAD,     "Start_upload"       , PROTO_RWNULL},
    { S7COMM_FUNC_UPLOAD,          "Upload"             , PROTO_RWNULL},
    { S7COMM_FUNC_ENDUPLOAD,       "End_upload"         , PROTO_RWNULL},
    { S7COMM_FUNC_PISERVICE,       "PI_Service"         , PROTO_RWNULL},
    { S7COMM_FUNC_PLCSTOP,         "PLC_Stop"           , PROTO_WRITE}
};

// Function codes in parameter part （PDU为USERDATA类型时的命令）
#define PUSH_TYPE     (0)
#define REQUEST_TYPE  (4)
#define RESPONSE_TYPE (8)
const S7COMMFUNCMAP g_S7UserDataMap[] = {
    { PUSH_TYPE,     "Push"    , PROTO_RWNULL},
    { REQUEST_TYPE,  "Request" , PROTO_RWNULL},
    { RESPONSE_TYPE, "Response", PROTO_RWNULL}
};

//------------------------------------------------------------------参数------
//Names of Function groups in userdata parameter part
#define S7COMM_UD_FUNCGROUP_MODETRANS       (0x0)
#define S7COMM_UD_FUNCGROUP_PROG            (0x1)
#define S7COMM_UD_FUNCGROUP_CYCLIC          (0x2)
#define S7COMM_UD_FUNCGROUP_BLOCK           (0x3)
#define S7COMM_UD_FUNCGROUP_CPU             (0x4)
#define S7COMM_UD_FUNCGROUP_SEC             (0x5)    //Security functions e.g. plc password
#define S7COMM_UD_FUNCGROUP_PBC             (0x6)    // PBC = Programmable Block Communication (PBK in german)
#define S7COMM_UD_FUNCGROUP_TIME            (0x7)
#define S7COMM_UD_FUNCGROUP_NCPRG           (0xf)

const S7COMMFUNCMAP g_S7FuncGroupMap[] = {
    { S7COMM_UD_FUNCGROUP_MODETRANS,        "Mode_transition"    , PROTO_RWNULL},
    { S7COMM_UD_FUNCGROUP_PROG,             "Programmer_commands", PROTO_RWNULL},
    { S7COMM_UD_FUNCGROUP_CYCLIC,           "Cyclic_data"        , PROTO_READ},// to read data from plc without a request
    { S7COMM_UD_FUNCGROUP_BLOCK,            "Block_functions"    , PROTO_RWNULL},
    { S7COMM_UD_FUNCGROUP_CPU,              "CPU_functions"      , PROTO_RWNULL},
    { S7COMM_UD_FUNCGROUP_SEC,              "Security"           , PROTO_RWNULL},
    { S7COMM_UD_FUNCGROUP_PBC,              "PBC_BSEND/BRECV"    , PROTO_RW},
    { S7COMM_UD_FUNCGROUP_TIME,             "Time_functions"     , PROTO_RWNULL},
    { S7COMM_UD_FUNCGROUP_NCPRG,            "NC_programming"     , PROTO_WRITE},
};

//--------------------------------------------------------------------附件参数-
//subfunc map struct
typedef struct _S7commsubfuncmap {
    unsigned char funcgrp;
    unsigned char subfunc;
    char *funcgrpname;
    char *subfuncname;
    int rw;
} S7COMMSUBFUNCMAP, *PS7COMMSUBFUNCMAP;

//sub Function part
#define PC_VARTAB           (2)
#define PC_READDIAGDATA     (14)
#define BF_LISTBLOCKS       (1)
#define BF_LISTBLOCKSOfTYPE (2)
#define BF_GETBLOCKINFO     (3)
#define CF_READSZL          (1)
#define CF_SYSTEMSTATE      (2)
#define TF_READCLOCK        (1)
#define TF_SETCLOCK         (2)
#define CD_MEMORY           (1)

//sub Function part
const S7COMMSUBFUNCMAP g_S7SubFuncMap[] = {
    { S7COMM_UD_FUNCGROUP_PROG,   PC_VARTAB,           "Programmer_commands", "VarTab"             , PROTO_RWNULL},
    { S7COMM_UD_FUNCGROUP_PROG,   PC_READDIAGDATA,     "Programmer_commands", "Read_diag_data"     , PROTO_READ},
    { S7COMM_UD_FUNCGROUP_BLOCK,  BF_LISTBLOCKS,       "Block_functions",     "List_blocks"        , PROTO_READ},
    { S7COMM_UD_FUNCGROUP_BLOCK,  BF_LISTBLOCKSOfTYPE, "Block_functions",     "List_blocks_of_type", PROTO_READ},
    { S7COMM_UD_FUNCGROUP_BLOCK,  BF_GETBLOCKINFO,     "Block_functions",     "Get_block_info"     , PROTO_READ},
    { S7COMM_UD_FUNCGROUP_CPU,    CF_READSZL,          "CPU_functions",       "Read_SZL"           , PROTO_READ},
    { S7COMM_UD_FUNCGROUP_CPU,    CF_SYSTEMSTATE,      "CPU_functions",       "System_state"       , PROTO_READ},
    { S7COMM_UD_FUNCGROUP_TIME,   TF_READCLOCK,        "Time_functions",      "Read_Clock"         , PROTO_READ},
    { S7COMM_UD_FUNCGROUP_TIME,   TF_SETCLOCK,         "Time_functions",      "Set_Clock"          , PROTO_WRITE},
    { S7COMM_UD_FUNCGROUP_CYCLIC, CD_MEMORY,           "Cyclic_data",         "Memory"             , PROTO_READ}
};

CS7::CS7(void)
{
    m_pdu_type = -1;
    m_rw = PROTO_RWNULL;
    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));
    memset(m_chpara2, 0, sizeof(m_chpara2));
}

CS7::~CS7(void)
{
}

bool CS7::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        //return DoDstMsg(sdata, slen, cherror);
        return DoSrcMsg(sdata, slen, cherror);
    }
}

bool CS7::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;
    if (datalen <= 0) {
        return true;
    }

    bool result = true;
    char tmpcmd[MAX_CMD_NAME_LEN] = {0};
    char tmppara[MAX_PARA_NAME_LEN] = {0};

    if (datalen > (TPKT_HEADER_SIZE + COTP_MIN_SIZE)) {
        if (DecodeRequest(sdata + hdlen, slen - hdlen)) {
            MakeString(tmpcmd, sizeof(tmpcmd), tmppara, sizeof(tmppara));
            if (FilterCode(cherror)) {
                RecordCallLog(sdata, tmpcmd, tmppara, cherror, true);
                result = true;
            } else {
                RecordCallLog(sdata, tmpcmd, tmppara, cherror, false);
                result = false;
                PRINT_ERR_HEAD
                print_err("s7 command not allow to pass[%s][%s]", tmpcmd, tmppara);
            }
        } else {
            PRINT_INFO_HEAD
            print_info("datalen %d decode request fail,pass", datalen);
        }
    } else {
        PRINT_INFO_HEAD
        print_info("datalen[%d] too short, less then %d,pass", datalen, TPKT_HEADER_SIZE + COTP_MIN_SIZE);
    }
    return result;
}

bool CS7::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/*******************************************************************************************
*功  能:  检查TPKT
*参  数:
*         sdata      应用层数据
*         slen       应用层数据长度
*返回值:  TPKT_PACKET_COMPLETE 是完整包
*         TPKT_PACKET_PARTIAL  是部分包
*         TPKT_PACKET_MUTIPLE  是连包
*******************************************************************************************/
int CS7::CheckTpkt(unsigned char *sdata, int slen)
{
    int data_len = sdata[2] * 256 + sdata[3];
    if (data_len == slen) {
        return TPKT_PACKET_COMPLETE;
    } else if (data_len > slen) {
        PRINT_INFO_HEAD
        print_info("find partial packet.datalen[%d] slen[%d]", data_len, slen);
        return TPKT_PACKET_PARTIAL;
    } else {
        PRINT_INFO_HEAD
        print_info("find mutiple packet.datalen[%d] slen[%d]", data_len, slen);
        return TPKT_PACKET_MUTIPLE;
    }
}

/*******************************************************************************************
*功  能:  解析数据包，把要过滤的信息都保存到成员变量
*参  数:
*         sdata      应用层数据
*         slen       应用层数据长度
*返回值:  true   解析成功
*******************************************************************************************/
bool CS7::DecodeRequest(unsigned char *sdata, int slen)
{
    int ret = CheckTpkt(sdata, slen);
    if (TPKT_PACKET_PARTIAL == ret) { //是部分包
        PRINT_INFO_HEAD
        print_info("checktptk find partial packet.%d\n", slen);
        return false;
    }

    //目前只处理cotp部分length为2的情况
    if (2 != sdata[TPKT_HEADER_SIZE]) {
        PRINT_ERR_HEAD
        print_err("cotp length not 2.[%d]", sdata[TPKT_HEADER_SIZE]);
        return false;
    }

    //把包含要过滤内容的数据拷贝到结构体变量
    S7COMMSTATE tmp_state;
    int offset = TPKT_HEADER_SIZE + COTP_MIN_SIZE;
    memset(&tmp_state, 0, sizeof(tmp_state));
    if (slen - offset > (int)sizeof(tmp_state)) {
        memcpy(&tmp_state, sdata + offset, sizeof(tmp_state));
    } else {
        memcpy(&tmp_state, sdata + offset, slen - offset);
    }

    //检查协议号是否正确
    if (S7COMM_PROTOCOL_ID != tmp_state.protocol_id) {
        PRINT_ERR_HEAD
        print_err("s7 protocol id fail[%d]", tmp_state.protocol_id);
        return false;
    }

    //检查PDU类型
    if (!CheckPduType(tmp_state.rosctr)) {
        PRINT_ERR_HEAD
        print_err("rosctr is [%d],pass", tmp_state.rosctr);
        return false;
    }
    m_pdu_type = tmp_state.rosctr;
    m_rw = PROTO_RWNULL;
    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));
    memset(m_chpara2, 0, sizeof(m_chpara2));

    //检查s7报文的长度是否与报文中描述的长度一致
    if ((slen - offset) <
        (int)(offsetof(S7COMMSTATE, PARM) + ntohs(tmp_state.para_len) + ntohs(tmp_state.data_len))) {
        PRINT_ERR_HEAD
        print_err("slen is [%d],offset is [%d],protolen is [%u],pass", slen, offset,
                  (offsetof(S7COMMSTATE, PARM) + ntohs(tmp_state.para_len) + ntohs(tmp_state.data_len)));
        return false;
    }

    if (m_pdu_type == S7COMM_ROSCTR_JOB) {
        //对于PDU为JOB类型的，只需要去解析出命令
        return GetOnlyCmd(tmp_state.PARM.JOB.job_func);
    } else if ((m_pdu_type == S7COMM_ROSCTR_ACK)
               || (m_pdu_type == S7COMM_ROSCTR_ACK_DATA)) {
        //对于PDU为ACK 或 ACK_DATA类型的，只需要去解析出命令
        return GetOnlyCmd(tmp_state.PARM.S7ACK.ack_func);
    } else if (m_pdu_type == S7COMM_ROSCTR_USERDATA) {
        //对于PDU为USERDATA类型的，需要去解析出 <类型 功能组 子功能>
        return GetUserDataInfo(tmp_state.PARM.USERDATA.type, tmp_state.PARM.USERDATA.sub_func);
    }

    PRINT_ERR_HEAD
    print_err("decode request fail.m_pdu_type is [%d],pass", m_pdu_type);
    return false;
}

/*******************************************************************************************
*功  能:  过滤命令
*参  数:
*返回值:  true   允许通过
*******************************************************************************************/
bool CS7::FilterCode(char *cherror)
{
    bool result = m_service->m_IfExec;
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        //匹配命令
        if (MatchCode(m_service->m_cmd[i]->m_cmd)) {
            //匹配参数
            if (MatchPara(m_service->m_cmd[i]->m_parameter)) {
                //匹配附加参数
                if (MatchPara2(m_service->m_cmd[i]->m_sign)) {
                    result = m_service->m_cmd[i]->m_action;
                    break;
                }
            }
        }
    }

    if (!result) {
        sprintf(cherror, "%s", S7_PERM_FORBID);
    }
    return result;
}

/*******************************************************************************************
*功  能:  检查roctr
*参  数:  ch      ------> PDU类型对应的值
*返回值:  true   检查通过
*******************************************************************************************/
bool CS7::CheckPduType(unsigned char ch)
{
    if ((ch == S7COMM_ROSCTR_JOB)
        || (ch == S7COMM_ROSCTR_ACK)
        || (ch == S7COMM_ROSCTR_ACK_DATA)
        || (ch == S7COMM_ROSCTR_USERDATA)) {
        return true;
    }

    PRINT_ERR_HEAD
    print_err("pdutype unknown[%d]", ch);
    return false;
}

/*******************************************************************************************
*功  能:  解析命令,只有命令  没有更多参数的数据包
*参  数:  ch      ------> 命令对应的协议的值
*返回值:  true    解析成功
*******************************************************************************************/
bool CS7::GetOnlyCmd(unsigned char ch)
{
    for (int i = 0; i < (int)(sizeof(g_S7FuncMap) / sizeof(g_S7FuncMap[0])); i++) {
        if (ch == g_S7FuncMap[i].func) {
            if (strlen(g_S7FuncMap[i].name) < sizeof(m_chcmd)) {
                strcpy(m_chcmd, g_S7FuncMap[i].name);
            } else {
                PRINT_ERR_HEAD
                print_err("s7 name too long[%s] cut it,max support[%d]", g_S7FuncMap[i].name, sizeof(m_chcmd) - 1);
                memcpy(m_chcmd, g_S7FuncMap[i].name, sizeof(m_chcmd) - 1);
            }
            m_rw = g_S7FuncMap[i].rw;
            PRINT_DBG_HEAD
            print_dbg("cmd is[%s] rw is[%d]", m_chcmd, m_rw);
            return true;
        }
    }
    PRINT_ERR_HEAD
    print_err("get only cmd,can not find cmd[%d]", ch);
    return false;
}

/*******************************************************************************************
*功  能:  PDU类型为USERDATA类型时，解析出 <类型 功能组 子功能>，保存到成员变量中
*参  数:  type     ------> 高4位是类型，低4位是function group
*         sub_func ------> 子功能
*返回值:  true   解析成功
*******************************************************************************************/
bool CS7::GetUserDataInfo(unsigned char type, unsigned char sub_func)
{
    char realtype = ((type >> 4) & 0x0F);
    char funcgroup = (type & 0x0F);

    //依次获取 <类型 功能组 子功能>
    if (GetUserDataType(realtype) && GetFuncGroup(funcgroup) && GetSubFunc(funcgroup, sub_func)) {
        PRINT_DBG_HEAD
        print_dbg("type[%s] funcgroup[%s] subfun[%s] rw[%d]", m_chcmd, m_chpara, m_chpara2, m_rw);
        return true;
    } else {
        PRINT_ERR_HEAD
        print_err("get user data info fail");
        return false;
    }
}

/*******************************************************************************************
*功  能:  通过参数解析对应的类型描述，保存到成员变量
*参  数:  ch      ------> 类型值
*返回值:  true   解析成功
*******************************************************************************************/
bool CS7::GetUserDataType(unsigned char ch)
{
    for (int i = 0; i < (int)(sizeof(g_S7UserDataMap) / sizeof(g_S7UserDataMap[0])); i++) {
        if (ch == g_S7UserDataMap[i].func) {
            if (strlen(g_S7UserDataMap[i].name) < sizeof(m_chcmd)) {
                strcpy(m_chcmd, g_S7UserDataMap[i].name);
            } else {
                PRINT_ERR_HEAD
                print_err("s7 name too long[%s] cut it,max support[%d]", g_S7UserDataMap[i].name, sizeof(m_chcmd) - 1);
                memcpy(m_chcmd, g_S7UserDataMap[i].name, sizeof(m_chcmd) - 1);
            }
            m_rw = g_S7UserDataMap[i].rw;
            PRINT_DBG_HEAD
            print_dbg("cmd[%s] rw[%d]", m_chcmd, m_rw);
            return true;
        }
    }
    PRINT_ERR_HEAD
    print_err("get user data type fail");
    return false;
}

/*******************************************************************************************
*功  能:  通过参数解析对应的功能组，保存到成员变量
*参  数:  ch      ------> 功能组值
*返回值:  true   解析成功
*******************************************************************************************/
bool CS7::GetFuncGroup(unsigned char ch)
{
    for (int i = 0; i < (int)(sizeof(g_S7FuncGroupMap) / sizeof(g_S7FuncGroupMap[0])); i++) {
        if (ch == g_S7FuncGroupMap[i].func) {
            if (strlen(g_S7FuncGroupMap[i].name) < sizeof(m_chcmd)) {
                strcpy(m_chpara, g_S7FuncGroupMap[i].name);
            } else {
                PRINT_ERR_HEAD
                print_err("s7 name too long[%s] cut it,max support[%d]", g_S7FuncGroupMap[i].name, sizeof(m_chpara) - 1);
                memcpy(m_chpara, g_S7FuncGroupMap[i].name, sizeof(m_chpara) - 1);
            }
            m_rw = g_S7FuncGroupMap[i].rw;
            PRINT_DBG_HEAD
            print_dbg("para[%s] rw[%d]", m_chpara, m_rw);
            return true;
        }
    }
    PRINT_ERR_HEAD
    print_err("get func group fail");
    return false;
}

/*******************************************************************************************
*功  能:  通过参数解析对应的子功能，保存到成员变量
*参  数:  funcgroup ------> 功能组值
*         ch        ------> 子功能值
*返回值:  true   解析成功
*******************************************************************************************/
bool CS7::GetSubFunc(unsigned char funcgroup, unsigned char subfun)
{
    for (int i = 0; i < (int)(sizeof(g_S7SubFuncMap) / sizeof(g_S7SubFuncMap[0])); i++) {
        if ((funcgroup == g_S7SubFuncMap[i].funcgrp) && (subfun == g_S7SubFuncMap[i].subfunc)) {
            if (strlen(g_S7SubFuncMap[i].subfuncname) < sizeof(m_chpara2)) {
                strcpy(m_chpara2, g_S7SubFuncMap[i].subfuncname);
            } else {
                PRINT_ERR_HEAD
                print_err("s7 name too long[%s] cut it,max support[%d]", g_S7SubFuncMap[i].subfuncname, sizeof(m_chpara2) - 1);
            }
            m_rw = g_S7SubFuncMap[i].rw;
            PRINT_DBG_HEAD
            print_dbg("para2[%s] rw[%d]", m_chpara2, m_rw);
            return true;
        }
    }
    //没找到子功能也返回true  因为有些功能组是不对应子功能的
    return true;
}

/*******************************************************************************************
*功能:  匹配命令
*参数:
*       chcmd      前台配置的命令字符串
*注释:  返回值 true匹配   false不匹配
*******************************************************************************************/
bool CS7::MatchCode(const char *chcmd)
{
    if (((strcmp(chcmd, "allread") == 0) && (m_rw == PROTO_READ))
        || ((strcmp(chcmd, "allwrite") == 0) && (m_rw == PROTO_WRITE))) {
        return true;
    }

    return (strcmp(chcmd, m_chcmd) == 0);
}

/*******************************************************************************************
*功能:  匹配参数
*参数:
*       chpara      前台配置的参数字符串
*注释:  返回值 true匹配   false不匹配
*******************************************************************************************/
bool CS7::MatchPara(const char *chpara)
{
    if (chpara[0] == '\0') { //为空匹配所有
        return true;
    }
    return (strcmp(chpara, m_chpara) == 0);
}

/*******************************************************************************************
*功能:  匹配附加参数
*参数:
*       chpara      前台配置的附加参数字符串
*注释:  返回值 true匹配   false不匹配
*******************************************************************************************/
bool CS7::MatchPara2(const char *chpara2)
{
    if (chpara2[0] == '\0') { //为空匹配所有
        return true;
    }
    return (strcmp(chpara2, m_chpara2) == 0);
}

/*******************************************************************************************
*功  能: 组命令字符串
*参  数:
*        strcmd   输出参数 存放命令
*        cmdlen   缓冲区长度
*        strpara  输出参数 存放参数
*        paralen  缓冲区长度
*注  释:
*返回值:void
*******************************************************************************************/
void CS7::MakeString(char *strcmd, int cmdlen, char *strpara, int paralen)
{
    if ((strcmd == NULL) || (strpara == NULL) || (cmdlen <= 0) || (paralen <= 0)) {
        return;
    }
    memset(strcmd, 0, cmdlen);
    memset(strpara, 0, paralen);

    if (S7COMM_ROSCTR_JOB == m_pdu_type) {
        sprintf(strcmd, "[Job]%s", m_chcmd);
    } else if (S7COMM_ROSCTR_ACK == m_pdu_type) {
        sprintf(strcmd, "[Ack]%s", m_chcmd);
    } else if (S7COMM_ROSCTR_ACK_DATA == m_pdu_type) {
        sprintf(strcmd, "[Ack_Data]%s", m_chcmd);
    } else {
        sprintf(strcmd, "[UserData]%s", m_chcmd);
    }

    if (strlen(m_chpara) > 0) {
        if (strlen(m_chpara2) > 0) {
            sprintf(strpara, "[%s][%s]", m_chpara, m_chpara2);
        } else {
            sprintf(strpara, "[%s]", m_chpara);
        }
    }
}
