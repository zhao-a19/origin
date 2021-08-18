/*******************************************************************************************
*文件:  FCSMBSingle.cpp
*描述:  SMB模块
*作者:  王君雷
*日期:
*修改:
*       特殊处理Zone.Identifier后缀                                     ------> 2019-05-15
*       整理SMB模块，统一使用结构                                       ------> 2019-05-29
*******************************************************************************************/
#include "FCSMBSingle.h"
#include "debugout.h"
#include <locale.h>

unsigned char SMBFLAG[4], SMB2FLAG[4];

//特殊文件 忽略不处理
char g_particular_file[][20] = {
    "desktop.ini",
    "Thumbs.db",
    "srvsvc",
    "wkssvc",
    ".svn",
    ":Zone.Identifier",
    "folder.gif",
    "folder.jpg"
};

CSMBSINGLE::CSMBSINGLE()
{
    SMBFLAG[0] = 0xFF;
    SMBFLAG[1] = 0x53;
    SMBFLAG[2] = 0x4D;
    SMBFLAG[3] = 0x42;

    SMB2FLAG[0] = 0xFE;
    SMB2FLAG[1] = 0x53;
    SMB2FLAG[2] = 0x4D;
    SMB2FLAG[3] = 0x42;
    BZERO(m_action);
    BZERO(m_fname);
}

CSMBSINGLE::~CSMBSINGLE()
{
}

/**
 * [CSMBSINGLE::ParticularFile 是否为需要特殊处理的文件]
 * @param  file [输入的文件名称]
 * @return      [是特殊文件 返回true]
 */
bool CSMBSINGLE::ParticularFile(const char *file)
{
    for (uint32 i = 0; i < ARRAY_SIZE(g_particular_file); ++i) {
        if (strcasestr(file, g_particular_file[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/**
 * [CSMBSINGLE::DoMsg 处理数据包]
 * @param  sdata     [数据包]
 * @param  slen      [ip头开始的数据包长度]
 * @param  cherror   [出错信息]
 * @param  pktchange [数据包是否改变了]
 * @param  bFromSrc  [为1表示来自客户端的请求]
 * @return           [允许通过返回true]
 */
bool CSMBSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}

/**
 * [CSMBSINGLE::DoSrcMsg 处理数据包 来自客户端的请求]
 * @param  sdata   [数据包]
 * @param  slen    [ip头开始的数据包长度]
 * @param  cherror [出错信息]
 * @return         [允许通过返回true]
 */
bool CSMBSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    BZERO(m_action);
    BZERO(m_fname);
    bool bflag = true;
    if (DecodeRequest(sdata + hdflag, slen - hdflag, cherror)) {
        PRINT_DBG_HEAD
        print_dbg("docode request ok[%s][%s]", m_action, m_fname);

        if (AnalyseCmdRule(m_action, m_fname, cherror)) {
            if ((strcmp(m_action, "Auth") == 0)
                || (strcmp(m_fname, "") == 0)) {
                RecordCallLog(sdata, m_action, m_fname, cherror, true);
            } else if (ParticularFile(m_fname)) {
            } else {
                if (FilterFileType(m_fname, cherror)) {
                    RecordCallLog(sdata, m_action, m_fname, cherror, true);
                } else {
                    PRINT_ERR_HEAD
                    print_err("smb filetype forbid.[%s:%s]", m_action, m_fname);
                    RecordCallLog(sdata, m_action, m_fname, cherror, false);
                    RecordFilterLog(sdata, rindex((char *)m_fname, '.'), cherror);
                    bflag = false;
                }
            }
        } else {
            PRINT_ERR_HEAD
            print_err("smb forbid.[%s:%s]", m_action, m_fname);
            RecordCallLog(sdata, m_action, m_fname, cherror, false);
            bflag = false;
        }
    } else {
        //解码失败时允许通过
    }
    return bflag;
}

/**
 * [CSMBSINGLE::DoDstMsg 处理响应信息]
 * @param  sdata   [数据包]
 * @param  slen    [ip头开始的数据包长度]
 * @param  cherror [出错信息]
 * @return         [允许通过返回true]
 */
bool CSMBSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/**
 * [CSMBSINGLE::DecodeRequest 解析命令参数]
 * @param  sdata   [应用层内容开始的数据包]
 * @param  slen    [应用层长度]
 * @param  cherror [出错信息]
 * @return         [解析成功返回true]
 */
bool CSMBSINGLE::DecodeRequest(unsigned char *sdata, int slen, char *cherror)
{
    if (slen < (int)sizeof(NETBIOS_SESSION_MESSAGE)) {
        return false;
    }

    if (memcmp(sdata + sizeof(NETBIOS_SESSION_MESSAGE), SMBFLAG, sizeof(SMBFLAG)) == 0) {
        return DecodeRequestSMBV1(sdata, slen, cherror);
    } else if (memcmp(sdata + sizeof(NETBIOS_SESSION_MESSAGE), SMB2FLAG, sizeof(SMB2FLAG)) == 0) {
        return DecodeRequestSMBV2(sdata, slen, cherror);
    }
    return false;
}

/**
 * [CSMBSINGLE::DecodeRequestSMBV1 解析命令参数]
 * @param  sdata   [应用层内容开始的数据包]
 * @param  slen    [应用层长度]
 * @param  cherror [出错信息]
 * @return         [解析成功返回true]
 */
bool CSMBSINGLE::DecodeRequestSMBV1(unsigned char *sdata, int slen, char *cherror)
{
    int mlen = sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB_HEADER);
    if (slen < mlen) {
        PRINT_ERR_HEAD
        print_err("smb data too short[%d].The length should be at least[%d]", slen, mlen);
        return false;
    }

    bool bflag = false;
    PSMB_HEADER psmbheader = (PSMB_HEADER)(sdata + sizeof(NETBIOS_SESSION_MESSAGE));
    if (psmbheader->Flags & SMB_FLAGS_RESPONSE) {
        PRINT_ERR_HEAD
        print_err("smb not request. Flags[%d]", psmbheader->Flags);
        return false;
    }

    switch (psmbheader->Command) {
    case SMB_COM_CREATE_DIRECTORY://0x00
        break;
    case SMB_COM_DELETE_DIRECTORY: { //0x01
        strcpy(m_action, "IODelete");
        PDELETE_DIRECTORY_REQUEST prequest = (PDELETE_DIRECTORY_REQUEST)(sdata + mlen);
        if (prequest->bufferformat == ASCII_FORMAT) {
            DecodeFileName(sdata + mlen + sizeof(DELETE_DIRECTORY_REQUEST),
                           prequest->bytecount - sizeof(prequest->bufferformat));
        } else {
            PRINT_ERR_HEAD
            print_err("not ascii format.");
        }
        bflag = true;
        break;
    }
    case SMB_COM_RENAME://0x07
        strcpy(m_action, "IORename");
        bflag = true;
        break;
    case SMB_COM_WRITE_ANDX://0x2f
        strcpy(m_action, "IOWrite");
        bflag = true;
        break;
    case SMB_COM_NT_CREATE_ANDX://0xA2
        bflag = DecodeSMBV1NTCreateAndXRequest(sdata, slen, cherror);
        break;
    case SMB_COM_TRANSACTION2://0x32
        bflag = DecodeSMBV1Trans2Request(sdata, slen, cherror);
        break;
    case SMB_COM_SESSION_SETUP_ANDX://0x73
        strcpy(m_action, "Auth");
        bflag = true;
        break;
    default:
        break;
    }

    if (bflag) {
        PRINT_DBG_HEAD
        print_dbg("docode success[%s][%s]", m_action, m_fname);
    }
    return bflag;
}

/**
 * [CSMBSINGLE::DecodeSMBV1NTCreateAndXRequest 解码SMBV1 NT Create AndX Request请求]
 * @param  sdata   [应用层内容开始的数据包]
 * @param  slen    [应用层长度]
 * @param  cherror [出错信息]
 * @return         [解析成功返回true]
 */
bool CSMBSINGLE::DecodeSMBV1NTCreateAndXRequest(unsigned char *sdata, int slen, char *cherror)
{
    int mlen = sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB_HEADER) + sizeof(SMB_Parameters);
    if (slen < mlen) {
        PRINT_ERR_HEAD
        print_err("smb andx data too short[%d].The length should be at least[%d]", slen, mlen);
        return false;
    }

    PSMB_Parameters pparameter =
        (PSMB_Parameters)(sdata + sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB_HEADER));

    if (pparameter->CreateDisposition == FILE_OPEN) {
        if ((pparameter->CreateOptions & FILE_DELETE_ON_CLOSE)
            && (pparameter->ShareAccess & SMB_SHARE_ACCESS_DELETE)) {
            strcpy(m_action, "IODelete"); //删除文件
        } else {
            strcpy(m_action, "IORead");
        }
    } else if (pparameter->CreateDisposition == FILE_CREATE) {
        strcpy(m_action, "IOWrite");
    } else if (pparameter->CreateDisposition == FILE_OPEN_IF) {
        strcpy(m_action, "IOModify");
    } else {
        PRINT_ERR_HEAD
        print_err("unknown CreateDisposition %d", pparameter->CreateDisposition);
        return false;
    }

    if (slen - mlen > 2) {
        //文件名长度
        int fnamelen = sdata[mlen] + sdata[mlen + 1] * 256;
        if ((fnamelen > 0) && ((slen - mlen - 2) == fnamelen)) {
            DecodeFileName(sdata + mlen + 2 + fnamelen % 2, fnamelen);
        } else {
            PRINT_INFO_HEAD
            print_dbg("filenamelen[%d],slen[%d],mlen[%d]", fnamelen, slen, mlen);
            return false;
        }
    }

    PRINT_DBG_HEAD
    print_dbg("decode ok. action[%s] filename[%s]", m_action, m_fname);
    return true;
}

/**
 * [CSMBSINGLE::DecodeSMBV1Trans2Request 解码TRANS2 Request请求]
 * @param  sdata   [应用层内容开始的数据包]
 * @param  slen    [应用层长度]
 * @param  cherror [出错信息]
 * @return         [解析成功返回true]
 */
bool CSMBSINGLE::DecodeSMBV1Trans2Request(unsigned char *sdata, int slen, char *cherror)
{
    int mlen = sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB_HEADER) + sizeof(SMB_TRANS2_REQUEST);
    if (slen < mlen) {
        PRINT_ERR_HEAD
        print_err("smb1 trans2 data too short[%d].The length should be at least[%d]", slen, mlen);
        return false;
    }

    PSMB_TRANS2_REQUEST ptrans2request =
        (PSMB_TRANS2_REQUEST)(sdata + sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB_HEADER));

    bool bflag = false;
    switch (ptrans2request->Setup) {
    case SET_PATH_INFO:
        if (slen >= (int)sizeof(NETBIOS_SESSION_MESSAGE) + ptrans2request->ParameterOffset
            + ptrans2request->ParameterCount) {

            PSET_PATH_INFO_PARAMETER psetpathinfo =
                (PSET_PATH_INFO_PARAMETER)(sdata + sizeof(NETBIOS_SESSION_MESSAGE) + ptrans2request->ParameterOffset);
            if (psetpathinfo->level == SET_FILE_POSIX_UNLINK) {
                strcpy(m_action, "IODelete");
                DecodeFileName(sdata + sizeof(NETBIOS_SESSION_MESSAGE) + ptrans2request->ParameterOffset
                               + sizeof(SET_PATH_INFO_PARAMETER), ptrans2request->ParameterCount);
                bflag = true;
                PRINT_DBG_HEAD
                print_dbg("smb1 trans2 setpathinfo oidelete.[%s]", m_fname);

            } else if (psetpathinfo->level == SET_FILE_POSIX_OPEN) {
                strcpy(m_action, "IORead");
                DecodeFileName(sdata + sizeof(NETBIOS_SESSION_MESSAGE) + ptrans2request->ParameterOffset
                               + sizeof(SET_PATH_INFO_PARAMETER), ptrans2request->ParameterCount);
                bflag = true;
                PRINT_DBG_HEAD
                print_dbg("smb1 trans2 setpathinfo oiread.[%s]", m_fname);
            }
        } else {
            PRINT_ERR_HEAD
            print_err("set path info slen too short[%d],ParameterOffset[%d],ParameterCount[%d]", slen,
                      ptrans2request->ParameterOffset, ptrans2request->ParameterCount);
        }
        break;
    case SET_FILE_INFO:
        if (slen >= (int)sizeof(NETBIOS_SESSION_MESSAGE) + ptrans2request->ParameterOffset + ptrans2request->ParameterCount) {

            PSET_FILE_INFO_PARAMETER ppara =
                (PSET_FILE_INFO_PARAMETER)(sdata + sizeof(NETBIOS_SESSION_MESSAGE) + ptrans2request->ParameterOffset);
            if (ppara->InformationLevel == SET_DISPOSITION_INFO) {

                if (sdata[sizeof(NETBIOS_SESSION_MESSAGE) + ptrans2request->DataOffset] == DELETE_PENDING) {
                    strcpy(m_action, "IODelete");
                    bflag = true;
                    PRINT_DBG_HEAD
                    print_dbg("smb1 trans2 setfileinfo oidelete");
                }
            }
        } else {
            PRINT_ERR_HEAD
            print_err("set file info slen too short[%d],ParameterOffset[%d],ParameterCount[%d]", slen,
                      ptrans2request->ParameterOffset, ptrans2request->ParameterCount);
        }
        break;
    case FIND_FIRST2:
        break;
    default:
        break;
    }

    PRINT_DBG_HEAD
    print_dbg("Decode SMBV1 Trans2 Request over. action[%s] fname[%s]", m_action, m_fname);
    return bflag;
}

/**
 * [CSMBSINGLE::DecodeFileName 解析出文件名称]
 * @param  data  [开始查找的位置]
 * @param  len   [长度]
 * @return       [成功返回true]
 */
bool CSMBSINGLE::DecodeFileName(unsigned char *data, int len)
{
    char fname[1024] = {0};
    unsigned long unic = 0;
    unsigned char pOutput[16] = {0};
    int ret = 0, icount = 0;

    for (int i = 0; i < len / 2; i++) {
        BZERO(pOutput);
        memcpy(&unic, data + i * 2, 2);
        ret = EncUnicodeToUTF8(unic, pOutput, sizeof(pOutput));
        if (ret == 0) {
            PRINT_ERR_HEAD
            print_err("encunicode to utf8 fail.namelength %d", len);
            return false;
        } else if ((ret == 1) && (pOutput[0] == '\\')) {//把反斜杠换成2个反斜杠
            memcpy(fname + icount, pOutput, ret);
            memcpy(fname + icount + 1, pOutput, ret);
            icount += 2;
        } else {
            memcpy(fname + icount, pOutput, ret);
            icount += ret;
        }
    }

    strncpy(m_fname, fname, sizeof(m_fname) - 1);
    PRINT_DBG_HEAD
    print_dbg("decode filename over[%s]", m_fname);
    return true;
}

/**
 * [CSMBSINGLE::DecodeRequestSMBV2 解析命令参数]
 * @param  sdata   [应用层内容开始的数据包]
 * @param  slen    [应用层长度]
 * @param  cherror [出错信息]
 * @return         [解析成功返回true]
 */
bool CSMBSINGLE::DecodeRequestSMBV2(unsigned char *sdata, int slen, char *cherror)
{
    int mlen = sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB2_HEADER);
    if (slen < mlen) {
        PRINT_ERR_HEAD
        print_err("smb2 data too short[%d].The length should be at least[%d]", slen, mlen);
        return false;
    }

    PSMB2_HEADER prequest = (PSMB2_HEADER)(sdata + sizeof(NETBIOS_SESSION_MESSAGE));
    if (prequest->flags & SMB2_FLAGS_RESPONSE) {
        PRINT_ERR_HEAD
        print_err("smb2 not request packet");//是回应包
        return false;
    }

    bool bflag = false;
    switch (prequest->command) {
    case SMB2_COM_CREATE:
        bflag = DecodeRequestSMBV2Create(sdata, slen, cherror);
        break;
    case SMB2_COM_SETINFO:
        bflag = DecodeRequestSMBV2SetInfo(sdata, slen, cherror);
        break;
    default:
        break;
    }
    return bflag;
}

/**
 * [CSMBSINGLE::DecodeRequestSMBV2Create 解析SMB2 createrequest]
 * @param  sdata   [应用层内容开始的数据包]
 * @param  slen    [应用层长度]
 * @param  cherror [出错信息]
 * @return         [解析成功返回true]
 */
bool CSMBSINGLE::DecodeRequestSMBV2Create(unsigned char *sdata, int slen, char *cherror)
{
    int mlen = sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB2_HEADER) + sizeof(SMB2_CREATE_REQUEST);
    if (slen < mlen) {
        PRINT_ERR_HEAD
        print_err("smb2 create data too short[%d].The length should be at least[%d]", slen, mlen);
        return false;
    }

    PSMB2_CREATE_REQUEST pcreaterequest =
        (PSMB2_CREATE_REQUEST)(sdata + sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB2_HEADER));
    if ((pcreaterequest->fileattributes & SMB2_FLAGS_ATTR_DIRECTORY)
        || (pcreaterequest->createoptions & FILE_DIRECTORY_FILE)) {
        PRINT_DBG_HEAD
        print_dbg("this is a directory.");
        return false;
    }

    if (pcreaterequest->namelength == 0) {
        PRINT_DBG_HEAD
        print_dbg("neme length is 0.");
        return false;
    }

    if (pcreaterequest->disposition == FILE_OPEN) {
        strcpy(m_action, (pcreaterequest->createoptions & FILE_DELETE_ON_CLOSE) ? "IODelete" : "IORead");
    } else if (pcreaterequest->disposition == FILE_CREATE) {
        strcpy(m_action, "IOWrite");
    } else {
        PRINT_INFO_HEAD
        print_info("createrequest disposition is %d", pcreaterequest->disposition);
        return false;
    }

    DecodeFileName(pcreaterequest->buffer, pcreaterequest->namelength);
    PRINT_DBG_HEAD
    print_dbg("smb2 create request decode over. action[%s] filename[%s] filenamelen[%d]",
              m_action, m_fname, pcreaterequest->namelength);
    return true;
}

/**
 * [CSMBSINGLE::DecodeRequestSMBV2SetInfo 解析SMB2 setinfo]
 * @param  sdata   [应用层内容开始的数据包]
 * @param  slen    [应用层长度]
 * @param  cherror [出错信息]
 * @return         [解析成功返回true]
 */
bool CSMBSINGLE::DecodeRequestSMBV2SetInfo(unsigned char *sdata, int slen, char *cherror)
{
    int mlen = sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB2_HEADER) + sizeof(SMB2_SET_INFO_REQUEST);
    if (slen < mlen) {
        PRINT_ERR_HEAD
        print_err("smb2 setinfo data too short[%d].The length should be at least[%d]", slen, mlen);
        return false;
    }

    bool bflag = false;

    PSMB2_SET_INFO_REQUEST psetinfo =
        (PSMB2_SET_INFO_REQUEST)(sdata + sizeof(NETBIOS_SESSION_MESSAGE) + sizeof(SMB2_HEADER));

    if (psetinfo->infotype == SMB2_0_INFO_FILE) {
        PRINT_DBG_HEAD
        print_dbg("fileinfo class is [%d]", psetinfo->fileinfoclass);

        switch (psetinfo->fileinfoclass) {
        case SMB2_FILE_DISPOSITION_INFO: {
            if (psetinfo->buffer[0] == 0x01) {
                strcpy(m_action, "IODelete");
                PRINT_DBG_HEAD
                print_dbg("io delete");
                bflag = true;
            }
            break;
        }
        case SMB2_FILE_ALLOCATION_INFO: {
            strcpy(m_action, "IOModify");
            PRINT_DBG_HEAD
            print_dbg("io modify");
            bflag = true;
            break;
        }
        case SMB2_FILE_RENAME_INFO: {
            strcpy(m_action, "IORename");
            PRINT_DBG_HEAD
            print_dbg("io rename");
            bflag = true;
            break;
        }
        default:
            break;
        }
    }

    PRINT_DBG_HEAD
    print_dbg("decode request  smbv2 setinfo over. action[%s]", m_action);
    return bflag;
}

/**
 * [CSMBSINGLE::AnalyseCmdRule 匹配命令规则]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息]
 * @return         [允许通过返回true]
 */
bool CSMBSINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    PRINT_DBG_HEAD
    print_dbg("analyse cmd rule begin. cmd[%s] para[%s]", chcmd, chpara);

    bool bflag = m_service->m_IfExec;
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0) {
            if (m_common.casestrstr((const unsigned char *)chpara,
                                    (const unsigned char *)m_service->m_cmd[i]->m_parameter, 0,
                                    strlen(chpara)) == E_COMM_OK) {
                bflag = m_service->m_cmd[i]->m_action;
                break;
            }
        }
    }

    if (!bflag) {
        PRINT_ERR_HEAD
        print_err("smb perm forbid[%s][%s]", chcmd, chpara);
        sprintf(cherror, "%s", SMB_PERM_FORBID);
    }

    PRINT_DBG_HEAD
    print_dbg("analyse cmd rule over.%s", bflag ? "pass" : "drop");
    return bflag;
}
