/*******************************************************************************************
*文件: rfc3261.cpp
*描述: RFC3261平台互联
*作者: 王君雷
*日期: 2020-08-18
*修改:
*      使用的第一个通道端口号以及通道最大支持数可以通过配置文件配置 ------> 2020-09-03
*      上面的2个配置，改到[SYS]下                               ------> 2020-09-04
*      流媒体通道传输层协议，可以自动识别也可以通过配置指定        ------> 2020-09-15
*      开通通道以后可以通过配置决定是否需要清空连接追踪表，默认不开启 ------> 2020-09-16
*      contact字段替换IP及端口                                    ------> 2020-09-27
*      支持替换CallID中的IP                                       ------> 2020-09-28
*      按鼎桥的最新要求，不需要替换CallID中的IP                   ------> 2020-10-28
*******************************************************************************************/
#include "rfc3261.h"
#include "common.h"
#include "fileoperator.h"
#include "readcfg.h"
#include "debugout.h"
#include "quote_global.h"

RFC3261SIP::RFC3261SIP(int taskid): base(taskid, true)
{

}

RFC3261SIP::~RFC3261SIP(void)
{

}

/**
 * [RFC3261SIP::loadConf 加载配置信息]
 * @param  filename   [文件名称]
 * @return            [成功返回true]
 */
bool RFC3261SIP::loadConf(const char *filename)
{
    PRINT_DBG_HEAD
    print_dbg("load conf begin");

    int tmpint = 0;
    bool bflag = false;
    char taskid[32] = {0};
    char subitem[32] = {0};
    CCommon common;
    int indev = -1;
    int outdev = -1;
    CFILEOP fileop;

    if (fileop.OpenFile(filename, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        goto _out;
    }

    sprintf(taskid, "TaskSIP%d", m_taskid);
    READ_STRING(fileop, taskid, "Name", m_name, true, _out);
    common.DelChar(m_name, '\'');
    READ_INT(fileop, taskid, "Mode", m_mode, true, _out);
    READ_INT(fileop, taskid, "Area", m_area, true, _out);
    READ_INT(fileop, taskid, "InDev", indev, true, _out);
    READ_INT(fileop, taskid, "OutDev", outdev, true, _out);
    m_secway.setway("", 0, indev, outdev);
    READ_STRING(fileop, taskid, "GapInIP", m_gapinip, true, _out);
    READ_STRING(fileop, taskid, "GapOutIP", m_gapoutip, true, _out);
    READ_STRING(fileop, taskid, "InCenter", m_incenter, true, _out);
    READ_STRING(fileop, taskid, "OutCenter", m_outcenter, true, _out);
    READ_STRING(fileop, taskid, "InPort", m_inport, true, _out);
    READ_STRING(fileop, taskid, "OutPort", m_outport, true, _out);
    READ_STRING(fileop, taskid, "Protocol", m_proto, true, _out);
    READ_INT(fileop, taskid, "InBrandID", m_inbrandid, true, _out);
    READ_INT(fileop, taskid, "OutBrandID", m_outbrandid, true, _out);
    tmpint = 1;
    READ_INT(fileop, taskid, "Via", tmpint, true, _out);
    m_via = (tmpint == 1);
    tmpint = 1;
    READ_INT(fileop, taskid, "From", tmpint, true, _out);
    m_from = (tmpint == 1);
    tmpint = 1;
    READ_INT(fileop, taskid, "To", tmpint, true, _out);
    m_to = (tmpint == 1);
    tmpint = 0;
    READ_INT(fileop, taskid, "DefCmdAction", tmpint, true, _out);
    m_defaultaction = (tmpint == 1);
    READ_INT(fileop, taskid, "CmdNum", m_cmdnum, true, _out);
    m_cmdnum = MIN(m_cmdnum , C_MAX_CMD);

    //读取各个命令
    for (int j = 0; j < m_cmdnum; j++) {
        m_cmd[j] = new CCMDCONF;
        if (m_cmd[j] == NULL) {
            PRINT_ERR_HEAD
            print_err("new cmd error %d", j);
            goto _out;
        }
        sprintf(subitem, "CmdName%d", j);
        READ_STRING(fileop, taskid, subitem, m_cmd[j]->m_cmd, true, _out);
        sprintf(subitem, "Param%d", j);
        READ_STRING(fileop, taskid, subitem, m_cmd[j]->m_parameter, false, _out);
        sprintf(subitem, "Permit%d", j);
        READ_INT(fileop, taskid, subitem, tmpint, true, _out);
        m_cmd[j]->m_action = (tmpint == 1);
    }

    READ_INT(fileop, "SYS", "FirstChPort", m_first_chport, false, _out);
    READ_INT(fileop, "SYS", "MaxChannel", m_max_channel, false, _out);
    if (m_first_chport < 10000 || m_first_chport > 60000) {
        m_first_chport = 30000;
    }

    if (m_max_channel < 100 || m_max_channel > 5000) {
        m_max_channel = 3000;
    }
    READ_INT(fileop, "SYS", "StreamType", m_stream_type, false, _out);
    READ_INT(fileop, "SYS", "CleanTrack", m_clean_track, false, _out);

    bflag = true;
_out:
    fileop.CloseFile();
    PRINT_DBG_HEAD
    print_dbg("load conf over(%s)", bflag ? "ok" : "bad");
    return bflag;
}

/**
 * [RFC3261SIP::checkProto 检查所选协议是否正确]
 * @return  [正确返回true]
 */
bool RFC3261SIP::checkProto(void)
{
    if (strcmp(m_proto, "RFC3261") == 0) {
        return true;
    }
    PRINT_ERR_HEAD
    print_err("proto check fail[%s]", m_proto);
    return false;
}

/**
 * [RFC3261SIP::doMethodLine 处理信令行]
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [成功返回true]
 */
bool RFC3261SIP::doMethodLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec)
{
    const char *repip = (pinfo.recvarea == RECV_IN_CENTER) ? m_outcenter : m_incenter;
    for (int i = 0; i < (int)ARRAY_SIZE(rfc3261_methods); ++i) {
        if (strncmp(begin, rfc3261_methods[i].name, rfc3261_methods[i].len) == 0) {
            if (rfc3261_methods[i].breplaceip) {
                return doReplaceIP(begin, end, pinfo, bvec, repip);
            }
            break;
        }
    }
    BLOCK block;
    bvec.push_back(makeBlock1(block, begin, end - begin + 1));
    return true;
}

/**
 * [RFC3261SIP::doHeaderLine 处理头域行]
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [成功返回true]
 */
bool RFC3261SIP::doHeaderLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec)
{
    BLOCK block;

    int hdr = getHeaderType(begin);
    PRINT_DBG_HEAD
    print_dbg("hdr is %d", hdr);

    switch (hdr) {
    case HEADER_CALLID: {
        if (getCallID(begin, pinfo.callid, sizeof(pinfo.callid))) {
            if (strncasecmp(pinfo.chcmd, "BYE", 3) == 0) {
                lockChannel();
                delChannel(pinfo.callid);
                unlockChannel();
            }
        }
        const char *pat = strnchr(begin, end, '@');
        if (pat == NULL) {
            bvec.push_back(makeBlock1(block, begin, end - begin + 1));
            PRINT_DBG_HEAD
            print_dbg("callid not find @");
        } else {
#if 0
            doReplaceCallIDIP(begin, end, pinfo, bvec);
#else
            bvec.push_back(makeBlock1(block, begin, end - begin + 1));
#endif
        }
        break;
    }
    case HEADER_CONTACT: {
        const char *repip = (pinfo.recvarea == RECV_IN_CENTER) ? m_gapoutip : m_gapinip;
        const char *oriip = (pinfo.recvarea == RECV_IN_CENTER) ? m_incenter : m_outcenter;
        const char *repport = (pinfo.recvarea == RECV_IN_CENTER) ? m_inport : m_outport;

        const char *pat = strnchr(begin, end, '@');
        const char *pcolon = strnchr(pat, end, ':');
        if ((pat != NULL) && (pcolon != NULL)) {
            doReplaceIPPort(begin, end, pinfo, bvec, repip, repport);
        } else {
            doReplaceIP(begin, end, pinfo, bvec, oriip, repip);
        }
        break;
    }
    case HEADER_CONTENT_ENCODING:
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        break;
    case HEADER_CONTENT_LENGTH:
        doReplaceLength(begin, end, pinfo, bvec, false);
        break;
    case HEADER_CONTENT_TYPE:
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        if (!parserContentType(begin, end, pinfo)) {
            return false;
        }
        break;
    case HEADER_FROM: {
        if (m_from && (!pinfo.isresponse)) {
            const char *repip = (pinfo.recvarea == RECV_IN_CENTER) ? m_gapoutip : m_gapinip;
            const char *oriip = (pinfo.recvarea == RECV_IN_CENTER) ? m_incenter : m_outcenter;
            if (strnchr(begin, end, '@') != NULL) {
                doReplaceIP(begin, end, pinfo, bvec, repip);
            } else {
                doReplaceIP(begin, end, pinfo, bvec, oriip, repip);
            }
        } else {
            bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        }
        break;
    }
    case HEADER_SUBJECT:
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        break;
    case HEADER_SUPPORTED:
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        break;
    case HEADER_TO:
        if (m_to && (!pinfo.isresponse)) {
            const char *repip = (pinfo.recvarea == RECV_IN_CENTER) ? m_outcenter : m_incenter;
            const char *oriip = (pinfo.recvarea == RECV_IN_CENTER) ? m_gapinip : m_gapoutip;
            if (strnchr(begin, end, '@') != NULL) {
                doReplaceIP(begin, end, pinfo, bvec, repip);
            } else {
                doReplaceIP(begin, end, pinfo, bvec, oriip, repip);
            }
        } else {
            bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        }
        break;
    case HEADER_VIA:
        if (m_via && (!pinfo.isresponse)) {
            const char *repip = (pinfo.recvarea == RECV_IN_CENTER) ? m_gapoutip : m_gapinip;
            const char *oriip = (pinfo.recvarea == RECV_IN_CENTER) ? m_incenter : m_outcenter;
            doReplaceIP(begin, end, pinfo, bvec, oriip, repip);
        } else {
            bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        }
        break;
    default: {
        PRINT_INFO_HEAD
        print_info("unknown header[%d]", hdr);
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        break;
    }
    }
    return true;
}

/**
 * [RFC3261SIP::doBodyLine 处理包体行]
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [成功返回true]
 */
bool RFC3261SIP::doBodyLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec)
{
    BLOCK block;

    if (pinfo.multipart) {
        if (strncasestr(begin, end, pinfo.boundary) != NULL) {
            bvec.push_back(makeBlock1(block, begin, end - begin + 1));
            PRINT_INFO_HEAD
            print_info("find boundary line");
            goto _out;
        } else if (strncasecmp(begin, "content-length", strlen("content-length")) == 0) {
            doReplaceLength(begin, end, pinfo, bvec, true);
            goto _out;
        } else if (strncasestr(begin, end, "application/sdp") != NULL) {
            pinfo.subsdp = true;
            bvec.push_back(makeBlock1(block, begin, end - begin + 1));
            goto _out;
        }
    }
    if (memcmp(begin, "o=", 2) == 0) {
        doReplaceO(begin, end, pinfo, bvec);
    } else if (memcmp(begin, "c=", 2) == 0) {
        doReplaceC(begin, end, pinfo, bvec);
    } else if (memcmp(begin, "m=audio ", 8) == 0) {
        return doReplaceAudio(begin, end, pinfo, bvec);
    } else if (memcmp(begin, "m=video ", 8) == 0) {
        return doReplaceVideo(begin, end, pinfo, bvec);
    } else {
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
    }
_out:
    return true;
}

/**
 * [RFC3261SIP::getHeaderType 获取header类型]
 * @param  line [一行内容]
 * @return      [header类型]
 */
int RFC3261SIP::getHeaderType(const char *line)
{
    int hdr = HEADER_UNKNOWN;
    for (int i = 0; i < (int)ARRAY_SIZE(rfc3261_headers); ++i) {
        if (HEADER_TYPE(rfc3261_headers[i].name, rfc3261_headers[i].cname, line)) {
            hdr = i;
            break;
        }
    }
    return hdr;
}

