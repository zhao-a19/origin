/*******************************************************************************************
*文件:  FCRTSP.cpp
*描述:  RTSP模块  即MEDIA模块
*作者:  王君雷
*日期:  2016-03
*修改:  添加对命令HEARTBEAT的支持                                 ------>   2016-03-29
*       不再调用IfRequest，注释掉，解析命令失败时按未定义命令处理 ------>   2016-03-30
*******************************************************************************************/
#include "FCRTSP.h"

CRTSP::CRTSP()
{
    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_url, 0, sizeof(ch_url));
}

CRTSP::~CRTSP()
{

}

bool CRTSP::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
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

bool CRTSP::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    int datalen = slen - hdflag;
    if (datalen <= 0)
    {
        return true;
    }

    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_url, 0, sizeof(ch_url));

    if (DecodeRequest(sdata + hdflag, slen - hdflag, cherror))
    {
        if (AnalyseCmdRule(ch_cmd, ch_url, cherror))
        {
            RecordCallLog(sdata, ch_cmd, ch_url, cherror, true);
            return true;
        }
        else
        {
            RecordCallLog(sdata, ch_cmd, ch_url, cherror, false);
            return false;
        }
    }
    else
    {
        //return true;
        return m_service->m_IfExec;
    }
}

bool CRTSP::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

bool CRTSP::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    //printf("==AnalyseCmdRule %s %s\n",chcmd,chpara);
    for (int i = 0; i < m_service->m_cmdnum; i++)
    {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0)
        {
            printf("==find chcmd==\n");
            if (m_common.casestrstr((const unsigned char *)chpara,
                                   (const unsigned char *)m_service->m_cmd[i]->m_parameter, 0,
                                   strlen(chpara)) == E_COMM_OK)
            {
                if (!(m_service->m_cmd[i]->m_action))
                {
                    printf("==RTSP_PERM_FORBID==\n");
                    sprintf(cherror, "%s", RTSP_PERM_FORBID);
                }

                if (g_debug)
                {
                    printf("==exec Specify action!==\n");
                }
                return m_service->m_cmd[i]->m_action;
            }
        }
    }

    if (!(m_service->m_IfExec))
    {
        printf("==RTSP_PERM_FORBID==\n");
        sprintf(cherror, "%s", RTSP_PERM_FORBID);
    }
    if (g_debug)
    {
        printf("==exec default action!==\n");
    }
    return m_service->m_IfExec;
}

bool CRTSP::DecodeRequest(unsigned char *data, int datasize, char *error_reason)
{
    unsigned char ucflag[2] = {0x0d, 0x0a};
    unsigned char tucflag[1] = {0x20};
    int offset_0d0a = 0;
    int cmd_len = 0;
    int url_len = 0;

    //printf("DecodeRequest: datasize %d\n",datasize);
    if (data == NULL || datasize <= 0)
    {
        return false;
    }
    //查找第一个0d0a的偏移量
    for (offset_0d0a = 0; offset_0d0a < datasize - 1; offset_0d0a++)
    {
        if (memcmp(data + offset_0d0a, ucflag, 2) == 0)
        {
            break;
        }
    }
    if (offset_0d0a == datasize - 1)
    {
        strcpy(error_reason, RTSP_PROTO_ERROR);
        return false;
    }

    //取出命令
    for (cmd_len = 0; cmd_len < offset_0d0a; cmd_len++ )
    {
        if (data[cmd_len] == tucflag[0])
        {
            break;
        }
    }
    if (cmd_len == offset_0d0a)
    {
        strcpy(error_reason, RTSP_PROTO_ERROR);
        return false;
    }
    memset(ch_cmd, 0, sizeof(ch_cmd));
    memcpy(ch_cmd, data, cmd_len < 16 ? cmd_len : 16);

    //检查命令是否为正确的RTSP命令
    //if (!IfRequest(ch_cmd))
    //{
    //    return false;
    //}

    //取URL
    for (url_len = cmd_len + 1; url_len < offset_0d0a; url_len++ )
    {
        if (data[url_len] == tucflag[0])
        {
            break;
        }
    }
    if (url_len == offset_0d0a)
    {
        strcpy(error_reason, RTSP_PROTO_ERROR);
        return false;
    }

    memset(ch_url, 0, sizeof(ch_url));
    memcpy(ch_url, data + cmd_len + 1,
        (url_len - cmd_len - 1) < (int)sizeof(ch_url) - 1 ? (url_len - cmd_len - 1) : (int)sizeof(ch_url) - 1);

    //如果url中有单引号,替换为空格 否则后面组装sql语句时可能会出错
    for (int i = 0; i < (int)strlen(ch_url); i++)
    {
        if (ch_url[i] == '\'')
        {
            ch_url[i] = ' ';
        }
    }

    if (g_debug)
    {
        printf("CMD:%s,URL:%s\n", ch_cmd, ch_url);
    }

    return true;
}

/*
bool CRTSP::IfRequest(char *chrequest)
{
    char    m_RequestCmd[][16] =
    {
        "OPTIONS", "DESCRIBE", "SETUP", "TEARDOWN",
        "PLAY", "GET_PARAMETER", "SET_PARAMETER","HEARTBEAT"
    };

    for (int i = 0; i < 8; i++)
    {
        if (strcasecmp(chrequest, m_RequestCmd[i]) == 0)
        {
            return true;
        }
    }
    return false;
}
*/
