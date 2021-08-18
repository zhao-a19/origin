/*******************************************************************************************
*文件:  FCHttpSingle.cpp
*描述:  HTTP模块
*作者:  王君雷
*日期:  2016-03
*修改:
*     URL中含中文时将其转为gbk格式，再写入数据库，保持数据库编码格式一致          ------> 2018-08-21
*     修改190216引入的BUG，打印整形数时使用的%s                               ------> 2019-03-18
*
*     通过调用开源http-parser解析http报文的请求和url                 ------> 2019-05-15  宋宇
*******************************************************************************************/
#include "FCHttpSingle.h"
#include "debugout.h"
#include "urlcoder.h"

CHTTPSINGLE::CHTTPSINGLE(void)
{   
    memset(end_str,0,sizeof(end_str));
    memset(next_arr,0,sizeof(next_arr));
    strcpy(end_str,"\r\n\r\n");
    get_next(end_str, strlen(end_str), next_arr);
}

CHTTPSINGLE::~CHTTPSINGLE(void)
{
}

/**
 * [CHTTPSINGLE::DoMsg 处理请求数据]
 * @param  sdata     [网络层开头的数据包]
 * @param  slen      [数据包长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [是否改变包内容了]
 * @param  bFromSrc  [是否来自客户端]
 * @return           [允许通过返回true]
 */
bool CHTTPSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    return (bFromSrc == 1) ? DoSrcMsg(sdata, slen, cherror) : DoDstMsg(sdata, slen, cherror);
}

/**
 * [CHTTPSINGLE::DoSrcMsg 处理客户端请求信息]
 * @param  sdata   [网络层开头的数据包]
 * @param  slen    [数据包长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CHTTPSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    if (DecodeRequest(sdata + hdflag, slen - hdflag, cherror)) {
        bool flag = AnalyseCmdRule(ch_cmd, ch_url, cherror);
        RecordCallLog(sdata, ch_cmd, ch_url, cherror, flag);
        return flag;
    } else {
        PRINT_DBG_HEAD
        print_dbg("decode fail,allow to pass. slen[%d] queuenum[%d]", slen, m_service->GetQueueNum());
        return true;//由于HTTP请求存在解码失败的可能，直接返回允许通过。
    }
}

/**
 * [CHTTPSINGLE::DoDstMsg 处理服务器响应信息]
 * @param  sdata   [网络层开头的数据包]
 * @param  slen    [数据包长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CHTTPSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/**
 * [CHTTPSINGLE::AnalyseCmdRule 过滤命令]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CHTTPSINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
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
        sprintf(cherror, "%s", HTTP_PERM_FORBID);
        PRINT_ERR_HEAD
        print_err("http cmd[%s] para[%s] not allow to pass.queuenum[%d]", chcmd, chpara,
                  m_service->GetQueueNum());
    }
    return bflag;
}

/**
 * [CHTTPSINGLE::DecodeRequest 解析请求]
 * 如：GET /~img3 HTTP/1.1\r\n
 * @param  data         [数据包]
 * @param  datasize     [数据包大小]
 * @param  error_reason [出错信息]
 * @return              [解析成功返回true]
 */
bool CHTTPSINGLE::DecodeRequest(unsigned char *data, int datasize, char *error_reason)
{
    PRINT_DBG_HEAD
    print_dbg("begin decode request. datasize[%d]", datasize);

    unsigned char tucflag[1] = {0x20};
    int offset_0d0a = 0;
    int cmd_len = 0;
    int url_len = 0;
    //char *pstart = NULL;
    //char *pend = NULL;

    if ((data == NULL) || (datasize <= 0)) {
        PRINT_ERR_HEAD
        print_err("http decode request. para err. datasize[%d]", datasize);
        return false;
    }

    //查找\r\n\r\n
    if((offset_0d0a = index_str((char *)data, datasize, end_str, strlen(end_str),next_arr)) < 0){
        return false;
    }

    //查找空格
    for (cmd_len = 0; cmd_len < offset_0d0a; cmd_len++) {
        if (data[cmd_len] == tucflag[0]) {
            break;
        }
    }
    //未查找到空格
    if (cmd_len == offset_0d0a) {
        PRINT_INFO_HEAD
        print_info("no blank find. datasize[%d]", datasize);
        return false;
    }
    BZERO(ch_cmd);
    memcpy(ch_cmd, data, MIN(cmd_len , (int)sizeof(ch_cmd) - 1));

    //检查命令是否为正确的HTTP命令
    if (!IfRequest(ch_cmd)) {
        PRINT_INFO_HEAD
        print_info("not http cmd[%s].datasize[%d] queuenum[%d]", ch_cmd, datasize,
                   m_service->GetQueueNum());
        return false;
    }

    //查找空格 取URL
    for (url_len = cmd_len + 1; url_len < offset_0d0a; url_len++) {
        if (data[url_len] == tucflag[0]) {
            break;
        }
    }
    //未查找到空格
    if (url_len == offset_0d0a) {
        PRINT_INFO_HEAD
        print_info("no blank find. datasize[%d]", datasize);
        return false;
    }

    BZERO(ch_url);
    memcpy(ch_url, data + cmd_len + 1, MIN((url_len - cmd_len - 1) , (int)(sizeof(ch_url) - 1)));

    //如果url中有单引号,替换为空格 否则后面组装sql语句时可能会出错
    for (int i = 0; i < (int)strlen(ch_url); i++) {
        if (ch_url[i] == '\'') {
            ch_url[i] = ' ';
        }
    }

    PRINT_DBG_HEAD
    print_dbg("ch_url:[%s]", ch_url);

    urldecode(ch_url);

    char tmpchar[sizeof(ch_url)] = {0};
    if (u2g(ch_url, strlen(ch_url), tmpchar, sizeof(tmpchar)) < 0) {
        PRINT_INFO_HEAD
        print_info("u2g fail. datasize[%d]", datasize);
    } else {
        strcpy(ch_url, tmpchar);
    }

    PRINT_DBG_HEAD
    print_dbg("decode request ok.cmd[%s] param[%s] queuenum[%d]", ch_cmd, ch_url,
              m_service->GetQueueNum());
    return true;
}

/**
 * [CHTTPSINGLE::DecodeReply 解析响应信息]
 * @param  sdata [网络层开始的数据包]
 * @param  slen  [数据包长度]
 * @return       [允许通过返回true]
 */
bool CHTTPSINGLE::DecodeReply(unsigned char *sdata, int slen)
{
    return false;
}

/**
 * [CHTTPSINGLE::IfRequest 是否为合法的HTTP方法]
 * @param  chrequest [输入的请求]
 * @return           [是合法的返回true]
 */
bool CHTTPSINGLE::IfRequest(const char *chrequest)
{
    char m_RequestCmd[][10] = {
        "OPTIONS", "TRACE", "GET", "HEAD", "DELETE",
        "PUT", "POST", "COPY", "MOVE", "MKCOL",
        "PROPFIND", "PROPPATCH", "LOCK", "UNLOCK", "SEARCH",
        "CONNECT"
    };

    for (int i = 0; i < (int)ARRAY_SIZE(m_RequestCmd); i++) {
        if (strcasecmp(chrequest, m_RequestCmd[i]) == 0) {
            return true;
        }
    }
    return false;
}

/*******************************************************************************************
*功能:       获取next数组
*参数:       key_str                        ----> 关键字符串
*            len                           ----> 字符串长度
*            next                          ----> next数组
*
*           返回值                          ----> void
*注释:
*******************************************************************************************/
void CHTTPSINGLE::get_next(const char *key_str, int len, int *next) {

    next[0] = -1;//-1代表没有重复子串
    int k = -1;
    for (int q = 1; q <= len; q++) {
        while ((k > -1) && (key_str[k + 1] != key_str[q])) {
            k = next[k];
        }

        if (key_str[k + 1] == key_str[q]) {
            k++;
            if (key_str[q] != key_str[k]) {
                next[q] = k;
            } else {
                next[q] = next[k];
            }

        }
    }
    return;
}

/*******************************************************************************************
*功能:       从主串中匹配子串
*参数:       main_str                           ----> 主串
*            main_len                          ----> 主串长度
*            key_str                           ----> 子串
*            key_len                           ----> 子串长度
*            next                              ----> next数组
*
*           返回值                              ---->  >=0 成功, -1 失败
*注释:
*******************************************************************************************/
int CHTTPSINGLE::index_str(const char *main_str, int main_len, const char *key_str, int key_len,int *next) {

    int k = -1;
    int i = 0;

    for (; i < main_len; i++) {
        while ((k > -1) && (key_str[k + 1] != main_str[i])) {
            k = next[k];
        }

        if (key_str[k + 1] == main_str[i]) {
            k++;
        }

        if (k == key_len - 1) {
            return (i - key_len + 1);
        }
    }
    return -1;
}
