/*******************************************************************************************
*文件: FCFgapCmd.cpp
*描述: 与光闸视频联动  使用该类的对象与光闸通信
*作者: 王君雷
*日期: 2018-04-15
*修改:
*      使用zlog记录更详细的出错信息，修改Add Del等函数返回值类型，开发过程版 ----> 20180521
*      编写Add、Del等函数；协议字段的命名尽量与单向保持一致；协议格式有调整  ----> 20180608
*******************************************************************************************/
#include "FCFgapCmd.h"
#include "debugout.h"
#include "define.h"

CFgapCmd::CFgapCmd(const char *ip, unsigned short port)
{
    m_port = port;
    if (strlen(ip) < sizeof(m_ip)) {
        strcpy(m_ip, ip);
    } else {
        PRINT_ERR_HEAD
        print_err("ip too long[%s],sizeof(m_ip)=[%d]", ip, (int)sizeof(m_ip));
    }

    srand(time(NULL));
}

CFgapCmd::~CFgapCmd()
{
}

/**
 * [CFgapCmd::Clear 要求光闸清空所有已建立的通道]
 * @return [返回值含义见本文件对应的头文件]
 */
int CFgapCmd::Clear()
{
    return ReqNoBody(TYPE_CLEAR);
}

/**
 * [CFgapCmd::Online 检查光闸是否在线]
 * @return [返回值含义见本文件对应的头文件]
 */
int CFgapCmd::Online()
{
    return ReqNoBody(TYPE_ONLINE);
}

/**
 * [CFgapCmd::ReqNoBody 发出请求并接收响应信息（请求只包含头部，没有请求体）]
 * @param  cmd [请求类型]
 * @return     [返回值含义见本文件对应的头文件]
 */
int CFgapCmd::ReqNoBody(int cmd)
{
    int retval = RESULT_OTHER_ERROR;
    int ret = 0, rlen = 0, slen = 0;
    char recvbuff[FGAP_CMD_BUFF_LEN] = {0};
    FGAP_RESPONSE_HEAD resphead;
    FGAP_REQUEST_HEAD reqhead;
    BZERO(resphead);
    BZERO(reqhead);

    struct timeval tvs, tvr;
    tvs.tv_sec = SECOND_TIMEOUT;
    tvs.tv_usec = 0;
    tvr.tv_sec = SECOND_TIMEOUT;
    tvr.tv_usec = 0;

    strcpy(reqhead.check, CHECK_KEYWORD);
    reqhead.version = CURRENT_VER;
    reqhead.id = rand();
    reqhead.cmd = cmd;
    reqhead.bodylen = 0;
    slen = sizeof(reqhead);
    Decode(&reqhead, slen);

    int sock = sockcli.Open(m_ip, m_port);
    if (sock > 0) {

        //设置发送超时
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tvs, sizeof(tvs));

        while (slen > 0) {
            ret = send(sock, &reqhead, slen, 0);
            if (ret > 0) {
                slen -= ret;
            } else {
                PRINT_ERR_HEAD
                print_err("send error[%s], ret=[%d], cmd=[%d]", strerror(errno), ret, cmd);
                goto _out;
            }
        }

        //设置接收超时
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tvr, sizeof(tvr));

        while (rlen < (int)sizeof(resphead)) {
            ret = recv(sock, recvbuff + rlen, sizeof(recvbuff) - rlen, 0);
            if (ret > 0) {
                rlen += ret;
            } else {
                PRINT_ERR_HEAD
                print_err("recv error[%s], ret=[%d], cmd=[%d]", strerror(errno), ret, cmd);
                goto _out;
            }
        }

        memcpy(&resphead, recvbuff, sizeof(resphead));
        Decode(&resphead, sizeof(resphead));

        if ((resphead.id == reqhead.id)
            && (resphead.cmd == reqhead.cmd)) {
            retval = resphead.result;

            if (retval == RESULT_VER_ERROR) {
                PRINT_ERR_HEAD
                print_err("fgap ver is [%d], myver is [%d], cmd=[%d]",
                          resphead.version, CURRENT_VER, cmd);
            }
        }
    } else {
        PRINT_ERR_HEAD
        print_err("socket open error,m_ip[%s],m_port[%d],cmd=[%d]", m_ip, m_port, cmd);
    }

_out:
    CLOSE(sock);
    return retval;
}

/**
 * [CFgapCmd::Add 添加通道]
 * @param rname          [规则名称]
 * @param fgap_recvip    [光闸代理IP，光闸在该IP上接收媒体流]
 * @param fgap_sendip    [光闸代理出口IP，光闸通过该IP把媒体流转发给realip]
 * @param fgap_recvport  [光闸代理端口，光闸在该端口上接收媒体流]
 * @param realip         [最终的真实接收者IP]
 * @param realport       [最终的真实接收者端口]
 * @return               [返回值含义见本文件对应的头文件]
 */
int CFgapCmd::Add(const char *rname,
                  const char *fgap_recvip, const char *fgap_sendip,
                  const char *fgap_recvport,
                  const char *realip, const char *realport)
{
    return ReqWithBody(rname, fgap_recvip, fgap_sendip, fgap_recvport, realip, realport, TYPE_ADD);
}

/**
 * [CFgapCmd::Del 删除通道]
 * @param rname          [规则名称]
 * @param fgap_recvip    [光闸代理IP，光闸在该IP上接收媒体流]
 * @param fgap_sendip    [光闸代理出口IP，光闸通过该IP把媒体流转发给realip]
 * @param fgap_recvport  [光闸代理端口，光闸在该端口上接收媒体流]
 * @param realip         [最终的真实接收者IP]
 * @param realport       [最终的真实接收者端口]
 * @return               [返回值含义见本文件对应的头文件]
 */
int CFgapCmd::Del(const char *rname,
                  const char *fgap_recvip, const char *fgap_sendip,
                  const char *fgap_recvport,
                  const char *realip, const char *realport)
{
    return ReqWithBody(rname, fgap_recvip, fgap_sendip, fgap_recvport,
                       realip, realport, TYPE_DELETE);
}

/**
 * [CFgapCmd::ReqWithBody 发出请求并接收响应信息（请求包含头部和请求体）]
 * @param rname          [规则名称]
 * @param fgap_recvip    [光闸代理IP，光闸在该IP上接收媒体流]
 * @param fgap_sendip    [光闸代理出口IP，光闸通过该IP把媒体流转发给realip]
 * @param fgap_recvport  [光闸代理端口，光闸在该端口上接收媒体流]
 * @param realip         [最终的真实接收者IP]
 * @param realport       [最终的真实接收者端口]
 * @return               [返回值含义见本文件对应的头文件]
 */
int CFgapCmd::ReqWithBody(const char *rname,
                          const char *fgap_recvip, const char *fgap_sendip,
                          const char *fgap_recvport,
                          const char *realip, const char *realport, int cmd)
{
    int retval = RESULT_OTHER_ERROR;
    int ret = 0, rlen = 0, slen = 0;
    char sendbuff[FGAP_CMD_BUFF_LEN] = {0};
    char recvbuff[FGAP_CMD_BUFF_LEN] = {0};
    FGAP_RESPONSE_HEAD resphead;
    FGAP_REQUEST_HEAD reqhead;
    FGAP_REQUEST_BODY reqbody;
    BZERO(resphead);
    BZERO(reqhead);
    BZERO(reqbody);

    struct timeval tvs, tvr;
    tvs.tv_sec = SECOND_TIMEOUT;
    tvs.tv_usec = 0;
    tvr.tv_sec = SECOND_TIMEOUT;
    tvr.tv_usec = 0;

    strcpy(reqhead.check, CHECK_KEYWORD);
    reqhead.version = CURRENT_VER;
    reqhead.id = rand();
    reqhead.cmd = cmd;
    reqhead.bodylen = sizeof(reqbody);
    strncpy(reqbody.rulename, rname, sizeof(reqbody.rulename) - 1);
    reqbody.fgap_recvport = atoi(fgap_recvport);
    reqbody.recvport = atoi(realport);
    strcpy(reqbody.fgap_recvip, fgap_recvip);
    strcpy(reqbody.fgap_sendip, fgap_sendip);
    strcpy(reqbody.recvip, realip);

    memcpy(sendbuff, &reqhead, sizeof(reqhead));
    memcpy(sendbuff + sizeof(reqhead), &reqbody, sizeof(reqbody));
    slen = sizeof(reqhead) + sizeof(reqbody);
    Decode(sendbuff, slen);

    int sock = sockcli.Open(m_ip, m_port);
    if (sock > 0) {

        //设置发送超时
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tvs, sizeof(tvs));

        while (slen > 0) {
            ret = send(sock, sendbuff, slen, 0);
            if (ret > 0) {
                slen -= ret;
            } else {
                PRINT_ERR_HEAD
                print_err("send error[%s], ret=[%d], cmd=[%d]", strerror(errno), ret, cmd);
                goto _out;
            }
        }

        //设置接收超时
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tvr, sizeof(tvr));

        while (rlen < (int)sizeof(resphead)) {
            ret = recv(sock, recvbuff + rlen, sizeof(recvbuff) - rlen, 0);
            if (ret > 0) {
                rlen += ret;
            } else {
                PRINT_ERR_HEAD
                print_err("recv error[%s], ret=[%d], cmd=[%d]", strerror(errno), ret, cmd);
                goto _out;
            }
        }

        memcpy(&resphead, recvbuff, sizeof(resphead));
        Decode(&resphead, sizeof(resphead));

        if ((resphead.id == reqhead.id)
            && (resphead.cmd == reqhead.cmd)) {
            retval = resphead.result;

            if (retval == RESULT_VER_ERROR) {
                PRINT_ERR_HEAD
                print_err("fgap ver is [%d], myver is [%d], cmd=[%d]",
                          resphead.version, CURRENT_VER, cmd);
            }
        }
    } else {
        PRINT_ERR_HEAD
        print_err("socket open error,m_ip[%s],m_port[%d],cmd=[%d]", m_ip, m_port, cmd);
    }

_out:
    CLOSE(sock);
    return retval;
}

/**
 * [CFgapCmd::Decode 加解密函数]
 * @param buff    [待加解密的信息缓冲区]
 * @param bufflen [待加解密的信息缓冲区长度]
 */
void CFgapCmd::Decode(void *buff, int bufflen)
{

}

