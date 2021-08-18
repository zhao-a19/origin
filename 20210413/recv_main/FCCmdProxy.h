/*******************************************************************************************
*文件:  FCCmdProxy.h
*描述:  命令代理处理类
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_CMD_PROXY_H__
#define __FC_CMD_PROXY_H__

int CmdProxyInit(void);
int cmdproxy_putmsg(const char *cmd, int len);
int StartCmdProxyServer(void);

#endif
