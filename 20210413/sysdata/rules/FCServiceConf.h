/*******************************************************************************************
*文件:  FCServiceConf.h
*描述:  应用服务类
*作者:  王君雷
*日期:  2016-03
*修改:
*       CSERVICECONF 添加以该类指针为参数的构造函数          ------> 2018-03-14
*       每个服务对应唯一的一个iptables队列，一个iptables队列可以对应多个服务 ------> 2019-01-30
*       增加应用名称的MD5值成员变量                                       ------> 2021-03-24
*       添加NameEq()重载函数                                             ------> 2021-05-07
*******************************************************************************************/
#ifndef __FC_SERVICE_CONF_H__
#define __FC_SERVICE_CONF_H__

#include "define.h"

//2017-10-10 改变字段长度
class CCMDCONF
{
public:
    CCMDCONF(void);
    CCMDCONF(const CCMDCONF *pcmd);
    virtual ~CCMDCONF(void);

    bool HexToStr(const char *ch, int len);
    int HexCharToValue(const char ch);
    int m_start;
    char m_cmd[MAX_CMD_NAME_LEN];
    char m_sign[MAX_PARA_NAME_LEN];
    char m_parameter[MAX_PARA_NAME_LEN];
    bool  m_action;

    int m_strlen;//16进制转换为字符串后的长度
    char m_str[128];//16进制转换后的字符串
};

class CSERVICECONF
{
public:
    CSERVICECONF(void);
    CSERVICECONF(const CSERVICECONF *pser);
    CSERVICECONF(const char *chname);
    virtual ~CSERVICECONF(void);
    void SetQueueNum(int queuenum);
    int GetQueueNum(void);
    const char *GetProtocol(void);
    void GetNameMd5(void);
    bool NameEq(const char *name);
    bool NameEq(const char *name, const char *namemd5);

public:
    CCMDCONF *m_cmd[C_MAX_CMD];
    int m_cmdnum;
    char m_name[APP_NAME_LEN];            //服务名称 （类似数据库的主键 不同应用不会重复）
    char m_namemd5[40];                   //应用名称的MD5值
    char m_protocol[TRANSPORT_PROTO_LEN]; //服务采用的协议 TCP/UDP/ICMP...
    char m_sport[PORT_STR_LEN];           //源端口号
    char m_dport[PORT_STR_LEN];           //目标端口号
    char m_tport[PORT_STR_LEN];           //代理端口号
    char m_asservice[APP_MODEL_LEN];      //应用层所属模块 HTTP/POP3/SMTP....
    bool m_IfExec;                        //服务没有定义的命令是否允许执行
    bool m_cklog;                         //是否记录日志
private:
    int m_queuenum;                       //对应的iptables NFQUEUE 的队列号
};

#endif
