/*******************************************************************************************
*文件:  sip_struct.h
*描述:  平台级联和视频代理都需要使用的一些宏和结构定义 放在了这里
*作者:  王君雷
*日期:  2018-07-11
*修改:
*       SIP单包最大支持长度从600000缩小为64K                                  ------> 2018-08-23
*       平台级联每条策略的通道个数由10000缩小为1000
*       视频代理每条策略的通道个数由4000缩小为1000.目的是控制iptables不要太多 ------> 2018-11-16
*       SIP替换IP代码接口封装，针对厂家接口封装                               -------> 2019-06-03
*       SIP关键字长度定义                                                     -------> 2019-06-03
*       修改SIP没有content_len字段时的处理                                    ------> 2019-06-27 --dzj
*       加入平台互联相关宏信息                                                ------> 2019-07-31 --dzj
*       添加媒体流为TCP时的主动方向识别宏                                     ------> 2019-08-03 --dzj
*       将视频代理的客户端登记结构移动到此和互联代理模块共用                  ------> 2019-08-07 --dzj
*       将视频代理的客户端登记时长宏移动到此共用                              ------> 2019-08-14 --dzj
*       添加宏SIP_SYSTEM                                                   ------> 2020-05-15 wjl
*******************************************************************************************/
#ifndef __SIP_STRUCT_H__
#define __SIP_STRUCT_H__

#include "define.h"

#define C_SIP_KEY_WORLD_LEN 32   //SIP请求关键字段长度
#define SIP_RULE_NAME_LEN 100  //规则名字最大长度
#define C_SIP_MAXNUM 200       //平台级联 视频代理 支持规则最大数 20141011
#define C_SIP_LINK_MAXNUM 20   //平台级联联动 视频代理联动 支持规则最大数
#define SIP_MAX_NODE 256       //每条联动策略最多支持的转发节点数
#define SIP_CALL_ID_LEN 256    //会话ID的最大支持长度
#define SIP_CONTENT_TYPE_LEN 256
#define SIP_MAX_PACKET (64 * 1024) //SIP单包最大支持长度
#define SIP_MAX_LINE_SIZE 8192 //分析出的每行内容最大支持长度
#define SIP_MAX_LINE_NUM 18000 //接收到的数据包 最多允许包含的行数
#define SIP_NODE_MAX_WEIGHT 10 //视频联动节点权重最大值
#define SIP_NODE_TEST_INTERVAL 10 //测试节点状态的间隔时间
#define SIP_TIME_OUT(a) (abs(a) > SIP_NODE_TEST_INTERVAL) //超时判断
#define SIP_NODE_WEIGHT_EXPRESS(a) (5 + (a))    //权重公式
#define SIP_NAT_PORT_START 10000 //平台级联联动 调度命令内部NAT跳转开始使用的端口
#define SIP_CLI_NAT_PORT_START (SIP_NAT_PORT_START + SIP_MAX_NODE * C_SIP_LINK_MAXNUM) //视频代理联动 调度命令内部NAT跳转开始使用的端口
#define IS_TYPE_OF(a, b) (strncasecmp((a), (b), strlen(b)) == 0)
#define SIP_NORM_MAX_CHANNEL 1000
#define CLI_SIP_NORM_MAX_CHANNEL 1000
#define SIP_PKT_LEN_CHANGE 32 //数据包可能会因为信息替换而 变长 或者 变短，预留长度

#define SIP_LINK_PORT_OFFSET 2000 //联动节点的前 n个端口不使用
#define SIP_LINK_TOTAL_CHANNEL  30000 //平台级联联动 所有策略使用的总的通道端口个数
#define SIP_LINK_CLI_TOTAL_CHANNEL  30000 //视频代理联动 所有策略使用的总的通道端口个数
#define SIP_CONF_KEY_NAME_LEN 32

#define SECONDS_PER_HOUR (60 * 60)
#define MAX_SIP_CLIENT 300         //每个客户端起一个线程 此值不能太大（一个IP只占一个客户端）
#define C_CLI_SIPDYNAMICPORT 6000  //传输sip的动态端口 开始端口
#define CHANNEL_TIME_OUT_SECOND 600 //通道超过这么多秒没被使用过时才复用这个通道

//SIP协议关键字段
#define SIP_INVITE_VALUE        "INVITE"
#define SIP_UPDATE_VALUE        "UPDATE"
#define SIP_ACK_VALUE           "ACK"
#define SIP_PRACK_VALUE         "PRACK"
#define SIP_BYE_VALUE           "BYE"
#define SIP_REGISTER_VALUE      "REGISTER"
#define SIP_CANCEL_VALUE        "CANCEL"
#define SIP_MESSAGE_VALUE       "MESSAGE"
#define SIP_VIA_VALUE           "VIA:"
#define SIP_CONTACT_VALUE       "CONTACT:"
#define SIP_OINIP4_VALUE        "o="
#define SIP_CINIP4_VALUE        "c=IN IP4 "
#define SIP_CINIP6_VALUE        "c=IN IP6 "
#define SIP_CONTENTLEN_VALUE    "Content-Length"
#define SIP_VIDEO_VALUE         "m=video "
#define SIP_AUDIO_VALUE         "m=audio "
#define SIP_TRANSFER_VALUE      "a=setup:"
#define SIP_CALLID_VALUE        "Call-ID"
#define SIP_FROM_VALUE          "From:"
#define SIP_TO_VALUE            "To:"
#define SIP_NOTIFY_VALUE        "NOTIFY"

//SIP协议关键字段转换为int型标志
enum {
    SIP_INVITE_KEY = 1,
    SIP_UPDATE_KEY,
    SIP_ACK_KEY,
    SIP_PRACK_KEY,
    SIP_BYE_KEY,         //5
    SIP_REGISTER_KEY,
    SIP_CANCEL_KEY,
    SIP_MESSAGE_KEY,
    SIP_VIA_KEY,
    SIP_CONTACT_KEY,     //10
    SIP_OINIP4_KEY,
    SIP_CINIP4_KEY,
    SIP_CINIP6_KEY,
    SIP_CONTENTLEN_KEY,
    SIP_MVIDEO_KEY,      //15
    SIP_MAUDIO_KEY,
    SIP_TRANSFER_KEY,
    SIP_CALLID_KEY,
    SIP_FROM_KEY,
    SIP_TO_KEY,
    SIP_NOTIFY_KEY,
    SIP_OTHER_KEY
};

enum {
    STATUS_FREE = 0, STATUS_INUSE = 1, STATUS_WAIT = 2
};

//SIP关键字对应行需要对应不同厂家需求替换处理接口
class CSipReplaceInterface
{
public:
    void replaceFrom(char *line, struct SIP_INFO *sip_info);
    void replaceTo(char *line, struct SIP_INFO *sip_info);
    void replaceVia(char *line, struct SIP_INFO *sip_info);
};

//不同厂家处理接口
class CSipVendorsHandleInterface
{
protected:
    CSipReplaceInterface replaceInterface;//sip每行关键字对应替换接口
public:
    int handleHikvision(char *recvstr, struct SIP_INFO *sip_info);
    int handleDahua(char *recvstr, struct SIP_INFO *sip_info);
    int handleH3c(char *recvstr, struct SIP_INFO *sip_info);
    int handleHuawei(char *recvstr, struct SIP_INFO *sip_info);
    int handlePublic(char *recvstr, struct SIP_INFO *sip_info);
    int handleTiandy(char *recvstr, struct SIP_INFO *sip_info);
    int handleTsd(char *recvstr, struct SIP_INFO *sip_info);
    int handleUniview(char *recvstr, struct SIP_INFO *sip_info);
    int handleKedacom(char *recvstr, struct SIP_INFO *sip_info);
    int handleSumavision(char *recvstr, struct SIP_INFO *sip_info);
    int handleSharpwisdom(char *recvstr, struct SIP_INFO *sip_info);
    int handleUnimas(char *recvstr, struct SIP_INFO *sip_info);
    int handleHanbanggaoke(char *recvstr, struct SIP_INFO *sip_info);
    int handleDongfang(char *recvstr, struct SIP_INFO *sip_info);
    int handleVitechViss(char *recvstr, struct SIP_INFO *sip_info);
};

struct SIP_INFO {
    bool b_bye;                     //该报文是否是bye
    bool fromUpplat;                //上级平台为true，下级平台为false
    int key_flag;                   //报文里关键字对应标志
    int contlen;                    //该报文变更后的长度
    char ctmpip[IP_STR_LEN];        //INVITE报文中接受视频流的IP地址
    char callid_str[SIP_CALL_ID_LEN];//该报文的CALLID
    char *m_upplatip;               //上级平台IP
    char *m_gapinip;                //网闸内网侧IP
    char *m_gapoutip;               //网闸外网侧IP
    char *m_downplatip;             //下级平台IP
};

//SIP客户端登记表
typedef struct SIP_CLIENT_REGTAB {
    sockaddr_in cliaddr;
    int fd;
    int bindport;
    int inuse;//在使用
    time_t updatetime;//最后更新时间 发送或接收消息后，更新这个字段
} SIP_CLIENT_REGTAB;


#pragma pack(push, 1)
//媒体传输通道登记表
typedef struct MediaChannel {
    char myport[PORT_STR_LEN];        //代理接收视频流的端口
    char media_recvip[IP_STR_LEN];    //媒体接收者真实IP
    char media_recvport[PORT_STR_LEN];//媒体接收者真实端口
    char callid[SIP_CALL_ID_LEN];     //会话ID
    time_t tm;                        //使用通道的时间
    bool able;                        //通道可用
} MediaChannel;

//转发节点
typedef struct ForwardNode {
    int id;
    int weight;
    unsigned short cmdport; //接收调度命令使用的端口号
    char comeip[IP_STR_LEN];//接收视频流的IP
    char goip[IP_STR_LEN];  //发送视频流的IP
    char natip[IP_STR_LEN]; //内部跳转NAT IP
    unsigned short natport; //内部跳转NAT port
    bool online;            //是否在线
    time_t testtm;          //探测在线状态的时刻

    MediaChannel *pchannel;//每个转发节点 有一份通道表
} ForwardNode;

#pragma pack(pop)

#define SIP_SYSTEM(chcmd) \
system(chcmd); \
PRINT_DBG_HEAD \
print_dbg("%s", chcmd);

#endif
