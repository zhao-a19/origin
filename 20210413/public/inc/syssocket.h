/*******************************************************************************************
*文件:    syssocket.h
*描述:    基础网络通讯TCP&UDP，支持简单数据加密
*         创建通讯的基本过程(CSYSSOCKET)
*         1) createsocket
*         2) setaddress
*         3) setconnect
*         4) getconnect（TCP服务器调用）
*         5) writesocket、readsocket
*         6) closesocket
*
*作者:    张冬波
*日期:    2015-01-12
*修改:    创建文件                            ------>     2015-01-12
*         添加专有类，实现文件传输和单向可靠传输
*                                             ------>     2015-01-14
*         专用类增加缓冲机制，提高socket接收速度
*                                             ------>     2015-02-12
*         提高缓冲池大小，确保特殊情况下有足够的空间
*                                             ------>     2015-02-26
*         增加消息队列配置                    ------>     2015-03-16
*         修改文件接收，返回文件大小          ------>     2015-03-18
*         添加读取socket属性                  ------>     2015-03-25
*         添加socket阻塞设置                  ------>     2015-04-13
*         添加关闭特定socket接口              ------>     2015-05-20
*         添加socket控制接口                  ------>     2015-05-26
*         添加单向传输延时设置                ------>     2015-06-11
*         单向传输支持丢包，以及修改文件接口
*                                             ------>     2015-07-27
*         添加获取客户端地址                  ------>     2015-11-19
*         修改closesocket接口错误, 添加获取网卡MAC
*                                             ------>     2015-11-27
*         修改接口                            ------>     2015-12-07
*         添加超时接口                        ------>     2016-12-27
*         修改参数定义，记录总包数            ------>     2017-02-23
*         获取重复及延时参数                 ------>     2019-01-02
*
*******************************************************************************************/
#ifndef __SYSSOCKET_H__
#define __SYSSOCKET_H__

#include "datatype.h"
#include <arpa/inet.h>
#include <netinet/in.h>

#define SUQCACHE    1           //数据包乱序缓冲
#define SUFILETEST  1           //文件处理

typedef int SYSSOCKET;
enum SOCKETTYPE {
    SOCKET_TCP = 1,             //协议属性
    SOCKET_UDP,

    SOCKET_SRV = 5,             //应用属性
    SOCKET_CLIENT,

} ;

#define SOCKET_OK  (0)          //错误标志
#define SOCKET_ERR (-1)

/**
 * 基础类定义
 */
class CSYSSOCKET
{
public:
    CSYSSOCKET();
    CSYSSOCKET(SOCKETTYPE type, bool encode = true);
    CSYSSOCKET(const CSYSSOCKET &obj);
    CSYSSOCKET(SOCKETTYPE type, bool encode, const pchar ip, uint16 port);

    virtual ~CSYSSOCKET();

    SYSSOCKET createsocket(SOCKETTYPE type);
    int32 closesocket(void);
    int32 closesocket(SYSSOCKET &s);
    bool settimeout(int32 timeout);                                                        //单位：秒
    static bool settimeout(SYSSOCKET s, int32 timeout);
    bool setaddress(uint32 ip, uint16 port);
    bool setaddress(const pchar ip, uint16 port);
    bool setaddress(const pchar ip, const pchar port);
    const SYSSOCKET getsocket(SOCKETTYPE type = SOCKET_CLIENT);
    bool getaddress(struct sockaddr_in *addr);
    bool getaddress(puint32 ip, puint16 port, bool self = false, pchar straddr = NULL);
    bool getmac(const pchar netcard, puint64 mac, pchar macstr = NULL);

    bool setconnect(SOCKETTYPE type);                                                      //服务器or客户端
    bool getconnect(int32 timeout);                                                        //服务器监听客户端连接, 阻塞方式
    bool getconnect(void);
    bool closeconnect(void);                                                               //服务器关闭客户连接

    int32 writesocket(const void *data, const int32 size);
    int32 readsocket(void *data, const int32 size);
    void setencode(bool disable = false);

    uint32 gettype(void);
    void setblock(bool enable = true);
    void setnodelay(bool enable = true);

    void setdatamore(bool enable = false);

    int32 geterrno(void);

    static bool clear_contrack(void);
protected:
    SOCKETTYPE m_type;
    SOCKETTYPE m_srv;

    int32 m_errno;
    SYSSOCKET  m_socket;
    SYSSOCKET  m_socketnew;
    int32 m_fcntl;

    bool m_encode;
    uint8 m_data[8 * 1024];
    puint8 m_pdata;
    bool m_datamore;
    int32 m_timeout;

    void datafree(void);

    static int32 dataencode(const puint8 src, int32 len, puint8 dst, bool decode = false);
    static int32 dataencode_size(const int32 len, bool decode = false);

private:
    struct sockaddr_in m_addr;
    int32 m_size;
    void init(void);
};

//引入IPV6支持
#include "syssocket6.h"
#define  _SSLIB_ IPV6_TAG

/**
 * 专有类定义
 */
//susetopt的key定义
enum {
    K_OPTRPT = 0xE0,        //重传次数
    K_OPTDLY,               //发送包延时
    K_OPTCHK,               //文件校验
};

//K_OPTCHK 参数值定义
enum {
    FILECHK_ALL = -1,      //全部校验
    FILECHK_CLOSE = 0,     //关闭校验
};

#if (_SSLIB_ == IPV6_TAG)
class CSUSOCKET: public CSYSSOCKET6
#else
class CSUSOCKET: public CSYSSOCKET
#endif
{
public:
    CSUSOCKET();
    CSUSOCKET(const pchar ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp);
    CSUSOCKET(CSUSOCKET &obj);
    virtual ~CSUSOCKET();

    bool suopen(const pchar ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp = SOCKET_UDP);
    bool suopen(uint32 ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp = SOCKET_UDP);
    bool suclose(void);

    bool sendfile(const pchar fpath);   //文件传输（双向）
    bool recvfile(const pchar fpath);

    int32 suwrite(const void *data, int32 size);
    int32 suread(void *data, int32 size);
    bool susetopt(uint8 key, const void *data);

#define SUFILEGUIDNULL  ((int64)0)      //数据库表设计，ID不能为0
#if SUFILETEST
    bool susendfile(const pchar fpath, int64 uid = SUFILEGUIDNULL);
    bool surecvfile(const pchar fpath, int64 &uid, puint64 size = NULL);
#else
    bool susendfile(const pchar fpath);
    bool surecvfile(const pchar fpath, puint64 size = NULL);
#endif

    static const pchar version;
    //消息队列配置
    static const uint32 msgmnb;
    static const uint32 msgmax;
    static void msgqueueset(void);
    static void msgqueueset(int32 msgmnb, int32 msgmax);

    //缓冲机制
    bool sustart(void);               //启动缓冲，创建接收线程
    bool suend(void);
    void suendq(void);
    int32 suwriteq(const void *data, int32 size);
    int32 sureadq(void *data, int32 size);

    int32 sugeterrno(void);

    uint8 getrepeat(void);
    int32 getdelayus(void);
    void setcpu(void);

protected:
    //缓冲机制
    volatile int32 m_threadflag;      //线程状态
    volatile key_t m_keyqueue;        //队列唯一值

private:
    int32 m_errno;
    uint8 m_filebuf[4096];            //确保大于文件路径限制，因为内部实现会用此缓冲区发送文件名路径
    uint8 m_unique[32];               //md5值
    uint8 m_repeat;
    int32 m_delayus;                  //单位us
    int32 m_filechk;                  //文件校验长度单位MB，-1：全部，0：关闭，>0：文件头数据块
    uint64 m_totalp;                  //发送总包数

    void init(void);

    //缓冲机制
    uint32 m_wrUNIQ;                  //写唯一值
    volatile uint32 m_rdUNIQ;         //缓冲池替换规则，需要对比客户当前读取序列
    uint32 m_curUNIQ;
#define SUPOOL_MAX  (16*1024ul)       //设置32有问题，不知道为什么？？！！
#define SUPOOL_MASK (SUPOOL_MAX-1)
    struct {
        uint32 UNIQ;
        time_t timestamp;
    } m_pool[SUPOOL_MAX];

#if SUQCACHE
#define SUQCACHE_L  200
    struct {
        uint32 cnt;
        void *packet[SUQCACHE_L + 1];
    } m_queuecache;                   //记录乱序包

    int32 _queuecache(int msgid, void *data, uint32 size);
    int32 _queuecache_err(void);
    void _queuecacheclear(void);

    time_t timeout_q;                 //超时处理，及时清理缓冲数据
#endif

    friend uint32 suisvalid(CSUSOCKET &obj, const puint8 data, uint32 size);
    friend void *_queuefunc_(void *arg);
    void initq(void);
};

//自定义errno值, 不要与系统冲突
enum {
    ESUSOCKET1 = 200,       //丢包
    ESUSOCKET2 = 201,       //非阻塞模式，无数据
};

//支持IPv6和IPv4
#if (_SSLIB_ == IPV6_TAG)
#define CSYSSOCKET_t CSYSSOCKET6
#else
#define CSYSSOCKET_t CSYSSOCKET
#endif

#endif

