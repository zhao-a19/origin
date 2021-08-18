/*******************************************************************************************
*文件:  card_mg.h
*描述:  策略使用到的网卡汇总管理
*作者:  王君雷
*日期:  2020-10-22
*修改:
*******************************************************************************************/
#ifndef __CARD_MG_H__
#define __CARD_MG_H__
using namespace std;
#include <string>
#include <vector>

#define MOD_INFO_HANDLER(__num, __name)  \
{ \
    (__num), (__name), sizeof(__name) - 1 \
}

typedef struct _mod_info_type {
    int modnum;
    const char *name;
    unsigned int len;
} MOD_INFO_TYPE, *PMOD_INFO_TYPE;

enum MOD_NUM {
    NORMAL_RULE_MOD = 0,//普通规则
    DBSYNC_MOD, //数据库同步
    FILESYNC_MOD, //文件交换
    FILESYNC_PRIV_MOD, //私有文件交换
    WEBPROXY_MOD, //WEB代理
    MULTICAST_MOD, //组播策略
    SIP_NORMAL_MOD,//平台级联
    SIP_CLI_NORMAL_MOD, //视频代理
    SIP_LINK_MOD, //平台级联联动
    SIP_CLI_LINK_MOD, //视频代理联动
    GB28181_INTER_MOD,//视频互联28181
    RFC3261_MOD,//视频互联RFC3261
    PDT_MOD,//PDT互联
};

const struct _mod_info_type g_modinfo[] = {
    MOD_INFO_HANDLER(NORMAL_RULE_MOD, "normalrule"),
    MOD_INFO_HANDLER(DBSYNC_MOD, "dbsync"),
    MOD_INFO_HANDLER(FILESYNC_MOD, "msync"),
    MOD_INFO_HANDLER(FILESYNC_PRIV_MOD, "fileclient"),
    MOD_INFO_HANDLER(WEBPROXY_MOD, "webprxoy"),
    MOD_INFO_HANDLER(MULTICAST_MOD, "multicast"),
    MOD_INFO_HANDLER(SIP_NORMAL_MOD, "sipnormal"),
    MOD_INFO_HANDLER(SIP_CLI_NORMAL_MOD, "sipclinormal"),
    MOD_INFO_HANDLER(SIP_LINK_MOD, "siplink"),
    MOD_INFO_HANDLER(SIP_CLI_LINK_MOD, "sipclilink"),
    MOD_INFO_HANDLER(GB28181_INTER_MOD, "gb28181"),
    MOD_INFO_HANDLER(RFC3261_MOD, "rfc3261"),
    MOD_INFO_HANDLER(PDT_MOD, "pdt"),
};

typedef struct _mod_card {
    MOD_NUM modnum;
    vector<int> vec_in;
    vector<int> vec_out;
} MOD_CARD;

class CardMG
{
public:
    CardMG(void);
    virtual ~CardMG(void);
    void clear(void);
    void clear(int modnum);
    void add(int modnum, int incard, int outcard);
    void add(int modnum, int card, bool isout);
    int getTotal(void);
    MOD_CARD *getMod(int modnum);
    void analysis(void);
    vector<int> &getInVec(void);
    vector<int> &getOutVec(void);
    int getInVec(int id);
    int getOutVec(int id);
    void show(void);
    void showMod(void);
    void showAnalysis(void);

private:
    void push(vector<int> &vec, int card);

private:
    int m_total;
    MOD_CARD m_card[sizeof(g_modinfo) / sizeof(g_modinfo[0])];

    vector<int> m_vec_in; //存放汇总后无重复的网卡信息
    vector<int> m_vec_out;//存放汇总后无重复的网卡信息
};

#endif
