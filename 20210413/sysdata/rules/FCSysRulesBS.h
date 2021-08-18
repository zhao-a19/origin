/*******************************************************************************************
*文件:  FCSysRulesBS.h
*描述:  系统规则业务类
*作者:  王君雷
*日期:  2016-03
*修改:
*       可以设置每条规则的并发数                                        ------>  2016-08-16
*       组播使用英语multicast代理拼音                                   ------>  2018-02-05
*       使用zlog记录日志；加入光闸网闸视频联动功能                      ------>  2018-04-12
*       读取视频代理联动相关的配置信息                                  ------>  2018-06-06
*       支持多个转发节点的视频联动                                      ------>  2018-07-14
*       支持PDT互联                                                     ------>  2018-07-31
*       支持私有协议文件同步；无参函数加void                            ------>  2018-08-30
*       时间模式，封装为单独的类                                        ------>  2018-11-03
*       支持平台互联功能                                                ------>  2019-07-31 -dzj
*       路由和代理模式支持指定出口IP                                    ------>  2019-11-07 -dzj
*       变量名称拼写错误                                                ------>  2019-12-09 -dzj
*       添加服务汇总表，同一个服务只new一次，多个规则可以共用           ------>  2020-02-06 -wjl
*       添加对象汇总表，同一个对象只new一次，多个规则可以共用           ------>  2020-02-07 -wjl
*       读取普通规则的逻辑移到本类中，为接下来的修改做准备              ------> 2020-07-01 -wjl
*       取消后台对规则条数的限制                                        ------> 2020-07-03 wjl
*       支持RFC3261平台互联                                            ------> 2020-08-18 wjl
*       文件交换支持分模块生效                                          ------> 2020-11-10
*       组播策略支持分模块生效                                          ------> 2020-11-12
*       WEB代理支持分模块生效                                           ------> 2020-11-18
*******************************************************************************************/
#ifndef __FC_SYSRULESBS_H__
#define __FC_SYSRULESBS_H__

#include "FCObjectBS.h"
#include "FCServiceConf.h"
#include "fileoperator.h"
#include "FCMulticast.h"
#include "FCFileSync.h"
#include "FCDBSyncInGap.h"
#include "FCBonding.h"
#include "FCWebProxy.h"
#include "timemod.h"
#include "secway.h"

#include "FCSipNorm.h"
#include "FCSipLink.h"
#include "FCClientSipNorm.h"
#include "FCClientSipLink.h"
#include "pdtcommon.h"
#include "SipInterConnect.h"
#include "pvt_filesync.h"
#include "rfc3261.h"

//规则类
class CSYSRULES
{
public:
    CSYSRULES(void);
    virtual ~CSYSRULES(void);
    //操作规则名称
    bool SetName(const char *cname);
    bool GetName(char *cname);
public:
    char m_name[RULE_NAME_LEN];
    int m_occurs;
    bool Action;
    char m_specsip[IP_STR_LEN];   //指定的网闸出口IP
    int m_sobjectnum;  //源对象个数
    COBJECT *m_sobject[C_OBJECT_MAXNUM];
    int m_dobjectnum;  //目标对象个数
    COBJECT *m_dobject[C_OBJECT_MAXNUM];
    int m_servicenum;
    CSERVICECONF *m_service[C_SERVICE_MAXNUM];
    TIME_MOD m_timemod;
    SEC_WAY m_secway;
};

//系统规则业务
class CSYSRULESBUSINESS
{
public:
    CSYSRULESBUSINESS(void);
    virtual ~CSYSRULESBUSINESS(void);
    bool ClearAllData(void);
    int ImportRules(const char *filename);
    int ImportRule(const char *ruleitem);
    int ImportMulticast(const char *filename);
    int ImportSipNorm(const char *filename);
    int ImportSipLink(const char *filename);
    int ImportClientSipNorm(const char *filename);
    int ImportClientSipLink(const char *filename);
    int ImportDBSync(const char *filename);
    int ImportBonding(const char *filename);
    int ImportPDTCommon(const char *filename);
    int ImportSipInterConnect(const char *filename);
    int ImportPVTFileSync(const char *filename);
    int ImportRFC3261(const char *filename);

private:
    //查询模板
    int Find(const char *chname);
    void AddObject(COBJECT *pobj);
    void AddService(CSERVICECONF *pser);
    void AddNetWay(int modnum, SEC_WAY &secway);
    int AddRule(const char *chname);
    CSipNorm *AddSipNorm(void);
    CSipLink *AddSipLink(void);
    CPDTCommon *AddPDTCommon(void);
    CClientSipNorm *AddClientSipNorm(void);
    CClientSipLink *AddClientSipLink(void);
    CSipInterConnect *AddSipInterConnect(void);
    CDBSyncTask *AddDBSync(void);
    void ImportBondingSide(CBonding **ppbonding, const char *areaitem);
    CSERVICECONF *FindServByName(const char *chname);
    int RegisterService(CSERVICECONF *pserv);
    void CustomHSYTWeb(CSERVICECONF *pserv);
    void CustomHSYTDB(CSERVICECONF *pserv);
    COBJECT *FindObjectByName(const char *chname);
    int RegisterObject(COBJECT *pobj);

public:
    CFILEOP m_fileop;
    int m_sysrulenum;
    CSYSRULES **m_sysrule;

    int m_objectnum;
    COBJECT *m_object[C_OBJECT_MAXNUM];
    vector<COBJECT *> m_object_summary;

    int m_servicenum;
    CSERVICECONF *m_service[C_SERVICE_MAXNUM];
    vector<CSERVICECONF *> m_serv_summary;

    int m_sipnormnum;
    CSipNorm *m_sipnorm[C_SIP_MAXNUM];

    int m_clientsipnormnum;
    CClientSipNorm *m_clientsipnorm[C_SIP_MAXNUM];

    PVT_FILESYNC_MG m_pvt_filesync_mg;
    FILESYNC_MG m_filesync_mg;
    MulticastMG m_multicast_mg;
    WebProxyMG m_webproxy_mg;

    int m_dbsync_tasknum;
    CDBSyncTask *m_dbsync[C_DBSYNC_MAXNUM];

    CBonding *m_inbonding;
    CBonding *m_outbonding;

    int m_siplinknum;
    CSipLink *m_siplink[C_SIP_LINK_MAXNUM];

    int m_clientsiplinknum;
    CClientSipLink *m_clientsiplink[C_SIP_LINK_MAXNUM];

    int m_pdt_com_num;
    CPDTCommon *m_pdtcom[PDT_COMMON_RULE_NUM];

    int m_sipinterconnectnum;
    CSipInterConnect *m_sipinterconnect[C_SIP_MAXNUM];

    int m_rfc3261_tasknum;
    RFC3261SIP **m_rfc3261;
};

#endif
