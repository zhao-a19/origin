/*******************************************************************************************
*文件:  FCSysRuleBS.cpp
*描述:  系统规则业务类
*
*作者:  王君雷
*日期:  2015
*修改:  视频厂商宏使用英文翻译,改为UTF8编码,改用linux缩进格式           ------> 2018-01-23
*       支持ASM、SSM、FSM三种类型组播                                   ------> 2018-01-29
*       组播信源IP超过最大支持值时按最大支持值计算，而不是出错退出
*       组播使用英语multicast代理拼音                                   ------> 2018-02-05
*       读取配置文件，减少不必要的拷贝，读整形配置项使用ReadCfgFileInt,
*       重写AddService函数，使用DELETE宏                                ------> 2018-03-14
*       使用zlog记录日志；加入光闸网闸视频联动功能                      ------> 2018-04-12
*       视频相关函数命名统一风格                                        ------> 2018-04-23
*       读取视频代理联动相关的配置信息                                  ------> 2018-06-06
*       修改180428引入的错误,视频代理选项ClientIP错写为了CliIP          ------> 2018-06-21
*       支持多个转发节点的视频联动                                      ------> 2018-07-14
*       修改180714引入的错误，视频联动NodeWeight错写为了NodeWeitht      ------> 2018-07-23
*       视频相关规则的名称，把前后的单引号去除掉，否则记录日志时会组串错误
*                                                                       ------> 2018-07-24
*        加入PDT互联                                                    ------> 2018-07-31
*       支持私有协议文件同步;无参函数加void                             ------> 2018-08-30
*       修改负载均衡180423引入的BUG，bond类型读取有误                   ------> 2018-11-02
*       时间模式，封装为单独的类                                        ------> 2018-11-03
*       安全通道使用SEC_WAY类                                           ------> 2019-01-02
*       为每个服务分配一个队列                                          ------> 2019-01-30
*       AddService函数补充对ICMP6的处理                                 ------> 2019-02-12
*       解决20190130引入的BUG，WEBPROXY读取源对象IP类型变量用错         ------> 2019-06-24
*       支持平台互联功能                                                ------> 2019-07-31
*       路由和代理模式支持指定出口IP                                    ------> 2019-11-07 -dzj
*       形参名称拼写错误                                                ------> 2019-12-09-dzj
*       文件交换、数据库同步模块支持双机热备                            ------> 2019-12-19 wjl
*       添加服务汇总表，同一个服务只new一次，多个规则可以共用           ------> 2020-02-06 wjl
*       添加对象汇总表，同一个对象只new一次，多个规则可以共用           ------> 2020-02-07 -wjl
*       使用ARRAY_SIZE宏自动求数组大小，减少宏常数的使用               ------> 2020-05-15
*       使用新的读取配置文件接口，后台取消规则数限制，不再使用对象的方式
*       绑定IP MAC                                                     ------> 2020-07-03
*       支持RFC3261平台互联                                            ------> 2020-08-18 wjl
*       文件交换支持指定端口                                            ------> 2020-08-25
*       私有文件交换支持分模块生效                                       ------> 2020-11-05
*       文件交换支持分模块生效                                          ------> 2020-11-10
*       组播策略支持分模块生效                                          ------> 2020-11-12
*       WEB代理支持分模块生效                                           ------> 2020-11-18
*******************************************************************************************/
#include "FCSysRulesBS.h"
#include "FCYWBS.h"
#include "debugout.h"
#include "readcfg.h"
#include "card_mg.h"

extern CardMG g_cardmg;

CSYSRULES::CSYSRULES(void)
{
    m_occurs = 0;
    m_sobjectnum = 0;
    m_dobjectnum = 0;
    m_servicenum = 0;
    BZERO(m_service);
    BZERO(m_sobject);
    BZERO(m_dobject);
}

CSYSRULES::~CSYSRULES(void)
{
}

/**
 * [CSYSRULESBUSINESS::AddObject 添加对象]
 * CSYSRULESBUSINESS中有很多规则，每条规则中有很多对象，通过此函数，CSYSRULESBUSINESS会把本侧
 * 需要使用的对象，不重复的保留一份，用于后续进行对象MAC地址绑定
 * @param pobj [对象指针]
 */
void CSYSRULESBUSINESS::AddObject(COBJECT *pobj)
{
    if (pobj != NULL) {
        for (int i = 0; i < m_objectnum; i++) {
            if (strcmp(m_object[i]->m_objectname, pobj->m_objectname) == 0) {
                return ;
            }
        }

        if (m_objectnum == ARRAY_SIZE(m_object)) {
            PRINT_ERR_HEAD
            print_err("reach max suport objnum %d, ignore [%s]", ARRAY_SIZE(m_object), pobj->m_objectname);
            return ;
        }
        m_object[m_objectnum] = pobj;
        m_objectnum++;
    }
    return;
}

/**
 * [CSYSRULESBUSINESS::AddService 添加服务]
 * CSYSRULESBUSINESS中有很多规则，每条规则中有很多服务（应用），通过此函数，CSYSRULESBUSINESS会把本侧
 * 需要使用的服务，不重复的保留一份，用于后续创建数据处理对象，如CHTTPSINGLE等
 * @param pser [服务指针]
 */
void CSYSRULESBUSINESS::AddService(CSERVICECONF *pser)
{
    if (pser == NULL) {
        PRINT_ERR_HEAD
        print_err("add service para null");
        return;
    }

    for (int i = 0; i < m_servicenum; i++) {
        //是否已经存在
        if (strcmp(m_service[i]->m_name, pser->m_name) == 0) {
            //pser->SetQueueNum(m_service[i]->GetQueueNum());
            return;
        }
        //ICMP 应用只允许添加一个,ICMP6 应用也只允许添加一个
        if (((strcasecmp(pser->m_protocol, "ICMP") == 0) && (strcasecmp(m_service[i]->m_protocol, "ICMP") == 0))
            || ((strcasecmp(pser->m_protocol, "ICMP6") == 0) && (strcasecmp(m_service[i]->m_protocol, "ICMP6") == 0))) {
            //pser->SetQueueNum(m_service[i]->GetQueueNum());
            PRINT_INFO_HEAD
            print_info("you can't configure two diff %s service[%s][%s], the latter will be processed "
                       "according to the former", pser->m_protocol, m_service[i]->m_name, pser->m_name);
            return;
        }
    }
    if (m_servicenum == ARRAY_SIZE(m_service)) {
        PRINT_ERR_HEAD
        print_err("reach max suport servnum %d, ignore [%s]", ARRAY_SIZE(m_service), pser->m_name);
        return;
    }

    pser->SetQueueNum(m_servicenum % MAX_IPTABLES_QUEUE_NUM);
    m_service[m_servicenum] = pser;

    PRINT_DBG_HEAD
    print_dbg("begin add service[%s] queuenum[%d]", pser->m_name, pser->GetQueueNum());
    m_servicenum++;
    return;
}

/**
 * [CSYSRULESBUSINESS::AddNetWay 添加安全通道]
 * @param modnum [模块编号]
 * @param secway [安全通道的引用]
 */
void CSYSRULESBUSINESS::AddNetWay(int modnum, SEC_WAY &secway)
{
    g_cardmg.add(modnum, secway.getindev(), secway.getoutdev());
}

/**
 * [CSYSRULESBUSINESS::ImportRules 导入规则]
 * @param  filename [规则文件]
 * @return          [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportRules(const char *filename)
{
    char chSubItem[100] = {0};
    int rulenum = 0;

    if (m_fileop.OpenFile(filename, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("open file[%s] fail", filename);
        return E_FALSE;
    }

    if (m_fileop.ReadCfgFileInt("MAIN", "RuleNum", &rulenum) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("read rule num fail[%s]", filename);
        goto _err;
    }

    PRINT_DBG_HEAD
    print_dbg("rule num:%d", rulenum);

    if (rulenum > 0) {
        m_sysrule = (CSYSRULES **)malloc(sizeof(CSYSRULES *) * rulenum);
        if (m_sysrule == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc sysrules fail. size[%d] rulenum[%d]", sizeof(CSYSRULES *) * rulenum, rulenum);
            return E_FALSE;
        }
        memset(m_sysrule , 0, sizeof(CSYSRULES *) * rulenum);
    }

    for (int i = 0; i < rulenum; i++) {
        sprintf(chSubItem, "RULE%d", i);
        if (ImportRule(chSubItem) != E_OK) {
            PRINT_ERR_HEAD
            print_err("read rule fail[%s]", chSubItem);
            goto _err;
        }
    }
    m_fileop.CloseFile();
    return E_OK;

_err:
    m_fileop.CloseFile();
    return E_FALSE;
}

/**
 * [CSYSRULESBUSINESS::ImportRule 导入1条规则]
 * @param  ruleitem [规则项]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportRule(const char *ruleitem)
{
    if (ruleitem == NULL) {
        PRINT_ERR_HEAD
        print_err("ruleitem null");
        return E_FALSE;
    }

    char rulename[RULE_NAME_LEN] = {0};
    char item[100] = {0};
    char mychItem[100] = {0};
    CSYSRULES *p_rules = NULL;
    int tmpint = 0;
    int iIndex = 0;
    int area = 0;
    int indev = -1, outdev = -1;
    char wayname[SECWAY_NAME_LEN] = {0};
    char servname[APP_NAME_LEN] = {0};
    char objectname[OBJ_NAME_LEN] = {0};
    CCommon common;

    READ_STRING(m_fileop, ruleitem, "Name", rulename, true, _out);
    iIndex = AddRule(rulename);
    if ((iIndex == E_SYSRULE_FULL) || (iIndex == E_SYSRULE_EXIST)) {
        m_fileop.CloseFile();
        return E_OK;
    }

    p_rules = m_sysrule[iIndex];
    READ_STRING(m_fileop, ruleitem, "SecWayName", wayname, true, _out);
    READ_INT(m_fileop, ruleitem, "Area", area, true, _out);
    READ_INT(m_fileop, ruleitem, "InDev", indev, true, _out);
    READ_INT(m_fileop, ruleitem, "OutDev", outdev, true, _out);
    p_rules->m_secway.setway(wayname, area, indev, outdev);
    AddNetWay(NORMAL_RULE_MOD, p_rules->m_secway);
    READ_INT(m_fileop, ruleitem, "SObjNum", p_rules->m_sobjectnum, true, _out);
    READ_INT(m_fileop, ruleitem, "DObjNum", p_rules->m_dobjectnum, true, _out);
    READ_INT(m_fileop, ruleitem, "AppNum", p_rules->m_servicenum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("Name=%s SObjNum=%d DObjNum=%d AppNum=%d", rulename, p_rules->m_sobjectnum,
              p_rules->m_dobjectnum, p_rules->m_servicenum);

    for (int i = 0; i < p_rules->m_sobjectnum; i++) {
        BZERO(objectname);
        sprintf(item, "SObjName%d", i);
        READ_STRING(m_fileop, ruleitem, item, objectname, true, _out);
        //查找对象汇总表中有无该对象
        COBJECT *pobj = FindObjectByName(objectname);
        if (pobj == NULL) {
            //没找到该对象，就新建并记录到汇总表中
            pobj = new COBJECT(objectname);
            if (pobj == NULL) {
                PRINT_ERR_HEAD
                print_err("new object fail.object name[%s]", objectname);
                goto _out;
            }
            RegisterObject(pobj);
            sprintf(item, "SObjIP%d", i);
            READ_STRING(m_fileop, ruleitem, item, pobj->m_ipaddress, true, _out);
            sprintf(item, "SObjMask%d", i);
            READ_STRING(m_fileop, ruleitem, item, pobj->m_netmask, true, _out);
            sprintf(item, "SObjMac%d", i);
            READ_STRING(m_fileop, ruleitem, item, pobj->m_mac, false, _out);
#if (SUPPORT_IPV6==1)
            sprintf(item, "SrcIPType%d", i);
            READ_INT(m_fileop, ruleitem, item, pobj->m_iptype, false, _out);
#endif
        }
        p_rules->m_sobject[i] = pobj;
        if (IsCloseToSRCObj(p_rules->m_secway.getarea())) {
            //AddObject(pobj);
        }
    }

    for (int i = 0; i < p_rules->m_dobjectnum; i++) {
        BZERO(objectname);
        sprintf(item, "DObjName%d", i);
        READ_STRING(m_fileop, ruleitem, item, objectname, true, _out);
        //查找对象汇总表中有无该对象
        COBJECT *pobj = FindObjectByName(objectname);
        if (pobj == NULL) {
            //没找到该对象，就新建并记录到汇总表中
            pobj = new COBJECT(objectname);
            if (pobj == NULL) {
                PRINT_ERR_HEAD
                print_err("new object fail.object name[%s]", objectname);
                goto _out;
            }
            RegisterObject(pobj);
            sprintf(item, "DObjIP%d", i);
            READ_STRING(m_fileop, ruleitem, item, pobj->m_ipaddress, true, _out);
            sprintf(item, "DObjMask%d", i);
            READ_STRING(m_fileop, ruleitem, item, pobj->m_netmask, true, _out);
            sprintf(item, "DObjMac%d", i);
            READ_STRING(m_fileop, ruleitem, item, pobj->m_mac, false, _out);
#if (SUPPORT_IPV6==1)
            sprintf(item, "DstIPType%d", i);
            READ_INT(m_fileop, ruleitem, item, pobj->m_iptype, false, _out);
#endif
        }
        p_rules->m_dobject[i] = pobj;
        if (!IsCloseToSRCObj(p_rules->m_secway.getarea())) {
            //AddObject(pobj);
        }
    }

    for (int i = 0; i < p_rules->m_servicenum; i++) {
        sprintf(item, "AppName%d", i);
        BZERO(servname);
        READ_STRING(m_fileop, ruleitem, item, servname, true, _out);
        common.DelChar(servname, '\"');
        common.DelChar(servname, '\'');
        PRINT_DBG_HEAD
        print_dbg("AppName=%s", servname);

        //查找服务汇总表中有无该服务
        CSERVICECONF *pser = FindServByName(servname);
        if (pser == NULL) {
            //没有找到，就新建并记录到汇总表中
            pser = new CSERVICECONF(servname);
            if (pser == NULL) {
                PRINT_ERR_HEAD
                print_err("new service fail.service name[%s]", servname);
                goto _out;
            }
            RegisterService(pser);
            sprintf(item, "AppProtocol%d", i);
            READ_STRING(m_fileop, ruleitem, item, pser->m_protocol, true, _out);
            sprintf(item, "AppModule%d", i);
            READ_STRING(m_fileop, ruleitem, item, pser->m_asservice, true, _out);
            sprintf(item, "AppSPort%d", i);
            READ_STRING(m_fileop, ruleitem, item, pser->m_sport, true, _out);
            sprintf(item, "AppDPort%d", i);
            READ_STRING(m_fileop, ruleitem, item, pser->m_dport, true, _out);
            sprintf(item, "AppTPort%d", i);
            READ_STRING(m_fileop, ruleitem, item, pser->m_tport, false, _out);
            if (pser->m_tport[0] == '\0') {
                strcpy(pser->m_tport, pser->m_dport);
            }
            sprintf(item, "AppCKLog%d", i);
            tmpint = 1;
            READ_INT(m_fileop, ruleitem, item, tmpint, false, _out);
            pser->m_cklog = (tmpint == 1);

            //恒生芸泰定制
            if (strcmp(pser->m_asservice, "HSYT_WEBSERVICE") == 0) {
                CustomHSYTWeb(pser);
            } else if ((strcmp(pser->m_asservice, "HSYT_ORACLE") == 0)
                       || (strcmp(pser->m_asservice, "HSYT_SQLSERVER") == 0)
                       || (strcmp(pser->m_asservice, "HSYT_MYSQL") == 0)) {
                CustomHSYTDB(pser);
            } else {
                sprintf(item, "AppAction%d", i);
                tmpint = 1;
                READ_INT(m_fileop, ruleitem, item, tmpint, false, _out);
                pser->m_IfExec = (tmpint == 1);

                sprintf(item, "App%d_CmdNum", i);
                READ_INT(m_fileop, ruleitem, item, pser->m_cmdnum, false, _out);
                if (pser->m_cmdnum > C_MAX_CMD) {
                    PRINT_ERR_HEAD
                    print_err("too many cmd[%d], set to [%d]", pser->m_cmdnum, C_MAX_CMD);
                    pser->m_cmdnum = C_MAX_CMD;
                }

                for (int j = 0; j < pser->m_cmdnum; j++) {
                    pser->m_cmd[j] = new CCMDCONF;
                    sprintf(mychItem, "%s_APP%d_CMD%d", ruleitem, i, j);
                    READ_STRING(m_fileop, mychItem, "CmdName", pser->m_cmd[j]->m_cmd, false, _out);
                    READ_INT(m_fileop, mychItem, "StartPos", pser->m_cmd[j]->m_start, false, _out);
                    READ_STRING(m_fileop, mychItem, "Param", pser->m_cmd[j]->m_parameter, false, _out);
                    READ_STRING(m_fileop, mychItem, "SplitFlag", pser->m_cmd[j]->m_sign, false, _out);
                    tmpint = 1;
                    READ_INT(m_fileop, mychItem, "Permit", tmpint, false, _out);
                    pser->m_cmd[j]->m_action = (tmpint == 1);
                }
            }
        }
        p_rules->m_service[i] = pser;
        if (IsCloseToSRCObj(p_rules->m_secway.getarea())) {
            AddService(pser);
        }
    }

    READ_STRING(m_fileop, ruleitem, "SpecSip", p_rules->m_specsip, false, _out);
    READ_INT(m_fileop, ruleitem, "TimeType", p_rules->m_timemod.m_timetype, true, _out);
    READ_STRING(m_fileop, ruleitem, "StartTime", p_rules->m_timemod.m_stime, true, _out);
    READ_STRING(m_fileop, ruleitem, "EndTime", p_rules->m_timemod.m_etime, true, _out);
    READ_STRING(m_fileop, ruleitem, "StartDate", p_rules->m_timemod.m_sdate, true, _out);
    READ_STRING(m_fileop, ruleitem, "EndDate", p_rules->m_timemod.m_edate, true, _out);
    READ_STRING(m_fileop, ruleitem, "WeekDays", p_rules->m_timemod.m_weekdays, true, _out);
    READ_INT(m_fileop, ruleitem, "Action", tmpint, true, _out);
    p_rules->Action = (tmpint == 1);
    READ_INT(m_fileop, ruleitem, "Occurs", p_rules->m_occurs, true, _out);

    PRINT_DBG_HEAD
    print_dbg("[%s]read ok", ruleitem);
    return E_OK;

_out:
    return E_FALSE;
}

bool CSYSRULES::SetName(const char *cname)
{
    bool bflag = true;
    if (cname == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        bflag = false;
    } else {
        if (strlen(cname) < sizeof(m_name)) {
            strcpy(m_name, cname);
        } else {
            strncpy(m_name, cname, sizeof(m_name) - 1);
            m_name[sizeof(m_name) - 1] = '\0';
            PRINT_ERR_HEAD
            print_err("name too long[%d]!max support %d", (int)strlen(cname),
                      (int)sizeof(m_name) - 1);
        }
    }
    return bflag;
}

bool CSYSRULES::GetName(char *cname)
{
    if (cname == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    strcpy(cname, "");
    strcpy(cname, m_name);
    return true;
}

//系统规则业务类
CSYSRULESBUSINESS::CSYSRULESBUSINESS(void)
{
    m_sysrulenum = 0;
    m_sysrule = NULL;

    m_objectnum = 0;
    BZERO(m_object);
    m_object_summary.clear();

    m_servicenum = 0;
    BZERO(m_service);
    m_serv_summary.clear();

    m_sipnormnum = 0;
    BZERO(m_sipnorm);

    m_clientsipnormnum = 0;
    BZERO(m_clientsipnorm);

    m_dbsync_tasknum = 0;
    BZERO(m_dbsync);

    m_inbonding = NULL;
    m_outbonding = NULL;

    m_siplinknum = 0;
    BZERO(m_siplink);

    m_clientsiplinknum = 0;
    BZERO(m_clientsiplink);

    m_pdt_com_num = 0;
    BZERO(m_pdtcom);

    m_rfc3261_tasknum = 0;
    m_rfc3261 = NULL;
}

CSYSRULESBUSINESS::~CSYSRULESBUSINESS(void)
{
    ClearAllData();
}

bool CSYSRULESBUSINESS::ClearAllData(void)
{
    DELETE_N(m_sysrule, m_sysrulenum);
    if (m_sysrule != NULL) {
        free(m_sysrule);
        m_sysrule = NULL;
    }
    m_sysrulenum = 0;

    m_objectnum = 0;
    for (int i = 0; i < (int)m_object_summary.size(); ++i) {
        delete m_object_summary[i];
    }
    m_object_summary.clear();

    m_servicenum = 0;
    for (int i = 0; i < (int)m_serv_summary.size(); ++i) {
        delete m_serv_summary[i];
    }
    m_serv_summary.clear();

    DELETE_N(m_sipnorm, m_sipnormnum);
    m_sipnormnum = 0;

    DELETE_N(m_clientsipnorm, m_clientsipnormnum);
    m_clientsipnormnum = 0;

    DELETE_N(m_dbsync, m_dbsync_tasknum);
    m_dbsync_tasknum = 0;

    DELETE(m_inbonding);
    DELETE(m_outbonding);

    DELETE_N(m_siplink, m_siplinknum);
    m_siplinknum = 0;

    DELETE_N(m_clientsiplink, m_clientsiplinknum);
    m_clientsiplinknum = 0;

    DELETE_N(m_rfc3261, m_rfc3261_tasknum);
    if (m_rfc3261 != NULL) {
        free(m_rfc3261);
        m_rfc3261 = NULL;
    }
    m_rfc3261_tasknum = 0;
    return true;
}

/**
 * [CSYSRULESBUSINESS::AddRule 添加规则]
 * @param  chname [规则名称]
 * @return        [成功时返回规则指针下标]
 */
int  CSYSRULESBUSINESS::AddRule(const char *chname)
{
    if (Find(chname) == E_SYSRULE_NO_EXIST) {
        m_sysrule[m_sysrulenum] = new CSYSRULES;
        if (m_sysrule[m_sysrulenum] == NULL) {
            PRINT_ERR_HEAD
            print_err("new SYSRULES fail [%s], current rulenum[%d]", chname, m_sysrulenum);
            return E_SYSRULE_FULL;
        }
        m_sysrule[m_sysrulenum]->SetName(chname);
        m_sysrulenum++;
        return m_sysrulenum - 1;

    } else {
        PRINT_ERR_HEAD
        print_err("rule exist [%s]", chname);
        return E_SYSRULE_EXIST;
    }
}

/**
 * [CSYSRULESBUSINESS::Find 查询规则是否已经添加过]
 * @param  chname [规则名称]
 * @return        [未添加过则返回E_SYSRULE_NO_EXIST
 *                 否则返回下标值]
 */
int  CSYSRULESBUSINESS::Find(const char *chname)
{
    char temp[100] = {0};
    for (int i = 0; i < m_sysrulenum; i++) {
        if (m_sysrule[i]->GetName(temp)) {
            if (strcmp(temp, chname) == 0) {
                return i;
            }
        }
    }

    return E_SYSRULE_NO_EXIST;
}

CSipNorm *CSYSRULESBUSINESS::AddSipNorm(void)
{
    if (m_sipnormnum == ARRAY_SIZE(m_sipnorm)) {
        PRINT_ERR_HEAD
        print_err("reach max support sipnum[%d]", ARRAY_SIZE(m_sipnorm));
        return NULL;
    }
    m_sipnorm[m_sipnormnum] = new CSipNorm(m_sipnormnum);
    if (m_sipnorm[m_sipnormnum] == NULL) {
        PRINT_ERR_HEAD
        print_err("new CSipNorm fail. current tasknum[%d]", m_sipnormnum);
        return NULL;
    }
    m_sipnormnum++;

    return m_sipnorm[m_sipnormnum - 1];
}

CClientSipNorm *CSYSRULESBUSINESS::AddClientSipNorm(void)
{
    if (m_clientsipnormnum == ARRAY_SIZE(m_clientsipnorm)) {
        PRINT_ERR_HEAD
        print_err("reach max support sipnum[%d]", ARRAY_SIZE(m_clientsipnorm));
        return NULL;
    }
    m_clientsipnorm[m_clientsipnormnum] = new CClientSipNorm(m_clientsipnormnum);
    if (m_clientsipnorm[m_clientsipnormnum] == NULL) {
        PRINT_ERR_HEAD
        print_err("new CClientSipNorm fail. current tasknum[%d]", m_clientsipnormnum);
        return NULL;
    }
    m_clientsipnormnum++;
    return m_clientsipnorm[m_clientsipnormnum - 1];
}

CClientSipLink *CSYSRULESBUSINESS::AddClientSipLink(void)
{
    if (m_clientsiplinknum == ARRAY_SIZE(m_clientsiplink)) {
        PRINT_ERR_HEAD
        print_err("reach max support sipnum[%d]", ARRAY_SIZE(m_clientsiplink));
        return NULL;
    }
    m_clientsiplink[m_clientsiplinknum] = new CClientSipLink(m_clientsiplinknum);
    if (m_clientsiplink[m_clientsiplinknum] == NULL) {
        PRINT_ERR_HEAD
        print_err("new CClientSipLink fail. current tasknum[%d]", m_clientsiplinknum);
        return NULL;
    }
    m_clientsiplinknum++;

    return m_clientsiplink[m_clientsiplinknum - 1];
}

CDBSyncTask *CSYSRULESBUSINESS::AddDBSync(void)
{
    if (m_dbsync_tasknum == ARRAY_SIZE(m_dbsync)) {
        PRINT_ERR_HEAD
        print_err("reach max support dbsyncnum[%d]", ARRAY_SIZE(m_dbsync));
        return NULL;
    }
    m_dbsync[m_dbsync_tasknum] = new CDBSyncTask(m_dbsync_tasknum);
    if (m_dbsync[m_dbsync_tasknum] == NULL) {
        PRINT_ERR_HEAD
        print_err("new CDBSyncTask fail. current tasknum[%d]", m_dbsync_tasknum);
        return NULL;
    }
    m_dbsync_tasknum++;

    return m_dbsync[m_dbsync_tasknum - 1];
}

/**
 * [CSYSRULESBUSINESS::ImportSipNorm 导入平台级联策略]
 * @param  filename   [策略文件名称]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportSipNorm(const char *filename)
{
    char taskno[16] = {0};
    char subitem[16] = {0};
    int tasknum = 0;
    int tmpint = 1;
    int indev = -1;
    int outdev = -1;
    int area = 0;
    CCommon common;

    if (m_fileop.OpenFile(filename, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        return E_OPENFILE_ERROR;
    }

    READ_INT(m_fileop, "SIP", "TaskNum", tasknum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("tasknum:%d", tasknum);

    for (int i = 0; i < tasknum; i++ ) {
        CSipNorm *sip = AddSipNorm();
        if (sip == NULL) {
            break;
        }

        sprintf(taskno, "Task%d", i);
        READ_STRING(m_fileop, taskno, "Name", sip->m_name, true, _out);
        common.DelChar(sip->m_name, '\'');
        READ_INT(m_fileop, taskno, "BrandID", sip->m_brandID, false, _out);
        if (sip->m_brandID <= 0) {
            PRINT_ERR_HEAD
            print_err("brandid err[%d],use default %d", sip->m_brandID, ID_OTHERBRAND);
            sip->m_brandID = ID_OTHERBRAND;
        }
        READ_INT(m_fileop, taskno, "Area", area, true, _out);
        READ_INT(m_fileop, taskno, "InDev", indev, true, _out);
        READ_INT(m_fileop, taskno, "OutDev", outdev, true, _out);
        sip->m_secway.setway("", area, indev, outdev);
        READ_STRING(m_fileop, taskno, "CliIP", sip->m_upplatip, true, _out);
        READ_STRING(m_fileop, taskno, "GapInIP", sip->m_gapinip, true, _out);
        READ_STRING(m_fileop, taskno, "GapOutIP", sip->m_gapoutip, true, _out);
        READ_STRING(m_fileop, taskno, "VideoIP", sip->m_downplatip, true, _out);
        READ_STRING(m_fileop, taskno, "Port", sip->m_downplatport, true, _out);
        READ_STRING(m_fileop, taskno, "SrcPort", sip->m_upplatport, false, _out);
        if (strcmp(sip->m_upplatport, "") == 0) {
            PRINT_ERR_HEAD
            print_err("read upplat port err, use downplat port [%s] instead", sip->m_downplatport);
            strcpy(sip->m_upplatport, sip->m_downplatport);
        }
        READ_STRING(m_fileop, taskno, "Protocol", sip->m_proto, false, _out);
        if (strcmp(sip->m_proto, "") == 0) {
            PRINT_ERR_HEAD
            print_err("read Protocol error!use default SIP");
            strcpy(sip->m_proto, "SIP");
        }
        if (m_fileop.ReadCfgFileInt(taskno, "DefCmdAction", &tmpint) != E_FILE_OK) {
            PRINT_ERR_HEAD
            print_err("read DefCmdAction error!use default 1");
            tmpint = 1;
        }
        sip->m_ifexec = (tmpint == 1);
        READ_INT(m_fileop, taskno, "CmdNum", sip->m_cmdnum, false, _out);
        sip->m_cmdnum = MIN(sip->m_cmdnum , C_MAX_CMD);

        //读取各个命令
        for (int j = 0; j < sip->m_cmdnum; j++) {
            sip->m_cmd[j] = new CCMDCONF;
            if (sip->m_cmd[j] == NULL) {
                PRINT_ERR_HEAD
                print_err("new cmd error");
                goto _out;
            }
            sprintf(subitem, "CmdName%d", j);
            READ_STRING(m_fileop, taskno, subitem, sip->m_cmd[j]->m_cmd, true, _out);
            sprintf(subitem, "Param%d", j);
            READ_STRING(m_fileop, taskno, subitem, sip->m_cmd[j]->m_parameter, false, _out);
            sprintf(subitem, "Permit%d", j);
            READ_INT(m_fileop, taskno, subitem, tmpint, false, _out);
            sip->m_cmd[j]->m_action = (tmpint == 1);

            PRINT_DBG_HEAD
            print_dbg("cmd[%s] para[%s] action[%s]", sip->m_cmd[j]->m_cmd,
                      sip->m_cmd[j]->m_parameter, sip->m_cmd[j]->m_action ? "allow" : "forbid");
        }

        AddNetWay(SIP_NORMAL_MOD, sip->m_secway);
    }

    m_fileop.CloseFile();
    return E_OK;
_out:
    m_fileop.CloseFile();
    return E_FALSE;
}

/**
 * [CSYSRULESBUSINESS::ImportClientSipNorm 导入视频代理策略]
 * @param  filename   [策略文件名称]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportClientSipNorm(const char *filename)
{
    char taskno[16] = {0};
    char subitem[16] = {0};
    int tasknum = 0;
    int tmpint = 1;
    int indev = -1;
    int outdev = -1;
    int area = 0;
    CCommon common;

    if (m_fileop.OpenFile(filename, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        return E_OPENFILE_ERROR;
    }

    READ_INT(m_fileop, "SIP", "ClientTaskNum", tasknum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("tasknum:%d", tasknum);

    for (int i = 0; i < tasknum; i++ ) {
        CClientSipNorm *csip = AddClientSipNorm();
        if (csip == NULL) {
            break;
        }

        sprintf(taskno, "ClientTask%d", i);
        READ_STRING(m_fileop, taskno, "Name", csip->m_name, true, _out);
        common.DelChar(csip->m_name, '\'');
        READ_INT(m_fileop, taskno, "BrandID", csip->m_brandID, false, _out);
        if (csip->m_brandID <= 0) {
            PRINT_ERR_HEAD
            print_err("brandid err[%d],use default %d", csip->m_brandID, ID_OTHERBRAND);
            csip->m_brandID = ID_OTHERBRAND;
        }
        READ_INT(m_fileop, taskno, "Area", area, true, _out);
        READ_INT(m_fileop, taskno, "InDev", indev, true, _out);
        READ_INT(m_fileop, taskno, "OutDev", outdev, true, _out);
        csip->m_secway.setway("", area, indev, outdev);
        READ_STRING(m_fileop, taskno, "ClientIP", csip->m_cliip, true, _out);
        READ_STRING(m_fileop, taskno, "GapInIP", csip->m_gapinip, true, _out);
        READ_STRING(m_fileop, taskno, "GapOutIP", csip->m_gapoutip, true, _out);
        READ_STRING(m_fileop, taskno, "VideoIP", csip->m_videoip, true, _out);
        READ_STRING(m_fileop, taskno, "Port", csip->m_port, true, _out);
        READ_STRING(m_fileop, taskno, "Protocol", csip->m_proto, false, _out);
        if (strcmp(csip->m_proto, "") == 0) {
            PRINT_ERR_HEAD
            print_err("read Protocol error!use default SIP");
            strcpy(csip->m_proto, "SIP");
        }

        if (m_fileop.ReadCfgFileInt(taskno, "DefCmdAction", &tmpint) != E_FILE_OK) {
            PRINT_ERR_HEAD
            print_err("read DefCmdAction error!use default 1");
            tmpint = 1;
        }
        csip->m_ifexec = (tmpint == 1);
        READ_INT(m_fileop, taskno, "CmdNum", csip->m_cmdnum, false, _out);
        csip->m_cmdnum = MIN(csip->m_cmdnum, C_MAX_CMD);

        for (int j = 0; j < csip->m_cmdnum; j++) {
            csip->m_cmd[j] = new CCMDCONF;
            if (csip->m_cmd[j] == NULL) {
                PRINT_ERR_HEAD
                print_err("new cmd error");
                goto _out;
            }
            sprintf(subitem, "CmdName%d", j);
            READ_STRING(m_fileop, taskno, subitem, csip->m_cmd[j]->m_cmd, true, _out);
            sprintf(subitem, "Param%d", j);
            READ_STRING(m_fileop, taskno, subitem, csip->m_cmd[j]->m_parameter, false, _out);
            sprintf(subitem, "Permit%d", j);
            READ_INT(m_fileop, taskno, subitem, tmpint, false, _out);
            csip->m_cmd[j]->m_action = (tmpint == 1);

            PRINT_DBG_HEAD
            print_dbg("cmd[%s] para[%s] action[%s]", csip->m_cmd[j]->m_cmd,
                      csip->m_cmd[j]->m_parameter, csip->m_cmd[j]->m_action ? "allow" : "forbid");
        }

        AddNetWay(SIP_CLI_NORMAL_MOD, csip->m_secway);
    }

    m_fileop.CloseFile();
    return E_OK;
_out:
    m_fileop.CloseFile();
    return E_FALSE;
}

/**
 * [CSYSRULESBUSINESS::ImportClientSipLink 导入视频代理联动策略]
 * @param  filename   [策略文件名称]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportClientSipLink(const char *filename)
{
    char taskno[16] = {0};
    char subitem[16] = {0};
    int tasknum = 0;
    int tmpint = 1;
    int indev = -1;
    int outdev = -1;
    int area = 0;
    CCommon common;

    if (m_fileop.OpenFile(filename, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        return E_OPENFILE_ERROR;
    }

    READ_INT(m_fileop, "SIP", "LinkClientTaskNum", tasknum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("tasknum:%d", tasknum);

    for (int i = 0; i < tasknum; i++ ) {
        CClientSipLink *csip = AddClientSipLink();
        if (csip == NULL) {
            break;
        }

        sprintf(taskno, "LinkClientTask%d", i);
        READ_STRING(m_fileop, taskno, "Name", csip->m_name, true, _out);
        common.DelChar(csip->m_name, '\'');
        READ_INT(m_fileop, taskno, "BrandID", csip->m_brandID, false, _out);
        if (csip->m_brandID <= 0) {
            PRINT_ERR_HEAD
            print_err("brandid err[%d],use default %d", csip->m_brandID, ID_OTHERBRAND);
            csip->m_brandID = ID_OTHERBRAND;
        }
        READ_INT(m_fileop, taskno, "Area", area, true, _out);
        READ_INT(m_fileop, taskno, "InDev", indev, true, _out);
        READ_INT(m_fileop, taskno, "OutDev", outdev, true, _out);
        csip->m_secway.setway("", area, indev, outdev);
        READ_STRING(m_fileop, taskno, "ClientIP", csip->m_cliip, true, _out);
        READ_STRING(m_fileop, taskno, "GapInIP", csip->m_gapinip, true, _out);
        READ_STRING(m_fileop, taskno, "GapOutIP", csip->m_gapoutip, true, _out);
        READ_STRING(m_fileop, taskno, "VideoIP", csip->m_videoip, true, _out);
        READ_STRING(m_fileop, taskno, "Port", csip->m_port, true, _out);
        READ_STRING(m_fileop, taskno, "Protocol", csip->m_proto, false, _out);
        if (strcmp(csip->m_proto, "") == 0) {
            PRINT_ERR_HEAD
            print_err("read Protocol error!use default SIP");
            strcpy(csip->m_proto, "SIP");
        }

        if (m_fileop.ReadCfgFileInt(taskno, "DefCmdAction", &tmpint) != E_FILE_OK) {
            PRINT_ERR_HEAD
            print_err("read DefCmdAction error!use default 1");
            tmpint = 1;
        }
        csip->m_ifexec = (tmpint == 1);
        READ_INT(m_fileop, taskno, "CmdNum", csip->m_cmdnum, false, _out);
        csip->m_cmdnum = MIN(csip->m_cmdnum, C_MAX_CMD);
        READ_INT(m_fileop, taskno, "NodeNum", csip->m_nodenum, true, _out);
        csip->m_nodenum = MIN(csip->m_nodenum, SIP_MAX_NODE);

        for (int j = 0; j < csip->m_cmdnum; j++) {
            csip->m_cmd[j] = new CCMDCONF;
            if (csip->m_cmd[j] == NULL) {
                PRINT_ERR_HEAD
                print_err("new cmd error");
                goto _out;
            }
            sprintf(subitem, "CmdName%d", j);
            READ_STRING(m_fileop, taskno, subitem, csip->m_cmd[j]->m_cmd, true, _out);
            sprintf(subitem, "Param%d", j);
            READ_STRING(m_fileop, taskno, subitem, csip->m_cmd[j]->m_parameter, false, _out);
            sprintf(subitem, "Permit%d", j);
            READ_INT(m_fileop, taskno, subitem, tmpint, false, _out);
            csip->m_cmd[j]->m_action = (tmpint == 1);

            PRINT_DBG_HEAD
            print_dbg("cmd[%s] para[%s] action[%s]", csip->m_cmd[j]->m_cmd,
                      csip->m_cmd[j]->m_parameter, csip->m_cmd[j]->m_action ? "allow" : "forbid");
        }

        //读取视频转发节点
        for (int k = 0; k < csip->m_nodenum; k++) {
            csip->m_node[k] = new ForwardNode;
            if (csip->m_node[k] == NULL) {
                PRINT_ERR_HEAD
                print_err("new node error %d", k);
                goto _out;
            }

            csip->m_node[k]->id = k;
            sprintf(subitem, "NodeWeight%d", k);
            READ_INT(m_fileop, taskno, subitem, csip->m_node[k]->weight, true, _out);
            csip->m_node[k]->weight = MIN(csip->m_node[k]->weight, SIP_NODE_MAX_WEIGHT);
            sprintf(subitem, "NodeCmdPort%d", k);
            READ_INT(m_fileop, taskno, subitem, tmpint, true, _out);
            csip->m_node[k]->cmdport = tmpint;
            sprintf(subitem, "NodeComeIP%d", k);
            READ_STRING(m_fileop, taskno, subitem, csip->m_node[k]->comeip, true, _out);
            sprintf(subitem, "NodeGoIP%d", k);
            READ_STRING(m_fileop, taskno, subitem, csip->m_node[k]->goip, true, _out);
            csip->m_node[k]->natport = SIP_CLI_NAT_PORT_START + SIP_MAX_NODE * i + k;
            sprintf(csip->m_node[k]->natip, "%d.0.0.%d", g_linklanipseg,
                    ((csip->m_secway.getarea() == 0) ? 253 : 254));

            PRINT_DBG_HEAD
            print_dbg("node[%d] weight[%d] cmdport[%d] comeip[%s] goip[%s] natport[%d] natip[%s]",
                      csip->m_node[k]->id, csip->m_node[k]->weight, csip->m_node[k]->cmdport,
                      csip->m_node[k]->comeip, csip->m_node[k]->goip, csip->m_node[k]->natport,
                      csip->m_node[k]->natip);
        }

        csip->m_maxchannel = SIP_LINK_CLI_TOTAL_CHANNEL / 2 / tasknum;
        csip->m_exceptport.push_back(g_linklanport);
        AddNetWay(SIP_CLI_LINK_MOD, csip->m_secway);
    }

    m_fileop.CloseFile();
    return E_OK;
_out:
    m_fileop.CloseFile();
    return E_FALSE;
}

/**
 * [CSYSRULESBUSINESS::ImportDBSync 导入数据库同步策略]
 * @param  filename   [策略文件名称]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportDBSync(const char *filename)
{
    char readbuf[500] = {0};
    char item_tmp[500] = {0};
    int tasknum = 0;
    int tmpint = 0;

    if (m_fileop.OpenFile(filename, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        return E_OPENFILE_ERROR;
    }

    READ_INT(m_fileop, "Application", "rules_num", tasknum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("tasknum:%d", tasknum);

    for (int i = 0; i < tasknum; i++) {
        CDBSyncTask *dbsync = AddDBSync();
        if (dbsync == NULL) {
            break;
        }
        sprintf(item_tmp, "rule_name%d", i);
        READ_STRING(m_fileop, "Application", item_tmp, readbuf, true, _out);
        dbsync->setRuleName(readbuf);
        sprintf(item_tmp, "rule_area%d", i);
        READ_INT(m_fileop, "Application", item_tmp, tmpint, true, _out);
        dbsync->setRuleArea(tmpint);
        sprintf(item_tmp, "%s_tDBMS", dbsync->getRuleName());
        READ_STRING(m_fileop, item_tmp, "OldServer", readbuf, true, _out);
        dbsync->setOldDstServer(readbuf);
        READ_STRING(m_fileop, item_tmp, "OldPort", readbuf, true, _out);
        dbsync->setOldDstPort(readbuf);
        sprintf(item_tmp, "%s_sDBMS", dbsync->getRuleName());
        READ_STRING(m_fileop, item_tmp, "OldServer", readbuf, true, _out);
        dbsync->setOldSrcServer(readbuf);
        READ_STRING(m_fileop, item_tmp, "OldPort", readbuf, true, _out);
        dbsync->setOldSrcPort(readbuf);

        PRINT_DBG_HEAD
        print_dbg("rulename[%s] area[%d] srcserver[%s] dstserver[%s]", dbsync->getRuleName(),
                  dbsync->getRuleArea(), dbsync->getOldSrcServer(), dbsync->getOldDstServer());
    }

    m_fileop.CloseFile();
    return E_OK;
_out:
    m_fileop.CloseFile();
    return E_FALSE;
}

/**
 * [CSYSRULESBUSINESS::ImportBonding 导入负载均衡信息]
 * @param  filename   [策略文件名称]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportBonding(const char *filename)
{
    if (m_fileop.OpenFile(filename, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        return E_OPENFILE_ERROR;
    }

    ImportBondingSide(&m_inbonding, "INNET");
    ImportBondingSide(&m_outbonding, "OUTNET");
    m_fileop.CloseFile();
    return E_OK;
}

/**
 * [CSYSRULESBUSINESS::ImportBondingSide 导入负载均衡绑定信息（一侧的）]
 * @param pbonding [绑定结构指针]
 * @param areaitem [区域项]
 */
void CSYSRULESBUSINESS::ImportBondingSide(CBonding **ppbonding, const char *areaitem)
{
    char ipaddrstr[32] = {0};
    char maskaddrstr[32] = {0};
    char devstr[16] = {0};
    char iptypestr[16] = {0};
    int tmpint = 0;

    DELETE(*ppbonding);
    *ppbonding = new CBonding;
    if (*ppbonding == NULL) {
        PRINT_ERR_HEAD
        print_err("new CBonding error");
        return ;
    }

    READ_INT(m_fileop, areaitem, "Bond", tmpint, true, _out);
    (*ppbonding)->bond = (tmpint == 1);

    if ((*ppbonding)->bond) {

        READ_INT(m_fileop, areaitem, "DevNum", (*ppbonding)->devnum, false, _out);
        (*ppbonding)->devnum = MIN((*ppbonding)->devnum , C_BONDING_DEV_MAXNUM);

        READ_INT(m_fileop, areaitem, "IPNum", (*ppbonding)->ipnum, false, _out);
        (*ppbonding)->ipnum = MIN((*ppbonding)->ipnum , C_BONDING_IP_MAXNUM);

        READ_INT(m_fileop, areaitem, "BondType", (*ppbonding)->bondtype, true, _out);
        if ((*ppbonding)->bondtype < BONDTYPE0 || (*ppbonding)->bondtype > BONDTYPE6) {
            PRINT_ERR_HEAD
            print_err("bond type err[%d]", (*ppbonding)->bondtype);
            goto _out;
        }

        for (int i = 0; i < (*ppbonding)->devnum; i++) {
            sprintf(devstr, "Dev%d", i);
            READ_INT(m_fileop, areaitem, devstr, (*ppbonding)->dev[i], true, _out);
        }

        for (int i = 0; i < (*ppbonding)->ipnum; i++) {
            sprintf(ipaddrstr, "IPAddr%d", i);
            sprintf(maskaddrstr, "MaskAddr%d", i);
            sprintf(iptypestr, "IPType%d", i);
            READ_STRING(m_fileop, areaitem, ipaddrstr, (*ppbonding)->ipaddr[i], true, _out);
            READ_STRING(m_fileop, areaitem, maskaddrstr, (*ppbonding)->maskaddr[i], true, _out);
#if (SUPPORT_IPV6==1)
            READ_INT(m_fileop, areaitem, iptypestr, (*ppbonding)->iptype[i], false, _out);
#endif
        }
    }
    return;
_out:
    (*ppbonding)->bond = false;
    return;
}

CSipLink *CSYSRULESBUSINESS::AddSipLink(void)
{
    if (m_siplinknum == ARRAY_SIZE(m_siplink)) {
        PRINT_ERR_HEAD
        print_err("reach max support sipnum[%d]", ARRAY_SIZE(m_siplink));
        return NULL;
    }
    m_siplink[m_siplinknum] = new CSipLink(m_siplinknum);
    if (m_siplink[m_siplinknum] == NULL) {
        PRINT_ERR_HEAD
        print_err("new CSipLink fail. current tasknum[%d]", m_siplinknum);
        return NULL;
    }
    m_siplinknum++;
    return m_siplink[m_siplinknum - 1];
}

/**
 * [CSYSRULESBUSINESS::ImportSipLink 导入平台级联联动策略信息]
 * @param  filename   [文件名称]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportSipLink(const char *filename)
{
    char taskno[16] = {0};
    char subitem[16] = {0};
    int tasknum = 0;
    int tmpint = 1;
    int indev = -1;
    int outdev = -1;
    int area = 0;
    CCommon common;

    if (m_fileop.OpenFile(filename, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        return E_OPENFILE_ERROR;
    }

    READ_INT(m_fileop, "SIP", "LinkTaskNum", tasknum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("tasknum:%d", tasknum);

    for (int i = 0; i < tasknum; i++ ) {
        CSipLink *sip = AddSipLink();
        if (sip == NULL) {
            break;
        }

        sprintf(taskno, "LinkTask%d", i);
        READ_STRING(m_fileop, taskno, "Name", sip->m_name, true, _out);
        common.DelChar(sip->m_name, '\'');
        READ_INT(m_fileop, taskno, "BrandID", sip->m_brandID, true, _out);
        READ_INT(m_fileop, taskno, "Area", area, true, _out);
        READ_INT(m_fileop, taskno, "InDev", indev, true, _out);
        READ_INT(m_fileop, taskno, "OutDev", outdev, true, _out);
        sip->m_secway.setway("", area, indev, outdev);
        READ_STRING(m_fileop, taskno, "GapInIP", sip->m_gapinip, true, _out);
        READ_STRING(m_fileop, taskno, "GapOutIP", sip->m_gapoutip, true, _out);
        READ_STRING(m_fileop, taskno, "UpPlatIP", sip->m_upplatip, true, _out);
        READ_STRING(m_fileop, taskno, "UpPlatPort", sip->m_upplatport, true, _out);
        READ_STRING(m_fileop, taskno, "DownPlatIP", sip->m_downplatip, true, _out);
        READ_STRING(m_fileop, taskno, "DownPlatPort", sip->m_downplatport, true, _out);
        READ_STRING(m_fileop, taskno, "Protocol", sip->m_proto, true, _out);
        READ_INT(m_fileop, taskno, "DefCmdAction", tmpint, true, _out);
        sip->m_ifexec = (tmpint == 1);
        READ_INT(m_fileop, taskno, "CmdNum", sip->m_cmdnum, true, _out);
        sip->m_cmdnum = MIN(sip->m_cmdnum , C_MAX_CMD);
        READ_INT(m_fileop, taskno, "NodeNum", sip->m_nodenum, true, _out);
        sip->m_nodenum = MIN(sip->m_nodenum, SIP_MAX_NODE);

        //读取各个命令
        for (int j = 0; j < sip->m_cmdnum; j++) {
            sip->m_cmd[j] = new CCMDCONF;
            if (sip->m_cmd[j] == NULL) {
                PRINT_ERR_HEAD
                print_err("new cmd error %d", j);
                goto _out;
            }
            sprintf(subitem, "CmdName%d", j);
            READ_STRING(m_fileop, taskno, subitem, sip->m_cmd[j]->m_cmd, true, _out);
            sprintf(subitem, "Param%d", j);
            READ_STRING(m_fileop, taskno, subitem, sip->m_cmd[j]->m_parameter, false, _out);
            sprintf(subitem, "Permit%d", j);
            READ_INT(m_fileop, taskno, subitem, tmpint, true, _out);
            sip->m_cmd[j]->m_action = (tmpint == 1);

            PRINT_DBG_HEAD
            print_dbg("cmd[%s] para[%s] action[%s]", sip->m_cmd[j]->m_cmd,
                      sip->m_cmd[j]->m_parameter, sip->m_cmd[j]->m_action ? "allow" : "forbid");
        }

        //读取视频转发节点
        for (int k = 0; k < sip->m_nodenum; k++) {
            sip->m_node[k] = new ForwardNode;
            if (sip->m_node[k] == NULL) {
                PRINT_ERR_HEAD
                print_err("new node error %d", k);
                goto _out;
            }

            sip->m_node[k]->id = k;
            sprintf(subitem, "NodeWeight%d", k);
            READ_INT(m_fileop, taskno, subitem, sip->m_node[k]->weight, true, _out);
            sip->m_node[k]->weight = MIN(sip->m_node[k]->weight, SIP_NODE_MAX_WEIGHT);
            sprintf(subitem, "NodeCmdPort%d", k);
            READ_INT(m_fileop, taskno, subitem, tmpint, true, _out);
            sip->m_node[k]->cmdport = tmpint;
            sprintf(subitem, "NodeComeIP%d", k);
            READ_STRING(m_fileop, taskno, subitem, sip->m_node[k]->comeip, true, _out);
            sprintf(subitem, "NodeGoIP%d", k);
            READ_STRING(m_fileop, taskno, subitem, sip->m_node[k]->goip, true, _out);
            sip->m_node[k]->natport = SIP_NAT_PORT_START + SIP_MAX_NODE * i + k;
            sprintf(sip->m_node[k]->natip, "%d.0.0.%d", g_linklanipseg,
                    ((sip->m_secway.getarea() == 0) ? 253 : 254));

            PRINT_DBG_HEAD
            print_dbg("node[%d] weight[%d] cmdport[%d] comeip[%s] goip[%s] natport[%d] natip[%s]",
                      sip->m_node[k]->id, sip->m_node[k]->weight, sip->m_node[k]->cmdport,
                      sip->m_node[k]->comeip, sip->m_node[k]->goip, sip->m_node[k]->natport,
                      sip->m_node[k]->natip);
        }

        sip->m_maxchannel = SIP_LINK_TOTAL_CHANNEL / 2 / tasknum;
        sip->m_exceptport.push_back(g_linklanport);
        AddNetWay(SIP_LINK_MOD, sip->m_secway);
    }

    m_fileop.CloseFile();
    return E_OK;
_out:
    m_fileop.CloseFile();
    return E_FALSE;
}

CPDTCommon *CSYSRULESBUSINESS::AddPDTCommon(void)
{
    if (m_pdt_com_num == ARRAY_SIZE(m_pdtcom)) {
        PRINT_ERR_HEAD
        print_err("reach max support pdtnum[%d]", ARRAY_SIZE(m_pdtcom));
        return NULL;
    }
    m_pdtcom[m_pdt_com_num] = new CPDTCommon(m_pdt_com_num);
    if (m_pdtcom[m_pdt_com_num] == NULL) {
        PRINT_ERR_HEAD
        print_err("new CPDTCommon fail. current tasknum[%d]", m_pdt_com_num);
        return NULL;
    }
    m_pdt_com_num++;
    return m_pdtcom[m_pdt_com_num - 1];
}

/**
 * [CSYSRULESBUSINESS::ImportPDTCommon 导入PDT信息]
 * @param  filename   [文件名称]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportPDTCommon(const char *filename)
{
    PRINT_DBG_HEAD
    print_dbg("import pdt begin");

    int ret = E_FALSE;
    int tasknum = 0;

    if (m_fileop.OpenFile(filename, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        goto _out;
    }

    READ_INT(m_fileop, "SYS", "TaskNum", tasknum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("tasknum:%d", tasknum);

    for (int i = 0; i < tasknum; i++) {
        CPDTCommon *pdt = AddPDTCommon();
        if (pdt == NULL) {
            break;
        } else {

            if (pdt->loadConf(filename)) {
                AddNetWay(PDT_MOD, pdt->getSecway());
            } else {
                goto _out;
            }
        }
    }

    ret = E_OK;
_out:
    m_fileop.CloseFile();

    PRINT_DBG_HEAD
    print_dbg("import pdt over, ret = %d", ret);
    return ret;
}

CSipInterConnect *CSYSRULESBUSINESS::AddSipInterConnect(void)
{
    if (m_sipinterconnectnum == ARRAY_SIZE(m_sipinterconnect)) {
        PRINT_ERR_HEAD
        print_err("reach max support sip_interconnect_num[%d]", ARRAY_SIZE(m_sipinterconnect));
        return NULL;
    }
    m_sipinterconnect[m_sipinterconnectnum] = new CSipInterConnect(m_sipinterconnectnum);
    if (m_sipinterconnect[m_sipinterconnectnum] == NULL) {
        PRINT_ERR_HEAD
        print_err("new CSipInterConnect fail. current tasknum[%d]", m_sipinterconnectnum);
        return NULL;
    }
    m_sipinterconnectnum++;
    return m_sipinterconnect[m_sipinterconnectnum - 1];
}

/**
 * [CSYSRULESBUSINESS::ImportSipInterConnect 导入平台互联信息]
 * @param  filename   [文件名称]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportSipInterConnect(const char *filename)
{
    PRINT_DBG_HEAD
    print_dbg("import sip interconnect begin");

    int ret = E_FALSE;
    int tasknum = 0;

    if (m_fileop.OpenFile(filename, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        goto _out;
    }

    READ_INT(m_fileop, "SYS", "TaskNum", tasknum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("tasknum:%d", tasknum);

    for (int i = 0; i < tasknum; i++) {
        CSipInterConnect *sip_interconnect = AddSipInterConnect();
        if (sip_interconnect == NULL) {
            break;
        } else {
            if (sip_interconnect->loadConf(filename)) {
                AddNetWay(GB28181_INTER_MOD, sip_interconnect->getSecway());
            } else {
                goto _out;
            }
        }
    }

    ret = E_OK;
_out:
    m_fileop.CloseFile();

    PRINT_DBG_HEAD
    print_dbg("import sip interconnect over, ret = %d", ret);
    return ret;
}

/**
 * [CSYSRULESBUSINESS::FindServByName 通过名字查找服务]
 * @param  chname [待查的服务名]
 * @return        [查找成功返回服务指针 失败返回NULL]
 */
CSERVICECONF *CSYSRULESBUSINESS::FindServByName(const char *chname)
{
    if (chname == NULL) {
        PRINT_ERR_HEAD
        print_err("find serv by name para null");
        return NULL;
    }
    for (int i = 0; i < (int)m_serv_summary.size(); ++i) {
        if (strcmp(m_serv_summary[i]->m_name, chname) == 0) {
            return m_serv_summary[i];
        }
    }
    return NULL;
}

/**
 * [CSYSRULESBUSINESS::RegisterService 登记服务到汇总表]
 * @param  pserv [服务指针]
 * @return       [成功返回0 失败返回负值]
 */
int CSYSRULESBUSINESS::RegisterService(CSERVICECONF *pserv)
{
    if (pserv == NULL) {
        PRINT_ERR_HEAD
        print_err("register service para null");
        return -1;
    }

    if (pserv->m_name[0] == 0) {
        PRINT_ERR_HEAD
        print_err("register service name error[%s]", pserv->m_name);
        return -1;
    }

    m_serv_summary.push_back(pserv);
    PRINT_DBG_HEAD
    print_dbg("register serice[%s]", pserv->m_name);
    return 0;
}

/**
 * [CSYSRULESBUSINESS::CustomHSYTWeb 恒生芸泰定制WEB模块]
 * @param pserv [服务指针]
 */
void CSYSRULESBUSINESS::CustomHSYTWeb(CSERVICECONF *pserv)
{
    if (pserv != NULL) {
        pserv->m_cmd[0] = new CCMDCONF;
        pserv->m_cmd[0]->m_action = true;
        strcpy(pserv->m_cmd[0]->m_cmd, "GET");
        pserv->m_cmd[1] = new CCMDCONF;
        pserv->m_cmd[1]->m_action = true;
        strcpy(pserv->m_cmd[1]->m_cmd, "POST");
        pserv->m_cmdnum = 2;
        pserv->m_IfExec = false;
    }
}

/**
 * [CSYSRULESBUSINESS::CustomHSYTDB 恒生芸泰定制数据库模块]
 * @param pserv [服务指针]
 */
void CSYSRULESBUSINESS::CustomHSYTDB(CSERVICECONF *pserv)
{
    if (pserv != NULL) {
        pserv->m_cmd[0] = new CCMDCONF;
        pserv->m_cmd[0]->m_action = true;
        strcpy(pserv->m_cmd[0]->m_cmd, "SELECT");
        pserv->m_cmd[1] = new CCMDCONF;
        pserv->m_cmd[1]->m_action = true;
        strcpy(pserv->m_cmd[1]->m_cmd, "COMMIT");
        pserv->m_cmdnum = 2;
        pserv->m_IfExec = false;
    }
}

/**
 * [CSYSRULESBUSINESS::FindObjectByName 通过名字查找对象]
 * @param  chname [待查找的对象名]
 * @return        [成功返回对象指针 失败返回NULL]
 */
COBJECT *CSYSRULESBUSINESS::FindObjectByName(const char *chname)
{
    if (chname == NULL) {
        PRINT_ERR_HEAD
        print_err("find object by name para null");
        return NULL;
    }
    for (int i = 0; i < (int)m_object_summary.size(); ++i) {
        if (strcmp(m_object_summary[i]->m_objectname, chname) == 0) {
            return m_object_summary[i];
        }
    }
    return NULL;
}

/**
 * [CSYSRULESBUSINESS::RegisterObject 登记对象]
 * @param  pobj [对象指针]
 * @return      [成功返回0 失败返回负值]
 */
int CSYSRULESBUSINESS::RegisterObject(COBJECT *pobj)
{
    if (pobj == NULL) {
        PRINT_ERR_HEAD
        print_err("register object para null");
        return -1;
    }

    if (pobj->m_objectname[0] == 0) {
        PRINT_ERR_HEAD
        print_err("register object name error[%s]", pobj->m_objectname);
        return -1;
    }

    m_object_summary.push_back(pobj);
    PRINT_DBG_HEAD
    print_dbg("register object[%s]", pobj->m_objectname);
    return 0;
}

/**
 * [CSYSRULESBUSINESS::ImportRFC3261 导入RFC3261平台互联信息]
 * @param  filename   [文件名称]
 * @return            [成功返回E_OK]
 */
int CSYSRULESBUSINESS::ImportRFC3261(const char *filename)
{
    PRINT_DBG_HEAD
    print_dbg("import rfc3261 begin");

    int ret = E_FALSE;
    int tasknum = 0;

    if (m_fileop.OpenFile(filename, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        goto _out;
    }

    READ_INT(m_fileop, "SYS", "TaskNumSIP", tasknum, false, _out);
    PRINT_DBG_HEAD
    print_dbg("tasknum:%d", tasknum);

    if (tasknum > 0) {
        m_rfc3261 = (RFC3261SIP **)malloc(sizeof(RFC3261SIP *) * tasknum);
        if (m_rfc3261 == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc rfc3261 fail. size[%d] tasknum[%d]",
                      sizeof(RFC3261SIP *) * tasknum, tasknum);
            return E_FALSE;
        }
        memset(m_rfc3261 , 0, sizeof(RFC3261SIP *) * tasknum);
    }

    for (int i = 0; i < tasknum; i++) {
        m_rfc3261[i] = new RFC3261SIP(i);
        if (m_rfc3261[i] == NULL) {
            PRINT_ERR_HEAD
            print_err("new RFC3261 fail.[%d]", i);
            goto _out;
        }
        m_rfc3261_tasknum++;
        if (m_rfc3261[i]->loadConf(filename)) {
            AddNetWay(RFC3261_MOD, m_rfc3261[i]->getSecway());
        } else {
            goto _out;
        }
    }
    ret = E_OK;
_out:
    m_fileop.CloseFile();
    PRINT_DBG_HEAD
    print_dbg("import rfc3261 over ret = %d", ret);
    return ret;
}
