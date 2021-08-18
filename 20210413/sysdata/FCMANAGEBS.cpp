/*******************************************************************************************
*文件:  FCMANAGEBS.cpp
*描述:  管理业务类
*作者:  王君雷
*日期:  2016-03
*修改
*      格式化程序；使用zlog                                        ------> 2018-08-31
*******************************************************************************************/
#include "FCMANAGEBS.h"
#include "FCLogManage.h"
#include "debugout.h"
#include "define.h"

CMANAGEBS::CMANAGEBS(void)
{
    m_bs_cnt = 0;
    BZERO(m_bs);
    BZERO(m_bs_type);
    m_hotbakbs = new CHOTBAKBS;
}

CMANAGEBS::~CMANAGEBS(void)
{
    DELETE_N(m_bs, m_bs_cnt);
    DELETE(m_hotbakbs);
}

/**
 * [CMANAGEBS::CreateBS 创建业务对象]
 * @param  type   [对象类型]
 * @return        [失败返回E_FALSE 成功返回对象下标]
 */
int CMANAGEBS::CreateBS(int type)
{
    if (m_bs_cnt >= MAX_BUSINESS_NUM) {
        PRINT_ERR_HEAD
        print_err("bs count full[%d],type[%d]", m_bs_cnt, type);
        return E_FALSE;
    }
    switch (type) {
    case C_BSTYPE_RULE_DEV: {
        m_bs[m_bs_cnt] = new CDEVBS;
        m_bs_type[m_bs_cnt] = type;
        break;
    }
    case C_BSTYPE_RULE_YWBS: {
        m_bs[m_bs_cnt] = new CYWBS;
        m_bs_type[m_bs_cnt] = type;
        break;
    }
    default: {
        PRINT_ERR_HEAD
        print_err("unkonwn type[%d]", type);
        return E_FALSE;
    }
    }
    m_bs_cnt++;
    return m_bs_cnt - 1;
}

/**
 * [CMANAGEBS::InitAllBS 初始化所有业务]
 * @return [成功返回true]
 */
bool CMANAGEBS::InitAllBS(void)
{
    if (m_hotbakbs == NULL) {
        PRINT_ERR_HEAD
        print_err("hotbakbs null");
        return false;
    }
    m_bs_cnt = 0;

    //设备管理业务
    if (CreateBS(C_BSTYPE_RULE_DEV) == E_FALSE) {
        return false;
    }
    //设备规则业务
    if (CreateBS(C_BSTYPE_RULE_YWBS) == E_FALSE) {
        return false;
    }

    ((CYWBS *)m_bs[1])->SetDevBS(((CDEVBS *)m_bs[0]));

    CLOGMANAGE mlog;
    mlog.Init();
    //设备文件读取
    while (!m_bs[0]->LoadData()) {
        mlog.WriteSysLog(LOG_TYPE_RUN, D_FAIL, LOG_CONTENT_READ_DEVBS_ERR);
        sleep(2);
    }

    //策略文件读取
    while (!m_bs[1]->LoadData()) {
        mlog.WriteSysLog(LOG_TYPE_RUN, D_FAIL, LOG_CONTENT_READ_YWBS_ERR);
        sleep(2);
    }
    mlog.DisConnect();

    //hotbak 业务
    m_hotbakbs->SetDevBS(((CDEVBS *)m_bs[0]));
    m_hotbakbs->SetYWBS(((CYWBS *)m_bs[1]));
    m_hotbakbs->Start();

    return true;
}
