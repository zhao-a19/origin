#include "FCMAINCTRL.h"
#include "FCMANAGEBS.h"

CMAINCTRL::CMAINCTRL()
{
    m_managebs = NULL;
    m_managebs = new CMANAGEBS;
}

CMAINCTRL::~CMAINCTRL()
{
    if (m_managebs != NULL)
    {
        delete m_managebs;
        m_managebs = NULL;
    }
}

bool CMAINCTRL::Start()
{
    if (m_managebs == NULL)
    {
        printf("new CMANAGEBS error!");
        return false;
    }
    //初始化所有业务
    if (!m_managebs->InitAllBS())
    {
        printf("m_managebs ->> InitAllBS Error!\n");
        return false;
    }
    else
    {
        return true;
    }
}

