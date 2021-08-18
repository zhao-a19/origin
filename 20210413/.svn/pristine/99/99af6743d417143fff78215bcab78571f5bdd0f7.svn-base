#include "FCWINCCSingle.h"

CWINCCSINGLE::CWINCCSINGLE()
{
}

CWINCCSINGLE::~CWINCCSINGLE()
{

}

bool CWINCCSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1)
    {
        return DoSrcMsg(sdata, slen, cherror);
    }
    else
    {
        return DoDstMsg(sdata, slen, cherror);
    }
}

bool CWINCCSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    if (datalen <= 8)
    {
        return true;
    }

    if (sdata[hdlen + 0] == 0x03 && (sdata[hdlen + 2] * 256 + sdata[hdlen + 3] == slen - hdlen)) //protocol is wincc
    {
        if (sdata[hdlen + 5] == 0x0f) //is data
        {
            int startpos = sdata[hdlen + 4] + 5;
            char codeid[10] = "";
            sprintf(codeid, "%02X", sdata[hdlen + startpos + 9]);
            sprintf(codeid + 2, "%02X", sdata[hdlen + startpos + 10]);
            if (FilterCode(codeid))
            {
                RecordCallLog(sdata, "CODE", codeid, cherror, true);
                return true;
            }
            else
            {
                sprintf(cherror, "%s", WINCC_PERM_FORBID);
                RecordCallLog(sdata, "CODE", codeid, cherror, false);
                return false;
            }
        }
        else
        {
            return true;
        }
    }
    else
    {
        return false;
    }
}

bool CWINCCSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

bool CWINCCSINGLE::FilterCode(char *codeid)
{
    for (int i = 0; i < m_service->m_cmdnum; i++)
    {
        if (strcasecmp("CODE", m_service->m_cmd[i]->m_cmd) == 0)
        {
            if (memcmp(m_service->m_cmd[i]->m_parameter, codeid, 4) == 0)
            {
                return m_service->m_cmd[i]->m_action;
            }
        }
    }

    //Î´¶¨ÒåÃüÁî
    return m_service->m_IfExec;
}
