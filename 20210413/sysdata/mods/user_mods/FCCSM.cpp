#include "FCCSM.h"

CCSM::CCSM()
{
    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_param, 0, sizeof(ch_param));
}

CCSM::~CCSM()
{

}

bool CCSM::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
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

bool CCSM::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    if (datalen <= 0)
    {
        return true;
    }

    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_param, 0, sizeof(ch_param));

    if (IsHeartBeatToTCC(sdata+hdlen, datalen, cherror)
        || IsRequestToTC(sdata+hdlen, datalen, cherror)
        || IsToCSM(sdata+hdlen, datalen, cherror))
    {
        RecordCallLog(sdata, ch_cmd, ch_param, cherror, true);
        printf("%s\n", ch_cmd);
        return true;
    }

    printf("src drop![%d]\n", slen);

    return false;
}

bool CCSM::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    if (datalen <= 0)
    {
        return true;
    }

    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_param, 0, sizeof(ch_param));

    if (IsDataFromTCC(sdata+hdlen, datalen, cherror)
        || IsResponseFromTC(sdata+hdlen, datalen, cherror)
        || IsDataFromTC(sdata+hdlen, datalen, cherror)
        || IsToCSM(sdata+hdlen, datalen, cherror))
    {
        RecordCallLog(sdata, ch_cmd, ch_param, cherror, true);
        printf("%s\n", ch_cmd);
        return true;
    }

    printf("dst drop![%d]\n", slen);

    return false;
}

//-------------------------------------------------------------------------
bool CCSM::IsHeartBeatToTCC(unsigned char *sdata, int slen, char *cherror)
{
    if ((sdata==NULL) || (slen != 17) || (cherror==NULL))
    {
        return false;
    }

    char chbuff[16];
    memset(chbuff, 0xFF, sizeof(chbuff));

    if ((sdata[0] == 0x20))
    {
        if (memcmp(sdata + slen - 7, chbuff, 7) == 0)
        {
            strcpy(ch_cmd, "HeartBeat");
            return true;
        }
    }
    return false;
}

bool CCSM::IsDataFromTCC(unsigned char *sdata, int slen, char *cherror)
{
    if ((sdata==NULL) || (slen < 16) || (cherror==NULL))
    {
        return false;
    }
    char chbuff[16];
    memset(chbuff, 0, sizeof(chbuff));
    chbuff[0] = 0x43;
    chbuff[1] = 0x52;
    chbuff[2] = 0x53;
    chbuff[3] = 0x43;

    if (sdata[0] == 0x20)
    {
        if (memcmp(sdata + slen - 4, chbuff, 4) == 0)
        {
            strcpy(ch_cmd, "Data");
            return true;
        }
    }
    return false;
}
//-------------------------------------------------------------------------
bool CCSM::IsRequestToTC(unsigned char *sdata, int slen, char *cherror)
{
    if ((sdata==NULL) || (slen != 22) || (cherror==NULL))
    {
        return false;
    }

    char chbuff[16];
    memset(chbuff, 0xFF, sizeof(chbuff));

    if ((sdata[0] == 0x20) && (sdata[5] == 0x01))
    {
        if (memcmp(sdata + 12, chbuff, 10) == 0)
        {
            strcpy(ch_cmd, "Request");
            return true;
        }
    }
    return false;
}

bool CCSM::IsResponseFromTC(unsigned char *sdata, int slen, char *cherror)
{
    if ((sdata==NULL) || (slen != 22) || (cherror==NULL))
    {
        return false;
    }

    char chbuff[16];
    memset(chbuff, 0xFF, sizeof(chbuff));

    if ((sdata[0] == 0x20) && (sdata[5] == 0x02))
    {
        if (memcmp(sdata + 12, chbuff, 10) == 0)
        {
            strcpy(ch_cmd, "Response");
            return true;
        }
    }
    return false;
}

bool CCSM::IsDataFromTC(unsigned char *sdata, int slen, char *cherror)
{
    if ((sdata==NULL) || (slen < 16) || (cherror==NULL))
    {
        return false;
    }
    char chbuff[16];
    memset(chbuff, 0, sizeof(chbuff));
    chbuff[0] = 0x43;
    chbuff[1] = 0x52;
    chbuff[2] = 0x53;
    chbuff[3] = 0x43;

    if ((sdata[0] == 0x20) && (sdata[5] == 0x21))
    {
        if (memcmp(sdata + slen - 4, chbuff, 4) == 0)
        {
            strcpy(ch_cmd, "Data");
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
bool CCSM::IsToCSM(unsigned char *sdata, int slen, char *cherror)
{
    if ((sdata==NULL) || (slen < 6) || (cherror==NULL))
    {
        return false;
    }

    if (sdata[4] == 0x0F)
    {
        if (slen == 17)
        {
            if (sdata[slen - 1] == 0xFF)
            {
                strcpy(ch_cmd, "HeartBeat");
                return true;
            }
        }
    }

    if (sdata[4] == 0x8F)
    {
        if (sdata[slen - 1])
        {
            strcpy(ch_cmd, "Data");
            return true;
        }
    }
    return false;
}
