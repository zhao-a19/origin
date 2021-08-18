
/*******************************************************************************************
*文件:    Crisingav.cpp
*描述:    瑞星病毒库
*
*作者:    张冬波
*日期:    2015-04-28
*修改:    创建文件                            ------>     2015-04-28
*         修改bug                             ------>     2015-09-17
*
*******************************************************************************************/
#include "datatype.h"
#include "sysvirus.h"
#include "filename.h"
#include "mavapi.h"
#include "debugout.h"
#include "stringex.h"

#define _ERRASSERT {if(dlerror() != NULL){PRINT_ERR_HEAD;print_err("RISING %s", dlerror());return false;}}
#define _ERRASSERT1 {if(dlerror() != NULL){release();PRINT_ERR_HEAD;print_err("RISING %s",dlerror());return NULL;}}

CRISINGAV::CRISINGAV(): IVIRUS()
{

}

CRISINGAV::~CRISINGAV()
{
    release();
}

void *CRISINGAV::InitEngine(void)
{
    if (m_hengine != NULL) return m_hengine;    //重复调用

    //读入动态库
    char EnginePath[_FILEPATHMAX] = {0};
    make_filepath(VIRUS_PATH, "risingengine.so", EnginePath);

    if ((m_hengine = dlopen(EnginePath, RTLD_LAZY)) == NULL) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS DLL = %s", EnginePath);
        return NULL;
    }

    //打开引擎
    long  (*OpenMAVEngine)(char *, long, long);
    OpenMAVEngine = (long(*)(char *, long, long))dlsym(m_hengine, "OpenMAVEngine");
    _ERRASSERT1;

    if (OpenMAVEngine(VIRUS_PATH, 1, 30) == -1) {     //现有引擎.so导致死机，free段错误
        release();
        PRINT_ERR_HEAD;
        print_err("RISING OpenMAVEngine");
        return NULL;
    }

    /*
        bool  (*SetMaxSearchDepth)(int);
        SetMaxSearchDepth = (bool(*)(int))dlsym(m_hengine, "SetMaxSearchDepth");
        _ERRASSERT1;
    */

    void  (*SetMAVUserNumCallBack)(GETMAVUSERNUMPROC);
    SetMAVUserNumCallBack = (void(*)(GETMAVUSERNUMPROC))dlsym(m_hengine, "SetMAVUserNumCallBack");
    _ERRASSERT1;

    SetMAVUserNumCallBack(GetScanNumforMAV);    //如何应用？？？

    return m_hengine;
}

void CRISINGAV::release(void)
{
    if (m_hengine != NULL) {
        long  (*CloseMAVEngine)(short) = (long(*)(short))dlsym(m_hengine, "CloseMAVEngine");
        if (dlerror() != NULL) {
            PRINT_ERR_HEAD;
            print_err("RISING %s", dlerror());
            return;
        }

        CloseMAVEngine(true);
        m_hengine = NULL;
    }
}

bool CRISINGAV::scanvirus(const pchar filepath, pchar virus)
{
    return _rising(filepath, 0, virus, true, false);
}

bool CRISINGAV::killvirus(cpchar filepath, pchar virus)
{
    return _rising(filepath, 0, virus, true, true);
}

bool CRISINGAV::scanvirus(cpchar buff, uint32 size, pchar virus)
{
    return _rising(buff, size, virus, false, false);
}

bool CRISINGAV::killvirus(cpchar buff, uint32 size, pchar virus)
{
    return _rising(buff, size, virus, false, true);
}

cpchar CRISINGAV::getversion(void)
{
    if (m_hengine == NULL) return NULL;

    if (is_strempty(m_version)) {
        char tmp[100] = {0};
        void  (*GetVirusDefVersion)(char *);
        GetVirusDefVersion = (void(*)(char *))dlsym(m_hengine, "GetVirusDefVersion");
        if (dlerror() == NULL) {
            GetVirusDefVersion(tmp);
            sprintf(m_version, "RISING:%s", tmp);
        }

        PRINT_DBG_HEAD;
        print_dbg("RISING VER = %s", m_version);

    }

    return (cpchar)m_version;
}

bool CRISINGAV::_rising(const void *data, uint32 size, pchar virus, bool bfile, bool bkill)
{
    if (m_hengine == NULL) return false;

    if (bfile) {
        if (is_file((char *)data)) return false;
    } else {
        if ((data == NULL) || (size == 0))   return false;
    }

    if (bfile) {
        long  (*IsNeedScan)(char *);
        IsNeedScan = (long(*)(char *))dlsym(m_hengine, "IsNeedScan");
        _ERRASSERT;
        if (IsNeedScan((pchar)data) < 0) {
            PRINT_DBG_HEAD;
            print_dbg("RISING FILE INVALID");
            return false;
        }
    }

    unsigned long (*MailMAVScanEx)(PMAVSCANINFOEX, PMAVMAILINFO *);
    MailMAVScanEx = (unsigned long(*)(PMAVSCANINFOEX, PMAVMAILINFO *))dlsym(m_hengine, "MailMAVScanEx");
    _ERRASSERT;
    void  (*FreeMAVMailInfo)(PMAVMAILINFO);
    FreeMAVMailInfo = (void(*)(PMAVMAILINFO))dlsym(m_hengine, "FreeMAVMailInfo");
    _ERRASSERT;

    //search and kill
    MAVSCANINFOEX stScanInfoex;
    PMAVMAILINFO pMailInfo = NULL;
    NVMBMEMDATA memdata;
    bool bret = false;

    stScanInfoex.dwKillType = bkill ? MAV_KILLTYPE_KILL : MAV_KILLTYPE_SCAN;
    stScanInfoex.dwFilterType = MAV_FILTERTYPE_NULL;
    stScanInfoex.dwCompress = MAV_COMPRESS_BOTH | MAV_COMPRESS_MULTI;
    strcpy(stScanInfoex.szFilePath, (cpchar)data);
    stScanInfoex.szScanFilter[0] = 0;
    stScanInfoex.nType = MAVDISKFILE;
    if (!bfile) {
        stScanInfoex.nType = MAVMEMFILE;
        stScanInfoex.pData = (void *)&memdata;
        memdata.pData = (puint8)data;
        memdata.nDataSize = memdata.nBufSize = size;
    }

    MailMAVScanEx(&stScanInfoex, &pMailInfo);

    if (bret = (pMailInfo->dwInfectCount > 0)) {
        if (virus != NULL)   strcpy(virus, pMailInfo->pAttachList->szVirusName);
        if (bkill) {
            bret = (pMailInfo->dwDelFailCount > 0);
        }

        if (bfile) {
            PRINT_DBG_HEAD;
            print_dbg("RISING FIND = %s, virus = %s", (pchar)data, pMailInfo->pAttachList->szVirusName);
        } else {
            PRINT_DBG_HEAD;
            print_dbg("RISING FIND virus = %s", pMailInfo->pAttachList->szVirusName);
        }
    }

    FreeMAVMailInfo(pMailInfo);


    return bret;
}

long CRISINGAV::GetScanNumforMAV(void)
{
    long num = 0;
    return num;
}

