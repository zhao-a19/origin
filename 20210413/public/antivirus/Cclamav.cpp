
/*******************************************************************************************
*文件:    Cclamav.cpp
*描述:    clamav病毒库
*
*作者:    张冬波
*日期:    2015-04-28
*修改:    创建文件                            ------>     2015-04-28
*
*******************************************************************************************/
#include "datatype.h"
#include "sysvirus.h"
#include "filename.h"
#include <clamav.h>
#include "debugout.h"
#include "stringex.h"

#define _ERROUT(e) {PRINT_ERR_HEAD; print_err("CLAMAV %s", cl_strerror(e)); return NULL;}
#define _HANDLESET(h) ((struct cl_engine *)(h))

CCLAMAV::CCLAMAV(): IVIRUS()
{

}

CCLAMAV::~CCLAMAV()
{
    release();
}


void *CCLAMAV::InitEngine(void)
{
    if (m_hengine != NULL) return m_hengine;    //重复调用

    int ret;

    if ((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) _ERROUT(ret);

    uint sigs = 0;

    if ((m_hengine = (void *)cl_engine_new()) == NULL) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS ENGINNE");
        return NULL;
    }

    if ((ret = cl_load(VIRUS_PATH, _HANDLESET(m_hengine), &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
        release();
        _ERROUT(ret);
    }

    if ((ret = cl_engine_compile(_HANDLESET(m_hengine))) != CL_SUCCESS) {
        release();
        _ERROUT(ret);
    }

    return m_hengine;
}

void CCLAMAV::release(void)
{
    if (m_hengine != NULL) {
        int ret;

        if ((ret = cl_engine_free(_HANDLESET(m_hengine))) != CL_SUCCESS) {
            PRINT_ERR_HEAD;
            print_err("CLAMAV %s", cl_strerror(ret));
        }
        m_hengine = NULL;

    }
}

bool CCLAMAV::scanvirus(const pchar filepath, pchar virus)
{
    if ((m_hengine == NULL) || !is_file(filepath)) return false;

    const char *tmp = NULL;
    bool bret = false;
    unsigned long fsize = 0;
    int scanret;

#if (SUOS_V==2000)
    struct cl_scan_options scanoptions;
    scanoptions.parse = CL_SCAN_STDOPT;
    bret = ((scanret = cl_scanfile(filepath, &tmp, &fsize, _HANDLESET(m_hengine),
                                   &scanoptions)) == CL_VIRUS);
#else
    bret = ((scanret = cl_scanfile(filepath, &tmp, &fsize, _HANDLESET(m_hengine),
                                   CL_SCAN_STDOPT)) == CL_VIRUS);
#endif
    PRINT_DBG_HEAD;
    print_dbg("CLAMAV FIND = %s:%lu, %d(%s)", filepath, fsize, scanret, cl_strerror(scanret));

    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("CLAMAV FIND = %s:%lu, virus = %s", filepath, fsize, tmp);

        if (virus != NULL)    strcpy(virus, tmp);
    }

    return bret;
}


cpchar CCLAMAV::getversion(void)
{
    if (is_strempty(m_version)) getversion(m_version);

    return (cpchar)m_version;
}

cpchar CCLAMAV::getversion(pchar user)
{
    if (user == NULL) return NULL;

    char dailypath[_FILEPATHMAX] = {0};
    char mainpath[_FILEPATHMAX] = {0};

    make_filepath(VIRUS_PATH, "daily.cvd", dailypath);
    make_filepath(VIRUS_PATH, "main.cvd", mainpath);

    struct cl_cvd *myvermain;
    struct cl_cvd *myverdaily;

    myvermain = cl_cvdhead(mainpath);
    myverdaily = cl_cvdhead(dailypath);

    if (myvermain != NULL && myverdaily != NULL) {
        sprintf(user, "%d.%d", myvermain->version, myverdaily->version);
        cl_cvdfree(myvermain);
        cl_cvdfree(myverdaily);
    } else {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS file = %s;%s", dailypath, mainpath);
        return NULL;
    }

    PRINT_DBG_HEAD;
    print_dbg("CLAMAV VER(%s) = %s", mainpath, user);

    return (cpchar)user;

}
