
/*******************************************************************************************
*文件:    Cavl.cpp
*描述:    安天病毒库 www.antiy.cn
*
*作者:    张冬波
*日期:    2017-12-17
*修改:    创建文件                            ------>     2017-12-17
*
*******************************************************************************************/
#include "datatype.h"
#include "sysvirus.h"
#include "filename.h"
#include "debugout.h"
#include "stringex.h"

#include "engine.h"
#include "error_code.h"
#include "AVLSDK_rpt_idx.h"
#include "AVLSDK_conf_idx.h"
#include "ID2Name_interface.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

CAVL::CAVL(): IVIRUS()
{
    m_NT = NULL;
}

CAVL::~CAVL()
{
    release();
}


void *CAVL::InitEngine(void)
{
    if (m_hengine != NULL) return m_hengine;    //重复调用

    char avfile[_FILEPATHMAX] = {0};
    long errret;

    if ((errret = AVL_SDK_CreateInstance(&m_hengine)) != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS ENGINNE %ld", errret);
        return NULL;
    }

    make_filepath(VIRUS_PATH, "high_speed.ct", avfile);
    PRINT_DBG_HEAD;
    print_dbg("SYSTEM VIRUS CFG %s", avfile);
    if ((errret = AVL_SDK_LoadConfigFile(m_hengine, avfile)) != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS CFG %ld %s", errret, avfile);
        release();
        return NULL;
    }

    // Set the configuration by users CFG_INT_MAX_SCAN_LEVEL_LIMIT >=CFG_INT_APACK_RECURE_LAYER
    if ((errret = AVL_SDK_SetConfigInt(m_hengine, CFG_INT_APACK_RECURE_LAYER, 5)) != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS CFG %ld", errret);
        release();
        return NULL;
    }

    if ((errret = AVL_SDK_SetConfigInt(m_hengine, CFG_INT_MAX_SCAN_LEVEL_LIMIT, 5)) != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS CFG %ld", errret);
        release();
        return NULL;
    }

    make_filepath(VIRUS_PATH, "License.alf", avfile);
    PRINT_DBG_HEAD;
    print_dbg("SYSTEM VIRUS CFG %s", avfile);
    if ((errret = AVL_SDK_SetConfigString(m_hengine, CFG_STR_LICENSE_PATH, avfile)) != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS CFG %ld %s", errret, avfile);
        release();
        return NULL;
    }

    make_filepath(VIRUS_PATH, "Module", avfile);
    PRINT_DBG_HEAD;
    print_dbg("SYSTEM VIRUS CFG %s", avfile);
    if ((errret = AVL_SDK_SetConfigString(m_hengine, CFG_STR_MODULE_PATH, avfile)) != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS CFG %ld %s", errret, avfile);
        release();
        return NULL;
    }

    make_filepath(VIRUS_PATH, "Data", avfile);
    PRINT_DBG_HEAD;
    print_dbg("SYSTEM VIRUS CFG %s", avfile);
    if ((errret = AVL_SDK_SetConfigString(m_hengine, CFG_STR_DATA_PATH, avfile)) != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS CFG %ld %s", errret, avfile);
        release();
        return NULL;
    }

    if ((errret = AVL_SDK_InitInstance(m_hengine, NULL)) != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS ENGINNE INIT %ld", errret);
        m_hengine = NULL;
        release();
        return NULL;
    }

    make_filepath(VIRUS_PATH, "NData", avfile);
    if ((errret = AVL_NTranser_Init(avfile, &m_NT)) != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("SYSTEM VIRUS NAME %ld %s", errret, avfile);
        release();
        return NULL;
    }

#if 0
    //读取所有配置信息
    for (int32 i = CFG_FLAG_SHELL_RECG_LOAD; i < CFG_ITEM_MAX_LIMIT; i++) {
        long j = 0;
        if (AVL_SDK_GetConfigInt(m_hengine, (long)i, &j) == ERR_SUCCESS) {
            PRINT_INFO_HEAD;
            print_info("FILE CFG %d = %ld", i, j);
        }
    }

#endif

    return m_hengine;
}

void CAVL::release(void)
{
    if (m_hengine != NULL) {
        AVL_SDK_Release(m_hengine);
    }
    m_hengine = NULL;

    if (m_NT != NULL) {
        AVL_NTranser_Release(m_NT);
    }
    m_NT = NULL;
}

//自定义回调函数数据
typedef struct  {
    void *_hengine;
    void *_hname;
    pchar _vname;   //病毒名
    unsigned long _vsize;
    bool bfile;     //文件标识
} CB_DATA, *PCB_DATA;

static long _query_continue_callback(void *p_param)
{
    // This is the code sample, so it returns unconditionally.
    // Users can modify according to the condition.
    return  OD_CONTINUE;
}

#define _ERROUT(e) {PRINT_ERR_HEAD; print_err("AVL %ld", e); return -1;}

static long _rpt_callback(P_OBJ_PROVIDER p_op, void *p_data, void *p_param)
{
    long _malware_id = 0, _qry_ret = 0;
    PCB_DATA pdata = (PCB_DATA)p_param;
    puint8 _analyser = NULL, _desc = NULL;

    if ((p_data == NULL) || (p_param == NULL)) {
        _ERROUT(0L);
    }

    // Query the Malware ID
    _qry_ret = AVL_SDK_QueryReportInt(pdata->_hengine, p_data, RPT_IDX_MALWARE_ID, &_malware_id);
    if (_qry_ret == ERR_RPT_NOT_EXIST) {
        PRINT_DBG_HEAD;
        print_dbg("AVL %ld", _qry_ret);
        return -1;
    } else if (_qry_ret < 0) {
        _ERROUT(_qry_ret);
    }

    // Query the analyser who detected this malware,
    // users will use it when they need to get the malware name
    _qry_ret = AVL_SDK_QueryReportStr(pdata->_hengine, p_data, RPT_IDX_ANALYSER, &_analyser);
    if (_qry_ret != ERR_SUCCESS) {
        _ERROUT(_qry_ret);
    }

    // Query the VName
    _qry_ret = AVL_NTranser_QueryNameByID(pdata->_hname, (pchar)_analyser, _malware_id,
                                          (puint8)pdata->_vname, pdata->_vsize);
    if (_qry_ret < 0) {
        _ERROUT(_qry_ret);
    }

    // Query current description about the object
    if (pdata->bfile) {
        _qry_ret = AVL_SDK_QueryReportStr(pdata->_hengine, p_data, RPT_IDX_OBJ_DESCRIPTION, &_desc);
        if (_qry_ret != ERR_SUCCESS) {
            _ERROUT(_qry_ret);
        }
        PRINT_DBG_HEAD;
        print_dbg("AVL FIND %x:%s, %s", _malware_id, pdata->_vname, (pchar)_desc);
    } else {
        PRINT_DBG_HEAD;
        print_dbg("AVL FIND %x:%s", _malware_id, pdata->_vname);
    }


    return 0;
}

bool CAVL::scanvirus(cpchar filepath, pchar virus)
{
    if (!is_file(filepath)) return false;

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        PRINT_ERR_HEAD;
        print_err("AVL FIND %s", filepath);
        return false;
    }

    bool bret = false;
    struct stat status = {0};
    lstat(filepath, &status);

    puint8 buff = (puint8)mmap(NULL, status.st_size, PROT_READ, MAP_SHARED, fd, 0);   //文件数据地址
    if (buff == MAP_FAILED) {
        PRINT_ERR_HEAD;
        print_err("AVL MAP %s", strerror(errno));
        close(fd);
        return false;
    }

    bret = _avlscan(buff, status.st_size, virus, true, filepath);

    if (munmap(buff, status.st_size) != 0) {
        PRINT_ERR_HEAD;
        print_err("AVL UMAP %llu, %s", status.st_size, strerror(errno));
    }
    close(fd);
    return bret;
}

bool CAVL::scanvirus(cpchar buff, uint32 size, pchar virus)
{
    return _avlscan(buff, size, virus, false, NULL);
}

bool CAVL::_avlscan(const void *data, uint32 size, pchar virus, bool bfile, cpchar filepath)
{
    if ((m_hengine == NULL) || (m_NT == NULL) || (data == NULL)) {
        PRINT_ERR_HEAD;
        print_err("AVL SCAN NULL %p, %p, %p", m_hengine, m_NT, data);
        return false;
    }

    bool bret = false;
    long errret;

    OBJ_PROVIDER obj_p = {0};
    OBJ_DISPOSER obj_d = {0};
    CB_DATA cb_data = {0};
    char virusname[200] = {0};

    obj_p.obj_ver = CUR_ENGINE_VER;
    obj_p.evro_type = ET_DESKTOP;
    obj_p.buf = (puint8)data;   //数据地址
    obj_p.size = size;  //数据大小
    if ((cb_data.bfile = bfile) && !is_strempty(filepath)) {
        strncpy((pchar)obj_p.obj_des, filepath, sizeof(obj_p.obj_des) - 1);
    }

    cb_data._hengine = m_hengine;
    cb_data._hname = m_NT;
    cb_data._vname = virusname;
    cb_data._vsize = sizeof(virusname) - 1;

    obj_d.rpt_callback = _rpt_callback;
    obj_d.p_rpt_param = &cb_data;
    obj_d.query_continue_callback = _query_continue_callback;
    obj_d.p_qc_param = NULL;

    errret = AVL_SDK_Scan(m_hengine, &obj_p, &obj_d);
    if (errret != ERR_SUCCESS) {
        PRINT_ERR_HEAD;
        print_err("AVL FIND %ld = %s:%u", errret, filepath, size);
    } else {

        PRINT_DBG_HEAD;
        print_dbg("AVL FIND = %s:%u, virus = %s", filepath, size, virusname);

        if (!is_strempty(virusname)) {
            bret = true;
            if (virus != NULL)  strcpy(virus, virusname);
        }
    }

    return bret;
}

cpchar CAVL::getversion(void)
{
    if (is_strempty(m_version)) AVL_SDK_GetCurVersion((puint8)m_version, sizeof(m_version) - 1);

    PRINT_DBG_HEAD;
    print_dbg("AVL VER = %s", m_version);

    return (cpchar)m_version;
}
