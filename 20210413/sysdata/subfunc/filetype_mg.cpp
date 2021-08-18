/*******************************************************************************************
*文件:  filetype_mg.h
*描述:  文件类型过滤管理
*作者:  王君雷
*日期:  2020-11-02
*修改:
*******************************************************************************************/
#include "filetype_mg.h"
#include "debugout.h"
#include "define.h"
#include "fileoperator.h"
#include "readcfg.h"

FileTypeMG::FileTypeMG(void)
{
    memset(m_filetypestr, 0, sizeof(m_filetypestr));
    m_cktype = 0;
    m_filetype.clear();
    InitLock();
}

FileTypeMG::~FileTypeMG(void)
{
}

/**
 * [FileTypeMG::InitLock 初始化互斥锁]
 */
void FileTypeMG::InitLock(void)
{
    if (sem_init(&m_lock, 0, 1) == -1) {
        PRINT_ERR_HEAD
        print_err("init lock fail");
    }
}

/**
 * [FileTypeMG::GetInstance 获取唯一的对象实例的引用]
 * @return  [唯一对象实例的引用]
 */
FileTypeMG &FileTypeMG::GetInstance(void)
{
    static FileTypeMG instance_;
    return instance_;
}

/**
 * [FileTypeMG::Filter 过滤]
 * @param  fname   [文件名]
 * @param  cherror [返回出错信息]
 * @return         [允许通过返回true]
 */
bool FileTypeMG::Filter(const char *fname, char *cherror)
{
    if (fname == NULL) {
        sprintf(cherror, "%s", FILE_NAME_NULL);
        PRINT_ERR_HEAD
        print_err("para null while filter file type");
        return false;
    }

    if (m_cktype == 0) {
        return true;
    }

    sem_wait(&m_lock);

    bool isnullfile = true;//是否为无后缀文件
    bool bflag = (m_cktype == 2); //是否允许通过 默认动作

    //查找扩展名位置
    char *ptr = rindex((char *)fname, '.');
    if (ptr != NULL) {
        if ((index(ptr, '/') != NULL) || (index(ptr, '\\') != NULL)) {
        } else {
            isnullfile = false;
        }
    }

    if (isnullfile) {
        for (int i = 0; i < (int)m_filetype.size(); i++) {
            if (strcmp(m_filetype[i].c_str(), "*") == 0) {
                bflag = (m_cktype == 1);
                break;
            }
        }
    } else {
        for (int i = 0; i < (int)m_filetype.size(); i++) {
            if (strcasecmp(m_filetype[i].c_str(), ptr + 1) == 0) {
                bflag = (m_cktype == 1);
                break;
            }
        }
    }

    sem_post(&m_lock);
    if (!bflag) {
        sprintf(cherror, "%s", FILE_TYPE_FORBID);
        PRINT_ERR_HEAD
        print_err("file(%s) not allow to pass", fname);
    }
    return bflag;
}

/**
 * [FileTypeMG::ReadConf 读取配置信息]
 * @return  [成功返回0]
 */
int FileTypeMG::ReadConf(void)
{
    int type = 0;
    CFILEOP fileop;
    if (fileop.OpenFile(SYSSET_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("OpenFile[%s] fail", SYSSET_CONF);
        return -1;
    }

    READ_INT(fileop, "SYSTEM", "CKFileType", type, false, _out);
    if (type != 0) {
        READ_STRING(fileop, "SYSTEM", "FilterFileType", m_filetypestr, false, _out);
    }
    fileop.CloseFile();

    PRINT_INFO_HEAD
    print_info("ckfiletype[%d] filterfiletype[%s]", type, m_filetypestr);

    sem_wait(&m_lock);
    m_cktype = type;
    Separate();
    sem_post(&m_lock);
    return 0;

_out:
    PRINT_ERR_HEAD
    print_err("read conf fail");
    fileop.CloseFile();
    return -1;
}

/**
 * [FileTypeMG::Separate 解析分隔文件类型]
 */
void FileTypeMG::Separate(void)
{
    m_filetype.clear();
    if (m_cktype != 0) {
        char fileterfiletype[C_MAX_FILTERFILETYPE_LEN] = {0};
        strcpy(fileterfiletype, m_filetypestr);

        //名单指定的文件类型
        char *p = NULL;
        char *buf = fileterfiletype;
        while ((p = strtok(buf, ",")) != NULL) {
            buf = NULL;
            m_filetype.push_back(string(p));
        }
    }
}

/**
 * [FileTypeMG::Size vector元素个数]
 * @return  [description]
 */
int FileTypeMG::Size(void)
{
    return m_filetype.size();
}
