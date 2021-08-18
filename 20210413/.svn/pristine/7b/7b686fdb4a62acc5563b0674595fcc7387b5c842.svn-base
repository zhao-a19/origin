/*******************************************************************************************
*文件:    Ivirus.h
*描述:    病毒库应用接口
*
*作者:    张冬波
*日期:    2015-04-28
*修改:    创建文件                            ------>     2015-04-28
*
*******************************************************************************************/
#include "datatype.h"
#include <dlfcn.h>

class IVIRUS
{
public:
    IVIRUS() {m_hengine = NULL; memset(m_version, 0, sizeof(m_version)); }
    virtual ~IVIRUS() {}

    /**
     * [InitEngine 初始化话杀毒引擎]
     * @return  [引擎句柄]
     */
    virtual void *InitEngine(void) {return NULL;}

    /**
     * [release 关闭引擎]
     */
    virtual void release(void) {}

    /**
     * [scanvirus 扫描文件]
     * @param  filepath [文件路径]
     * @param  virus    [病毒类型，可以NULL]
     * @return          [true 发现病毒]
     */
    virtual bool scanvirus(const pchar filepath, pchar virus) {return false;}
    virtual bool killvirus(cpchar filepath, pchar virus) {return false;}

    /**
     * [scanvirus 扫描内存]
     * @param  buff  [数据地址]
     * @param  size  [数据大小]
     * @param  virus [病毒类型，可以NULL]
     * @return       [true 发现病毒]
     */
    virtual bool scanvirus(cpchar buff, uint32 size, pchar virus) {return false;}
    virtual bool killvirus(cpchar buff, uint32 size, pchar virus) {return false;}


    /**
     * [getversion 读取病毒库版本]
     * @return       [病毒库版本]
     */
    virtual cpchar getversion(void) {return (cpchar)m_version;}

protected:
    void *m_hengine;
    char m_version[100];

};


