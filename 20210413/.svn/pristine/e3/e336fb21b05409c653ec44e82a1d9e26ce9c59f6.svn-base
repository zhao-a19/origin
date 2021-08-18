/*******************************************************************************************
*文件: update_make.h
*描述: 制作升级包
*作者: 王君雷
*日期: 2018-10-10
*修改：
*      添加内核升级功能                                                 ------> 2019-08-30
*      添加both目录，可以同时升级内外网文件                             ------> 2020-02-20 wjl
*      升级支持ARM平台                                                  ------> 2020-03-28-dzj
*      支持飞腾平台                                                     ------> 2020-07-27
*      支持tar包首部 2KB异或混淆，解包兼容旧版upk包                     ------> 2021-02-19 zza
*      加强调用参数判断,无实质性的改动                                  ------> 2021-03-04 wjl
*******************************************************************************************/
#ifndef __UPDATE_MAKE_H__
#define __UPDATE_MAKE_H__

#define THIS_TOOL_VER 20210304      //本工具的版本日期 可以知道每个升级包是使用哪个工具制作的 暂不会对它进行校验
#define THIS_TOOL_VER_XOR_OFFSET 100000000
#define THIS_TOOL_VER_XOR (THIS_TOOL_VER + THIS_TOOL_VER_XOR_OFFSET)
#define SYSVER_MAX_LEN 10
#define UPPACK_SUFFIX ".upk"
#define MAX_UPVER (0xFF)
#define MIN_UPVER (0x00)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define TOTAL_CHECK_KEY "sugap"
#define TOTAL_OS_KEY "osupk"
#define DEFAULT_TOTAL_VER "update"
#define FILE_PATH_MAX_LEN 1024
#define NAME_MAX_LEN 256
#define FHEAD_CHECK_KEY "SUFILE"
#define ONCE_READ_BLOCK_SIZE (102400) //读文件时每次读取的最大长度

#define INROOT_PATH      "inroot/"
#define OUTROOT_PATH     "outroot/"

#define BOTH_PATH        "both/"
#define IN_SHELL         "in.sh"
#define OUT_SHELL        "out.sh"
#define GAP_IN_SHELL     "/initrd/abin/gap_inupdate.sh"   //脚本放在网闸后的路径
#define GAP_OUT_SHELL    "/initrd/abin/gap_outupdate.sh"  //脚本放在网闸后的路径

//#define INROOT_SYS6      "inroot/initrd/abin/sys6"
//#define OUTROOT_SYS6     "outroot/initrd/abin/sys6_w"
#define SYSVER_FILE      "inroot/initrd/abin/version"
#define OS_PATH          "os/"
#define OS_UPDATE_SHELL  "os/osupdate.sh"
#define OS_UPDATE_PACK   "os/osimg.tgz"
#define FILES_PATH       "files/"
#define UPDATE_MK_TMPTAR "tmp.tar"

//平台类型
enum PLAT_TYPE {
    PLAT_UNKNOWN = -1,
    PLAT_I686 = 0,
    PLAT_SW_64,
    PLAT_X86_64,
    PLAT_ARM_64,
    PLAT_FT,
};

//文件权限类型
enum PERM_TYPE {
    PERM_DEF = 0,  //默认权限
    PERM_EXEC,     //可执行权限
};

//升级文件区域类型
enum FILE_AREA {
    FILE_AREA_INNET = 0,
    FILE_AREA_OUTNET = 1,
    FILE_AREA_OS = 2,
    FILE_AREA_BOTH = 3,
};

#pragma pack(push, 1)
//升级包头部
typedef struct _total_head {
    char checkkey[10];
    unsigned char upver;
    int toolver;
    int platver;
    unsigned char reserved[20];
    unsigned char md5buff16[16];
} TOTAL_HEAD, *PTOTAL_HEAD;

//每个待升级的目标文件的头部
typedef struct  _file_head {
    char checkkey[16];
    int area;
    char path[1024];
    unsigned char reserved[20];
    int permission;
    unsigned int len;
} FILE_HEAD, *PFILE_HEAD;
#pragma pack(pop)

bool make_updatepack(const char *filename, const char *sysver, int upver, int platver);
bool check_updatepack_suffix(const char *filename);
bool check_updatepack_platver(int platver);

#endif
