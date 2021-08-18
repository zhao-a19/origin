/*******************************************************************************************
*文件:    libftp.h
*描述:    FTP协议API继承原有接口，但内部实现更新为ftplib4.0
*
*作者:    张冬波
*日期:    2016-07-22
*修改:    修改文件接口实现                            ------>     2016-07-22
*
*******************************************************************************************/

#ifndef __LIBFTP_H__
#define __LIBFTP_H__

#ifdef __cplusplus

extern "C" {

#endif

#include <sys/cdefs.h>  /* get __P definition (prototypes) */
#include <netdb.h>

#define ON              1
#define OFF             0

#ifndef __CONST
#define __CONST const       /* 自定义__CONST */
#endif

#include "ftplib.h"
typedef struct {
    netbuf *handle;         //移植库句柄
    in_port_t ftp_port;     //用户指定服务端口号
} FTPINFO;

int ftp_accnt __P((FTPINFO *, __CONST char *));
int ftp_ascii __P((FTPINFO *));
int ftp_binary __P((FTPINFO *));
int ftp_bye __P((FTPINFO *));
int ftp_chdir __P((FTPINFO *, __CONST char *));
int ftp_command __P((FTPINFO *, __CONST char *, __CONST char *));
int ftp_dataconn __P((FTPINFO *, __CONST char *, __CONST char *, __CONST char *));
int ftp_del __P((FTPINFO *, __CONST char *));
int ftp_dir __P((FTPINFO *, __CONST char *, __CONST char *));
int ftp_ebcdic __P((FTPINFO *));
int ftp_getfile __P((FTPINFO *, __CONST char *, __CONST char *));
int ftp_idle __P((FTPINFO *, __CONST char *));
int ftp_initconn __P((FTPINFO *));
int ftp_login __P((FTPINFO *, __CONST char *, __CONST char *, __CONST char *, __CONST char *));
int ftp_mkdir __P((FTPINFO *, __CONST char *));
int ftp_passwd __P((FTPINFO *, __CONST char *));
int ftp_setport __P((FTPINFO *, in_port_t ));//zdb
int ftp_prconnect __P((FTPINFO *, __CONST char *));
int ftp_putfile __P((FTPINFO *, __CONST char *, __CONST char *));
int ftp_appfile __P((FTPINFO *, __CONST char *, __CONST char *));
int ftp_pwd __P((FTPINFO *));
int ftp_rmdir __P((FTPINFO *, __CONST char *));
int ftp_settype __P((FTPINFO *, int));
int ftp_site __P((FTPINFO *, __CONST char *));
int ftp_tenex __P((FTPINFO *));
int ftp_user __P((FTPINFO *, __CONST char *));
int ftp_rename __P((FTPINFO *ftp_info, __CONST char *, __CONST char *));
int ftp_moddate __P((FTPINFO *ftp_info, __CONST char *path, char *lasttime));
//zdb add
int ftp_init __P((FTPINFO *, int));
char* ftp_getmsg __P((FTPINFO *));
int ftp_opts __P((FTPINFO *ftp_info, __CONST char *opts));
//zdb add end

#ifdef __cplusplus

}

#endif


#endif


