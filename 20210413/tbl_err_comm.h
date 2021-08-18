/*******************************************************************************************
*文件:  tbl_err_comm.h
*描述:  表损坏 内部通信
*作者:  王君雷
*日期:  2019-12-09
*修改:
*******************************************************************************************/
#ifndef __TBL_ERR__COMM_H__
#define __TBL_ERR__COMM_H__

bool tbl_err_comm_init(void);
bool tbl_err_put_request(const char *tbname, int tlen);
bool tbl_err_get_request(char *tbname, int tlen);

#endif
