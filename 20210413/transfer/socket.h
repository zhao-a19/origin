/*******************************************************************************************
*文件:  socket.h
*描述:  socket相关操作函数
*作者:  王君雷
*日期:  2020-03-07
*修改:
*******************************************************************************************/
#ifndef __SOCKET_H__
#define __SOCKET_H__

#include <arpa/inet.h>

bool fill_addr(const char *ip, int port, struct sockaddr_storage &addr, int &addrlen);
int server_socket(const char *ip, int port);
int client_socket(const char *ip, int port);

#define CLOSE(fd) if (fd > 0){ close(fd);fd = 0;}
#define FCLOSE(fp) if (fp != NULL) {fclose(fp);fp = NULL;}
#define MAX_LISTEN_NUM 100

#endif
