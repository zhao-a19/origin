/*******************************************************************************************
*文件:    syssocketex.cpp
*描述:    优化消息队列处理，分离部分函数&重写
*
*作者:    张冬波
*日期:    2016-12-26
*修改:    创建文件                            ------>     2016-12-26
*         可以设置线程名称                    ------>     2021-02-23
*
*******************************************************************************************/
#include "syssocket.h"
#include "debugout.h"
#include <errno.h>
#include "msgcfg.h"

#ifdef _MSG_ONE_

//数据堆最少MB
#if 0
static const uint16 HEAPMAX = 10000;
#define _freemsg(d,...) {}
#else
#define _freemsg(d,...) if((d)!=NULL) {free(d); d=NULL;}
#endif

/*******************************************************************************************
*功能:    启动缓冲数据处理
*参数:
*
*注释:    减少数据之间的重复拷贝，确保接收数据只有一份；
*
*******************************************************************************************/
void *_queuefunc_(void *arg)
{
    pthread_setself("queuefuncex");
    CSUSOCKET *self = (CSUSOCKET *)arg;
    SUQUEUE packet;
    int msgid;
    puint8 g_msgheap = NULL;
    uint16 msgidx = 0;

    self->m_keyqueue = (key_t)pthread_self();

    //防止内核版本差异导致的线程重复问题
_retry:
    //msgctl(msgget(self->m_keyqueue, 0660), IPC_RMID, NULL);
    msgid = msgget(self->m_keyqueue, IPC_CREAT | 0660 | IPC_EXCL);
    if (msgid == -1) {
        PRINT_ERR_HEAD;
        print_err("start queue task, queue = 0x%x failed", self->m_keyqueue);
        //return NULL;
        //usleep(1);
        self->m_keyqueue += (key_t)self->getsocket();
        goto _retry;
    }

    PRINT_INFO_HEAD;
    print_info("start queue task, queue = 0x%x", self->m_keyqueue);

    self->m_threadflag = 1;
    while (self->m_threadflag) {
        int32 i;

        //分配数据堆空间
#if 0
        if (g_msgheap == NULL) {
            if ((g_msgheap = (puint8)malloc(HEAPMAX * _UNI_PACKETSIZE)) == NULL) {
                PRINT_ERR_HEAD;
                print_err("task(%ld) queue = 0x%x no memory", pthread_self(), self->m_keyqueue);
                while (1) usleep(1);
            }
        }
        puint8 mdata = g_msgheap + (msgidx * _UNI_PACKETSIZE);
        if (++msgidx >= HEAPMAX) msgidx = 0;
#else
        puint8 mdata = (puint8)malloc(_UNI_PACKETSIZE);
        if (mdata == NULL) {
            PRINT_ERR_HEAD;
            print_err("task(%ld) queue = 0x%x no memory", pthread_self(), self->m_keyqueue);
            while (1) usleep(1);
        }
#endif

        PRINT_DBG_HEAD;
        print_dbg("task(%ld) queue = 0x%x memory at 0x%p", pthread_self(), self->m_keyqueue, mdata);

        if ((i = self->readsocket(mdata, _UNI_PACKETSIZE)) > 0) {
            if ((packet.mtype = (long)suisvalid(*self, mdata, i)) == 0) continue;

            //仅发送空间地址+数据长度
            memcpy(packet.mdata, &mdata, sizeof(mdata));
            memcpy(packet.mdata + sizeof(mdata), &i, sizeof(int32));

            PRINT_DBG_HEAD;
            print_dbg("task(%ld) queue = 0x%x memory at 0x%p(%d)", pthread_self(), self->m_keyqueue, mdata, i);

            if (msgsnd(msgid, &packet, sizeof(packet.mdata), 0) != 0) {       //阻塞方式
                PRINT_ERR_HEAD;
                print_err("task(%ld) queue = 0x%x errno = %d write failed!",
                          pthread_self(), self->m_keyqueue, errno);
                break;
            }
        } else {
            PRINT_ERR_HEAD;
            print_err("task(%ld) queue = 0x%x errno = %d socket failed!",
                      pthread_self(), self->m_keyqueue, errno);
        }

    }

    PRINT_INFO_HEAD;
    print_info("end queue task");

    PRINT_ERR_HEAD;
    print_err("end queue task");

    //外部同步检查
    self->m_threadflag = -1;
    return NULL;
}

/*******************************************************************************************
*功能:    接收数据
*参数:    data                  ---->    数据地址
*         size                  ---->    数据长度
*         返回值                ---->    实际接收量, -1 失败
*
*注释:    超时机制
*
*******************************************************************************************/
#define _breakout(d) {readsize = -1; _freemsg(d); break;}
int32 CSUSOCKET::sureadq(void *data, int32 size)
{
    if (m_keyqueue == 0) return -1;

    SUQUEUE packet;
    int msgid = msgget(m_keyqueue, 0660);
    if (msgid == -1) {
        PRINT_ERR_HEAD;
        print_err("read queue = 0x%x failed", m_keyqueue);
        return -1;
    }

    PRINT_DBG_HEAD;
    print_dbg("read queue = 0x%x, uniq = %lu", m_keyqueue, m_rdUNIQ);

    int32 readsize = -1;
    int32 packetcnt = 0, idxcnt = -1;
    uint16 badpacket = 0;
    int32 random = 0;
    UNI_PACKET s_packet;

    do {
        int32 len;
        puint8 mdata = NULL;

#if SUQCACHE
        len = _queuecache(msgid, (void *)&packet, sizeof(packet.mdata));
#else
        len = msgrcv(msgid, &packet, sizeof(packet.mdata), m_rdUNIQ, 0/*IPC_NOWAIT | IPC_EXCEPT*/);
#endif
        if (len == -1) {

            if (errno == ENOMSG ) {
                //超时处理
                //usleep(1);

            } else {
                PRINT_ERR_HEAD;
                print_err("read queue = 0x%x failed, errno = %d", m_keyqueue, errno);
                readsize = -1;
                break;
            }

        } else if (len == 0) {
            PRINT_DBG_HEAD;
            print_dbg("read queue = 0x%x data empty", m_keyqueue);
            continue;
        } else {
            _uniqinc((uint32 &)m_rdUNIQ);

            if (len != sizeof(packet.mdata)) {
                PRINT_ERR_HEAD;
                print_err("read queue = 0x%x failed, %d != %d", m_keyqueue, sizeof(packet.mdata), len);
                continue;
            }

            memcpy(&mdata, packet.mdata, sizeof(mdata));
            memcpy(&len, packet.mdata + sizeof(mdata), sizeof(int32));
            PRINT_DBG_HEAD;
            print_dbg("read queue = 0x%x memory at 0x%p(%d)", m_keyqueue, mdata, len);

            if (checkmd5_packet1(mdata, len, &s_packet)) {

                int32 i;
                int32 tmpidx = _getint(s_packet.idx);

                //起始包
                if (packetcnt == 0) {
                    if (tmpidx != 0) {
                        PRINT_ERR_HEAD;
                        print_err("read queue = 0x%x maybe disordered0(%u)", m_keyqueue, 0);
                        _breakout(mdata);
                    }
                    readsize = 0;
                    idxcnt = 0;
                    packetcnt = _getint(s_packet.total);
                    random = _getint(&(s_packet.payload.randomkey), sizeof(s_packet.payload.randomkey));
                }

                if (packetcnt != _getint(s_packet.total)) {
                    PRINT_ERR_HEAD;
                    print_err("read queue = 0x%x maybe disordered1(%u)", m_keyqueue, packetcnt);
                    _breakout(mdata);
                }

                if (random != _getint(&(s_packet.payload.randomkey), sizeof(s_packet.payload.randomkey))) {
                    PRINT_ERR_HEAD;
                    print_err("read queue = 0x%x maybe disordered2(%u)", m_keyqueue, random);
                    _breakout(mdata);
                }

                idxcnt++;

                i = s_packet.length - sizeof(s_packet.payload);
                if ((tmpidx * (int32)(_UNI_PACKETSIZE - sizeof(s_packet)) + i) > size) {
                    i = size - (tmpidx * (_UNI_PACKETSIZE - sizeof(s_packet)));
                    PRINT_ERR_HEAD;
                    print_err("read overflow packet idx = %d, length = %d, valid = %d",
                              tmpidx, s_packet.length, i);
                    if (i <= 0) {
                        PRINT_ERR_HEAD;
                        print_err("bad packet = %d", ++badpacket);
                        //if (badpacket <= 10) continue;
                        _breakout(mdata);
                    }
                }

                memcpy((puint8)data + tmpidx * (_UNI_PACKETSIZE - sizeof(s_packet)),
                       (void *)_OFFSET_DATA(mdata), i);
                readsize += i;
            } else {
                PRINT_ERR_HEAD;
                print_err("bad packet = %d", ++badpacket);
                //if (badpacket <= 10) continue;
                _breakout(mdata);
            }

        }

        //释放数据堆空间
        _freemsg(mdata);

    } while ((idxcnt < packetcnt) && (readsize < size));

    PRINT_DBG_HEAD;
    print_dbg("read data %d = %d", size, readsize);
    return readsize;
}

/*******************************************************************************************
*功能:    结束缓冲数据处理
*参数:
*
*注释:    可在在suend后调用，确保正常安全退出
*
*******************************************************************************************/
void CSUSOCKET::suendq(void)
{
    if (m_keyqueue != 0) {
        while (m_threadflag != -1) {
            usleep(1000);
        }

        PRINT_DBG_HEAD;
        print_dbg("delete queue 0x%x", m_keyqueue);
        if (msgctl(msgget(m_keyqueue, 0660), IPC_RMID, NULL) == -1) {
            PRINT_ERR_HEAD;
            print_err("delete queue 0x%x failed:%s", m_keyqueue, strerror(errno));
        }
        m_keyqueue = 0;
    }

#if SUQCACHE
    while (m_queuecache.cnt) {
        for (uint32 i = 0; i < SUQCACHE_L; i++) {
            if (m_queuecache.packet[i] != NULL) {
                //释放数据堆空间
                int32 len;
                SUQUEUE packet;
                memcpy(&len, m_queuecache.packet[i], sizeof(len));
                memcpy(&packet, (puint8)(m_queuecache.packet[i]) + sizeof(len), sizeof(packet));
                if (len == sizeof(packet.mdata)) {
                    puint8 mdata = NULL;
                    memcpy(&mdata, packet.mdata, sizeof(mdata));
                    memcpy(&len, packet.mdata + sizeof(mdata), sizeof(int32));

                    PRINT_DBG_HEAD;
                    print_dbg("delete queue 0x%x memory at 0x%p(%d)", m_keyqueue, mdata, len);
                    _freemsg(mdata);

                } else {
                    PRINT_ERR_HEAD;
                    print_err("delete queue 0x%x failed, %d != %d", m_keyqueue, sizeof(packet), len);
                }

                free(m_queuecache.packet[i]);
                m_queuecache.packet[i] = NULL;
            }
        }
        m_queuecache.cnt = 0;
    }
#endif

}

#endif
