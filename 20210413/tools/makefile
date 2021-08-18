
include ../suos_vermake

SYSDATA=../sysdata/
PUBLIC=../public/
FILESRC += $(PUBLIC)fileoperator.cpp
FILESRC += $(PUBLIC)filename.cpp
FILESRC += $(PUBLIC)syscfg.cpp
FILESRC += $(PUBLIC)stringex.cpp

INCLUDE=-I.. -I../include/ -I$(SYSDATA) -I$(PUBLIC)inc/
HARDINFOSRC=../hardinfo.cpp ../common.cpp ../FCDelSpace.cpp
SENDFILESRC=../FCSendFileUdp.cpp ../FCMsgAck.cpp ../FCMD5.cpp ../sendfiletcp.cpp ../common.cpp
LOGMANAGESRC=../FCLogManage.cpp ../tbl_err_comm.cpp ../slog.cpp ../common.cpp $(FILESRC)

ifdef suosv8
	LIBS=-lmysqlclient_r -L/usr/local/mysql/lib/
	INCLUDE+= -I/usr/local/mysql/include/
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
	LIBS=-lmysqlclient_r -L/usr/local/mysql/lib/
	INCLUDE+= -I/usr/local/mysql/include/
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=81
else ifdef suosv6
	LIBS=../lib/libmyisammrg.a ../lib/libmysqlclient_r.a -lrt -lz -lpthread
	INCLUDE+=-I../mysql/
	LIBZLOG=../lib/libzlog.a -lpthread
	SUOSVERSION=-DSUOS_V=6
else ifdef suos_arm64_1043
	LIBS=-lmysqlclient_r -L/usr/local/mysql/lib/
	INCLUDE+= -I/usr/local/mysql/include/
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=1000
else ifdef suos_ft
	LIBS=-lmysqlclient_r
	INCLUDE+= -I/usr/include/mysql/
	LIBZLOG=-lzlog -lpthread
	SUOSVERSION=-DSUOS_V=2000
endif


all:createdb checkfilevir sendsig cmdproxy tcpsock getfile ntpclient update_marktool mysqltest \
	clitool callclitool dbspeed mallocspeed clean_track putfile localip syslog_tool checkmac callwd enfile \
	log_mv

createdb:
	g++ createdb.cpp $(LOGMANAGESRC) -o $@ $(INCLUDE) $(SUOSVERSION) $(LIBS) $(LIBZLOG) $(FLAG)
sendsig:
	g++ sendsig.cpp $(FILESRC) ../FCMsgAck.cpp ../FCTimeToPeer.cpp -o $@ $(LIBZLOG) $(INCLUDE) $(SUOSVERSION) $(FLAG) -lpthread
checkfilevir:
	g++ checkfilevir.c ../FCVirusAPI.cpp -o $@ -I../include -I.. $(LIBZLOG) -lpthread -lz
cmdproxy:
	g++ cmdproxy.cpp $(FILESRC) ../FCMsgAck.cpp $(LIBZLOG) -lrt -o $@ $(INCLUDE) $(SUOSVERSION)
tcpsock:
	g++ tcpsock.cpp ../FCBSTX.cpp -I../ -I../include/ -I../public/inc/ -o $@ $(LIBZLOG) $(FLAG)
getfile:
	g++ getfile.cpp $(FILESRC) ../FCMsgAck.cpp $(LIBZLOG) -lrt -o $@ $(INCLUDE) $(SUOSVERSION)
ntpclient:
	gcc ntpclient.c -lrt -o $@ -std=c89 -W -Wall -O2
update:
	g++ update.cpp $(FILESRC) $(SENDFILESRC) ../FCPeerExecuteCMD.cpp $ ../FCLicenseMod.cpp \
	../common.cpp $(LIBZLOG) -lrt -o $@ $(INCLUDE) $(SUOSVERSION) $(FLAG)
update_marktool:
	g++ update_marktool.cpp -o $@
mysqltest:
	g++ mysqltest.cpp $(LOGMANAGESRC) -lpthread -lrt -lz $(INCLUDE) $(SUOSVERSION) $(LIBS) $(LIBZLOG) $(FLAG) -o $@
clitool:
	g++ clitool.cpp $(HARDINFOSRC) ../FCKey.cpp ../FCMD5.cpp $(FILESRC) $(LIBZLOG) -lpthread -o $@ $(INCLUDE) $(SUOSVERSION)
callclitool:
	g++ callclitool.cpp $(HARDINFOSRC) ../FCKey.cpp ../FCMD5.cpp $(FILESRC) $(LIBZLOG) -lpthread -o $@ $(INCLUDE) $(SUOSVERSION)
dbspeed:
	g++ dbspeed.cpp $(LOGMANAGESRC) -lpthread -lrt -lz $(INCLUDE) $(SUOSVERSION) $(LIBS) $(LIBZLOG) $(FLAG) -o $@
mallocspeed:
	g++ mallocspeed.cpp -o $@ -lrt -lpthread
clean_track:
	g++ clean_track.cpp -o $@
putfile:
	g++ putfile.cpp $(FILESRC) $(SENDFILESRC) $(LIBZLOG) -lrt -o $@ $(INCLUDE) $(SUOSVERSION) $(FLAG)
localip:
	g++ localip.cpp ../localip_api.cpp $(FILESRC) $(INCLUDE) -o localip $(SUOSVERSION) $(LIBZLOG) $(FLAG)
syslog_tool:
	g++ syslog_tool.cpp $(FILESRC) $(INCLUDE) -o syslog_tool $(SUOSVERSION) $(LIBZLOG) $(FLAG)
checkmac:
	g++ checkmac.cpp $(HARDINFOSRC) $(FILESRC) $(INCLUDE) -o checkmac $(SUOSVERSION) $(LIBZLOG)
callwd:
	g++ callwd.cpp ../common.cpp $(INCLUDE) -o callwd $(SUOSVERSION) $(LIBZLOG)
enfile:
	g++ ../FCMD5.cpp enfile.cpp $(INCLUDE) -o enfile $(SUOSVERSION) $(LIBZLOG)
log_mv:
	g++ log_mv.cpp $(PUBLIC)stringex.cpp -lrt -lz $(INCLUDE) $(SUOSVERSION) $(LIBS) $(LIBZLOG) $(FLAG) -o $@

clean:
	rm -rf createdb sendsig checkfilevir cmdproxy tcpsock getfile ntpclient update update_marktool
	rm -rf mysqltest clitool callclitool dbspeed mallocspeed clean_track putfile localip syslog_tool
	rm -rf checkmac callwd enfile log_mv


