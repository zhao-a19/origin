
include ../suos_vermake

PUBLIC=../public/
SCANCFG=../diffcfg/
LIBS=../lib/
INCLUDE=-I.. -I../include/ -I$(PUBLIC)inc/ -I$(SCANCFG) 

FILESRC += $(PUBLIC)fileoperator.cpp
FILESRC += $(PUBLIC)filename.cpp
FILESRC += $(PUBLIC)syscfg.cpp
FILESRC += $(PUBLIC)stringex.cpp

INITSRC=init_in.c $(FILESRC) ../FCKey.cpp ../hardinfo.cpp ../common.cpp ../FCDelSpace.cpp ../FCMD5.cpp

ifdef suosv8
	SUOSVERSION=-DSUOS_V=8
	ZLOGLIB=-lzlog
else ifdef suosv8.1
	SUOSVERSION=-DSUOS_V=81
	ZLOGLIB=-lzlog
else ifdef suos_arm64_1043
	SUOSVERSION=-DSUOS_V=1000
	ZLOGLIB=-lzlog
else ifdef suos_ft
	SUOSVERSION=-DSUOS_V=2000
	ZLOGLIB=-lzlog -lpthread
else ifdef suosv6
	SUOSVERSION=-DSUOS_V=6
	ZLOGLIB=$(LIBS)libzlog.a -lpthread
endif

all:start startall stop restart initsys init_in version_sync

start:
	g++ start.c  $(ZLOGLIB) -o $@ $(INCLUDE) $(SUOSVERSION) ${FLAG}
startall:
	g++ startall.c $(FILESRC) $(ZLOGLIB) -o $@ $(INCLUDE) $(SUOSVERSION)
stop:
	g++ stop.c  -o $@ $(INCLUDE)
restart:
	g++ restart.c  -o $@
initsys:
	g++ initsys.c  -o $@
init_in:
	g++ $(INITSRC) $(ZLOGLIB) -lpthread -o $@ $(INCLUDE) $(SUOSVERSION)
version_sync:
	g++ version_sync.c $(FILESRC) $(ZLOGLIB) -o $@ $(INCLUDE) $(SUOSVERSION)
clean:
	rm -rf ./start
	rm -rf ./startall
	rm -rf ./stop
	rm -rf ./restart
	rm -rf ./startvir
	rm -rf ./initsys
	rm -rf ./init_in
	rm -rf ./version_sync
