
include ../suos_vermake

LIBS=../lib/
INCLUDE=-I.. -I ../include/
PUBLIC=../public/
FILESRC += $(PUBLIC)fileoperator.cpp
FILESRC += $(PUBLIC)filename.cpp
FILESRC += $(PUBLIC)syscfg.cpp
FILESRC += $(PUBLIC)stringex.cpp
INCLUDE+=-I$(PUBLIC)inc/

INITSRC=init_out.c $(FILESRC) ../FCKey.cpp ../hardinfo.cpp ../common.cpp ../FCDelSpace.cpp ../FCMD5.cpp
MONITORSRC=monitor.c ../fileoperator.cpp

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

all: init_out

init_out:
	g++ $(INITSRC) $(ZLOGLIB) -lpthread -o init_out $(INCLUDE) $(SUOSVERSION)
monitor:
	g++ $(MONITORSRC) $(ZLOGLIB) -o monitor $(INCLUDE) $(SUOSVERSION)
clean:
	rm -rf ./init_out
	rm -rf ./monitor
