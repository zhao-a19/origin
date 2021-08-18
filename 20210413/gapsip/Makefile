
#set build
CC = g++
C = gcc
CFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))

include ../suos_vermake

MAIN=../
#project public files
COM = ../public/
COMINC = $(COM)inc/
COMLIB = $(COM)lib/
SOCKET=$(COM)socket/
MYSQL = ../
MYSQLINC = $(MYSQL)mysql/
MYSQLLIB = $(MYSQL)lib/
ZLOG = ../
ZLOGINC = $(ZLOG)include/
ZLOGLIB = $(ZLOG)lib/
APPS = ../
GLIB = ../3rd-party/glib/
GLIBV6INC=$(GLIB)inc_v6/glib-2.0/
GLIBV6LIB=$(GLIB)lib_v6/

GLIBV8INC=$(GLIB)inc_v8/glib-2.0/
GLIBV8LIB=$(GLIB)lib_v8/

GLIBFTINC=$(GLIB)inc_v8/glib-2.0/
GLIBFTLIB=$(GLIB)lib_ft/

VPATH = $(MAIN) : $(COMINC): $(COMLIB): $(ZLOGINC) : $(APPS)

ifdef suosv8
	VPATH += /usr/local/mysql/include :$(GLIBV8INC)
	LIBS +=$(wildcard $(GLIBV8LIB)*.a)
	LIBS +=-lpthread -lmysqlclient_r -L/usr/local/mysql/lib -lzlog
	SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
	VPATH += /usr/local/mysql/include :$(GLIBV8INC)
	LIBS +=$(wildcard $(GLIBV8LIB)*.a)
	LIBS +=-lpthread -lmysqlclient_r -L/usr/local/mysql/lib -lzlog
	SUOSVERSION=-DSUOS_V=81
else ifdef suos_arm64_1043
	VPATH +=/usr/local/mysql/include
	VPATH +=/usr/include/glib-2.0/
	VPATH +=/usr/include/glib-2.0/glib/
	VPATH +=/usr/lib64/glib-2.0/include/
	LIBS +=-lpthread -lmysqlclient_r -L/usr/local/mysql/lib -lzlog -lgthread-2.0 -lglib-2.0
	SUOSVERSION=-DSUOS_V=1000
else ifdef suos_ft
	VPATH +=/usr/include/mysql/:$(GLIBFTINC)
	LIBS +=$(wildcard $(GLIBFTLIB)*.a)
	LIBS +=-lpthread -lmysqlclient_r -lzlog
	SUOSVERSION=-DSUOS_V=2000
else ifdef suosv6
	VPATH += $(MYSQLINC): $(MYSQLLIB) :$(GLIBV6INC)
	LIBS +=$(wildcard $(GLIBV6LIB)*.a)
	LIBS +=-lpthread -lz $(MYSQLLIB)libmyisammrg.a $(MYSQLLIB)libmysqlclient_r.a $(ZLOGLIB)libzlog.a
	SUOSVERSION=-DSUOS_V=6
endif

#get all files
SOURCE = $(wildcard *.cpp) $(filter-out $(COM)fileoperator.cpp,$(wildcard $(COM)*.cpp)) $(wildcard $(SOCKET)*.cpp)
SOURCE += $(APPS)FCPeerExecuteCMD.cpp
SOURCE += $(APPS)FCLogManage.cpp
SOURCE += $(APPS)tbl_err_comm.cpp
SOURCE += $(APPS)slog.cpp
SOURCE += $(APPS)common.cpp
SOURCE += $(APPS)fileoperator.cpp
SOURCE += $(APPS)FCMsgAck.cpp
OBJS = $(patsubst %.cpp,%.o,$(SOURCE))

all : gapsip
gapsip : $(OBJS)
	echo $(OBJS)
	$(CC) -Wall $(CPPFLAGS) -g -rdynamic -o $@ $^ $(LIBS)

.PHONY : clean
clean :
	-rm -f gapsip *.o *.d $(COM)*.o $(COM)*.d

include $(SOURCE:.cpp=.d)

%.o:%.cpp
	$(CC) -Wall -O2 $(CPPFLAGS) $(FLAG) -c $< -o $@ $(SUOSVERSION)

#get all dependencies
%.d:%.cpp
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

