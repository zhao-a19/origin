
include ../suos_vermake

C++ = g++
C   = cc
flag=-O2 -Wno-deprecated ${FLAG}
RUN=${C++} ${flag}
RUNLINK=${C++} ${flag}
ROOT=../
PUBLIC=$(ROOT)public/
VPATH+=$(PUBLIC)inc/

CFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))

ifdef suosv8
	LIBS=-lpthread -lmysqlclient_r -lz -L/usr/local/mysql/lib
	VPATH += ..:../include:/usr/local/mysql/include
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
	LIBS=-lpthread -lmysqlclient_r -lz -L/usr/local/mysql/lib
	VPATH += ..:../include:/usr/local/mysql/include
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=81
else ifdef suos_arm64_1043
	LIBS=-lpthread -lmysqlclient_r -lz -L/usr/local/mysql/lib
	VPATH += ..:../include:/usr/local/mysql/include
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=1000
else ifdef suos_ft
	LIBS=-lpthread -lmysqlclient_r -lz
	VPATH += ..:../include:/usr/include/mysql/
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=2000
else ifdef suosv6
	LIBS=-lpthread ../lib/libmysqlclient_r.a ../lib/libmyisammrg.a -lz
	VPATH += ..:../include:../mysql
	LIBZLOG=../lib/libzlog.a
	SUOSVERSION=-DSUOS_V=6
endif

SOURCE=$(wildcard *.cpp)
SOURCE+=../FCLogManage.cpp
SOURCE += $(PUBLIC)fileoperator.cpp
SOURCE += $(PUBLIC)filename.cpp
SOURCE += $(PUBLIC)syscfg.cpp
SOURCE += $(PUBLIC)stringex.cpp
SOURCE+=../tbl_err_comm.cpp
SOURCE+=../slog.cpp
SOURCE+=../common.cpp
OBJECTS = $(patsubst %.cpp,%.o,$(SOURCE))

all:autobak

autobak:$(OBJECTS)
	$(RUNLINK) -o $@ $^ $(LIBS) $(LIBZLOG) $(CPPFLAGS)

%.o:%.cpp
	$(RUN) -c $< -o $@ $(CPPFLAGS) $(SUOSVERSION)

clean:
	rm -f $(OBJECTS)
	rm -f autobak
