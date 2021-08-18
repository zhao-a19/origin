
include ../../suos_vermake

#set build
CC = g++
C = gcc
CFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))

#project public files

LIBS += -lzlog
LIBS += -lmysqlclient_r
LIBS += -lz -ldl

#set env variable
VPATH+=../../
VPATH+=../../include/
VPATH+=../inc/
VPATH+=../lib_inc/
VPATH+=/usr/local/mysql/include/
VPATH+=/usr/local/ssl/include/

GLIB = ../../3rd-party/glib/
GLIBV8INC=$(GLIB)inc_v8/glib-2.0/
GLIBV8LIB=$(GLIB)lib_v8/

GLIBFTINC=$(GLIB)inc_v8/glib-2.0/
GLIBFTLIB=$(GLIB)lib_ft/

ifdef suosv8
	SUOSVERSION=-DSUOS_V=8
	LIBS +=$(wildcard $(GLIBV8LIB)*.a)
	VPATH += $(GLIBV8INC)
else ifdef suosv8.1
	SUOSVERSION=-DSUOS_V=81
	LIBS +=$(wildcard $(GLIBV8LIB)*.a)
	VPATH += $(GLIBV8INC)
	LIBS += -lcurl -L../lib_v8/
	LIBS += -lssh2 -L../lib_v8/
	LIBS += -lssl -L../lib_v8/
	LIBS += -lcrypto -L../lib_v8/
else ifdef suos_arm64_1043
	SUOSVERSION=-DSUOS_V=1000
	GLIB2INC+=/usr/include/glib-2.0/
	GLIB2INC+=/usr/include/glib-2.0/glib/
	GLIB2INC+=/usr/lib64/glib-2.0/include/
	VPATH+=$(GLIB2INC)
	LIBS += -lpthread -lglib-2.0
	LIBS += -lcurl -L../lib_arm64/
	LIBS += -lssh2 -L../lib_arm64/
	LIBS += -lssl -lcrypto
else ifdef suos_ft
	VPATH+=/usr/include/mysql/
	SUOSVERSION=-DSUOS_V=2000
	LIBS +=$(wildcard $(GLIBFTLIB)*.a)
	VPATH += $(GLIBFTINC)
	LIBS += -lpthread
	LIBS += -lcurl -L../lib_ft/
	LIBS += -lssh2 -L../lib_ft/
	LIBS += -lz -L../lib_ft/
	LIBS += -lssl
	LIBS += -lcrypto
	LIBS += -ldl
else ifdef suosv6

endif

PUBLIC=../../public/
FILESRC += $(PUBLIC)fileoperator.cpp
FILESRC += $(PUBLIC)filename.cpp
FILESRC += $(PUBLIC)syscfg.cpp
FILESRC += $(PUBLIC)stringex.cpp
VPATH+=$(PUBLIC)inc/

SOURCE = $(wildcard *.cpp)
SOURCE += ../../FCLogManage.cpp
SOURCE += ../../tbl_err_comm.cpp
SOURCE += ../../slog.cpp
SOURCE += $(FILESRC)
SOURCE += ../../common.cpp
OBJS = $(patsubst %.cpp,%.o,$(SOURCE))

all:msync
msync : $(OBJS)
	$(CC) -Wall $(CPPFLAGS) -g -rdynamic -o $@ $^ $(LIBS) $(SUOSVERSION)

.PHONY : clean
clean :
	-rm -f msync  $(OBJS) $(patsubst %.o,%.d,$(OBJS))
	-rm -f ./*.d.*
include $(SOURCE:.cpp=.d)

%.o:%.cpp
	$(CC) -Wall -O2 $(CPPFLAGS) -c $< -o $@	$(SUOSVERSION) -DSIDE=100


#get all dependencies
%.d:%.cpp
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$
