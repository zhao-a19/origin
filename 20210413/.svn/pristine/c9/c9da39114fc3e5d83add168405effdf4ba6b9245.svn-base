#set build
CC = g++
C = gcc
CFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))

#file size larger 2GB
include ../../osmake
include ../../suos_vermake

#project public files
COM = ../../public/
COMINC = ../../include/
COMINC += $(COM)inc/
COMLIB = $(COM)lib/
PRI = ../../ftp/
SQLITE = ./libsqlite/


TRANMYSQL = ../../lib/
#TRANSINC = ../../include/


LIBS += $(SQLITE)libsqlite.a
ifdef suosv8
	LIBS += -lzlog
	LIBS += -lmysqlclient_r -L/usr/local/mysql/lib
        OPT = -D UTC0
        SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
	LIBS += -lzlog
	LIBS += -lmysqlclient_r -L/usr/local/mysql/lib
        SUOSVERSION=-DSUOS_V=81
else ifdef suos_arm64_1043
	LIBS += -lzlog
	LIBS += -lmysqlclient_r -L/usr/local/mysql/lib
        SUOSVERSION=-DSUOS_V=1000
else ifdef suos_ft
	LIBS += -lzlog
	LIBS += -lmysqlclient_r
        SUOSVERSION=-DSUOS_V=2000
else ifdef suosv6
	LIBS += $(TRANMYSQL)libmyisammrg.a $(TRANMYSQL)libmysqlclient_r.a
	LIBS += $(TRANMYSQL)libzlog.a
        OPT = -D UTC0
        SUOSVERSION=-DSUOS_V=6
endif
LIBS += -pthread $(COMLIB)libsyssocket.a
LIBS += -lz -ldl

#set env variable
VPATH = $(COMINC): $(COMLIB): $(PRI)

ifdef suosv8
	VPATH += $(TRANSMYSQL):$(TRANSINC):$(SQLITE):../../:/usr/local/mysql/include/
else ifdef suosv8.1
	VPATH += $(TRANSMYSQL):$(TRANSINC):$(SQLITE):../../:/usr/local/mysql/include/
else ifdef suos_arm64_1043
	VPATH += $(TRANSMYSQL):$(TRANSINC):$(SQLITE):../../:/usr/local/mysql/include/
else ifdef suos_ft
	VPATH += $(TRANSMYSQL):$(TRANSINC):$(SQLITE):../../:/usr/include/mysql/
else ifdef suosv6
	VPATH += $(TRANSMYSQL):$(TRANSINC):$(SQLITE):../../:../../mysql
endif

PUBLIC=../../public/
FILESRC += $(PUBLIC)fileoperator.cpp
FILESRC += $(PUBLIC)filename.cpp
FILESRC += $(PUBLIC)syscfg.cpp
FILESRC += $(PUBLIC)stringex.cpp
VPATH+=$(PUBLIC)inc/

FILTER = $(COM)FCLogManage.cpp $(COM)fileoperator.cpp
SOURCE = $(wildcard *.cpp)  $(filter-out $(FILTER), $(wildcard $(COM)*.cpp))
SOURCE += $(PRI)priority.cpp
SOURCE += ../../FCLogManage.cpp
SOURCE += ../../tbl_err_comm.cpp
SOURCE += ../../slog.cpp
SOURCE += ../../common.cpp
SOURCE += $(FILESRC)
OBJS = $(patsubst %.cpp,%.o,$(SOURCE))


all : libsqlite.a fileclient fileclient_s
libsqlite.a : sqllite.o
	ar -crs ./libsqlite/libsqlite.a ./libsqlite/sqlite3.o
fileclient : $(OBJS)
	$(CC) -Wall $(CPPFLAGS) -g -rdynamic -o $@ $^ $(LIBS)
fileclient_s : $(OBJS)
	$(CC) -Wall $(CPPFLAGS) -g -rdynamic -o $@ $^ $(LIBS)

sqllite.o:
	gcc -c ./libsqlite/sqlite3.c -o ./libsqlite/sqlite3.o

.PHONY : clean
clean :
	-rm -f fileclient fileclient_s $(OBJS) $(patsubst %.o,%.d,$(OBJS))
	-rm -f ./libsqlite/libsqlite.a
	-rm -f ./libsqlite/sqlite3.o
include $(SOURCE:.cpp=.d)

%.o:%.cpp
	$(CC) -Wall -O2 $(CPPFLAGS) -c $< -o $@	$(OPT) $(SUOSVERSION) -DSIDE=100


#get all dependencies
%.d:%.cpp
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$
