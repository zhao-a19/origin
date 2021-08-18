
include ../suos_vermake

#set build
C++ = g++
C   = cc
RUN=${C++} -g -Wall -O2 -DSIDE=100 $(SUOSVERSION)
CFLAGS += $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS += $(patsubst %,-I%,$(subst :, ,$(VPATH)))
LIBS = -lpthread

#judge platform
ifdef suosv8
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=81
else ifdef suos_arm64_1043
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=1000
else ifdef suos_ft
	LIBZLOG=-lzlog -lpthread
	SUOSVERSION=-DSUOS_V=2000
else ifdef suosv6
	LIBZLOG=../lib/libzlog.a
	SUOSVERSION=-DSUOS_V=6 -lpthread
endif

#set env variable
VPATH+=../ ../include/ ../auth/

PUBLIC=../public/
FILESRC += $(PUBLIC)fileoperator.cpp
FILESRC += $(PUBLIC)filename.cpp
FILESRC += $(PUBLIC)syscfg.cpp
FILESRC += $(PUBLIC)stringex.cpp
FILESRC += $(PUBLIC)crc.cpp
VPATH+=$(PUBLIC)inc/

#get all files
FILTER_TOOL = update.cpp
SOURCE_TOOL = $(filter-out $(FILTER_TOOL), $(wildcard *.cpp)) $(FILESRC) FCMD5.cpp
OBJS_TOOL = $(patsubst %.cpp,%.o,$(SOURCE_TOOL))

FILTER_UPDATE = update_marktool.cpp
SOURCE_UPDATE = $(filter-out $(FILTER_UPDATE), $(wildcard *.cpp)) $(FILESRC) FCMD5.cpp \
 FCPeerExecuteCMD.cpp FCMsgAck.cpp FCSendFileUdp.cpp common.cpp FCLicenseMod.cpp sendfiletcp.cpp common.cpp
OBJS_UPDATE = $(patsubst %.cpp,%.o,$(SOURCE_UPDATE))

SOURCE=$(SOURCE_TOOL) $(SOURCE_UPDATE)

#user model name
all: update update_marktool

update_marktool:$(OBJS_TOOL)
	$(RUN) -o $@ $^ $(CPPFLAGS) $(LIBZLOG)
update:$(OBJS_UPDATE)
	echo $(OBJS_UPDATE)
	$(RUN) -o $@ $^ $(CPPFLAGS) $(LIBZLOG) $(LIBS)

%.o:%.cpp
	$(RUN) -c $< -o $@ $(CPPFLAGS)

.PHONY : clean
clean:
	rm -rf update update_marktool *.o *.d *.d.*
	rm -rf ../*.o ../*.d ../*.d.*

include $(SOURCE:.cpp=.d)
#get all dependencies
%.d:%.cpp
	@set -e; rm -f $@; \
	$(C++) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$
