
include ../suos_vermake

#set build
C++ = g++
C   = cc
RUN=${C++} -g -Wall -O2
CFLAGS += $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS += $(patsubst %,-I%,$(subst :, ,$(VPATH)))

#judge platform
ifdef suosv8
	LIBZLOG=-lzlog
else ifdef suosv8.1
	LIBZLOG=-lzlog
else ifdef suos_arm64_1043
	LIBZLOG=-lzlog
else ifdef suos_ft
	LIBZLOG=-lzlog
else ifdef suosv6
	LIBZLOG=../lib/libzlog.a
endif

#set env variable
VPATH+=../ ../include/

#get all files
HARDINFOSRC=hardinfo.cpp common.cpp FCDelSpace.cpp
FILTER_TOOL = ausvr.cpp au_api.cpp
SOURCE_TOOL = $(filter-out $(FILTER_TOOL), $(wildcard *.cpp)) $(HARDINFOSRC) FCMD5.cpp
OBJS_TOOL = $(patsubst %.cpp,%.o,$(SOURCE_TOOL))

FILTER_SVR = auth_tool.cpp au_api.cpp
SOURCE_SVR = $(filter-out $(FILTER_SVR), $(wildcard *.cpp)) $(HARDINFOSRC) FCMD5.cpp
OBJS_SVR = $(patsubst %.cpp,%.o,$(SOURCE_SVR))

SOURCE=$(SOURCE_TOOL) $(SOURCE_SVR)

#user model name
all: auth_tool ausvr
auth_tool:$(OBJS_TOOL)
	$(RUN) -o $@ $^ $(CPPFLAGS) $(LIBZLOG) -lpthread
ausvr:$(OBJS_SVR)
	$(RUN) -o $@ $^ $(CPPFLAGS) $(LIBZLOG) -lpthread

%.o:%.cpp
	$(RUN) -c $< -o $@ $(CPPFLAGS)

.PHONY : clean
clean:
	rm -rf auth_tool ausvr *.o *.d

include $(SOURCE:.cpp=.d)
#get all dependencies
%.d:%.cpp
	@set -e; rm -f $@; \
	$(C++) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

