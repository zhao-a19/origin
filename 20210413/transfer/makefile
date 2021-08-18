
include ../suos_vermake

CFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))

C++ = g++
RUN=${C++}
RUNLINK=${C++} -lrt -lpthread
GLIB = ../3rd-party/glib/
GLIBV6INC=$(GLIB)inc_v6/glib-2.0/
GLIBV6LIB=$(GLIB)lib_v6/

GLIBV8INC=$(GLIB)inc_v8/glib-2.0/
GLIBV8LIB=$(GLIB)lib_v8/

GLIBFTINC=$(GLIB)inc_v8/glib-2.0/
GLIBFTLIB=$(GLIB)lib_ft/

ifdef suosv8
	LIBS +=$(wildcard $(GLIBV8LIB)*.a)
	VPATH += $(GLIBV8INC):../include/
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
	LIBS +=$(wildcard $(GLIBV8LIB)*.a)
	VPATH += $(GLIBV8INC):../include/
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=81
else ifdef suos_arm64_1043
	LIBS += -lgthread-2.0 -lglib-2.0
	VPATH += ../include/
	VPATH +=/usr/include/glib-2.0/
	VPATH +=/usr/lib64/glib-2.0/include/
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=1000
else ifdef suos_ft
	LIBS += $(wildcard $(GLIBFTLIB)*.a)
	VPATH += $(GLIBFTINC):../include/
	LIBZLOG=-lzlog -lpthread
	SUOSVERSION=-DSUOS_V=2000
else ifdef suosv6
	LIBS +=$(wildcard $(GLIBV6LIB)*.a)
	VPATH += $(GLIBV6INC):../include/
	LIBZLOG=../lib/libzlog.a -lpthread
	SUOSVERSION=-DSUOS_V=6
endif

SOURCE=$(wildcard *.cpp)
OBJECTS=$(patsubst %.cpp,%.o,$(SOURCE))

all:transfer

transfer:$(OBJECTS)
	$(RUNLINK) -o $@ $^ $(LIBS) $(LIBZLOG) 

.PHONY : clean
clean:
	rm -f *.o transfer

%.o:%.cpp
	$(RUN) -c $< -o $@ $(CPPFLAGS) $(SUOSVERSION)

