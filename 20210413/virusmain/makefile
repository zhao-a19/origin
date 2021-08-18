
include ../suos_vermake

COMINC =../include/
VIRUS = ../3rd-party/virus/
PUBLIC =../public/
INC = $(PUBLIC)inc/
COMAV = $(PUBLIC)antivirus/
VIRUSINC = $(VIRUS)inc/
VIRUSLIB = $(VIRUS)lib/
JMINCX86 = $(VIRUSINC)jmav_x86/
JMLIBX86 = $(VIRUSLIB)jmav_x86/
JMINCARM = $(VIRUSINC)jmav_arm/
JMLIBARM = $(VIRUSLIB)jmav_arm/


INCLUDE+=-I$(VIRUSINC) -I$(COMINC) -I/usr/local/ssl/include/ -I$(COMAV) -I$(INC)
INCLUDE+= $(PUBLIC)fileoperator.cpp $(PUBLIC)syscfg.cpp $(PUBLIC)stringex.cpp $(PUBLIC)filename.cpp
INCLUDE+= $(COMAV)Crisingav.cpp $(COMAV)Cclamav.cpp
# INCLUDE+= $(COMAV)Cjmav.cpp
LIBS+=-ldl -lclamav -Wl,-rpath,/initrd/abin/ -lpthread -L/lib64/
LIBS+=-lmysqlclient -L $(VIRUSLIB) 
# LIBS+=-L $(JMLIBX86) -lavemgr -laveng
LIBZLOG+=-lzlog 

ifdef suosv8
	FLAG=
	INCLUDE+=-I/usr/local/clamav/include/ 
	INCLUDE+= -I$(JMINCX86)
	SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
	FLAG=
	INCLUDE+= -I/usr/local/clamav/include/ 
	INCLUDE+= -I$(JMINCX86)
	SUOSVERSION=-DSUOS_V=81
else ifdef suos_arm64_1043
	FLAG=
	INCLUDE+=-I/usr/local/clamav/include/ 
	INCLUDE+= -I$(JMINCARM)
	SUOSVERSION=-DSUOS_V=1000
else ifdef suos_ft
	FLAG=
	INCLUDE+=-I/usr/include/
	INCLUDE+= -I$(JMINCARM)
	SUOSVERSION=-DSUOS_V=2000
else ifdef suosv6
	FLAG=-lbz2 -L./libv6/
	SUOSVERSION=-DSUOS_V=6
endif

all:virusmain startvir

virusmain:
	g++ -g -Wno-deprecated -Wno-write-strings virusmain.c -o virusmain -lrt -lz -DUINT64_MAX -Wno-attributes $(FLAG) $(INCLUDE) $(LIBS) $(SUOSVERSION) $(LIBZLOG)

startvir:
	g++ startvir.c -o startvir $(SUOSVERSION)
clean:
	rm -r --force *.o virusmain startvir
