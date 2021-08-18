#make FLAG=-DSIDE=100   //innet
#make FLAG=-DSIDE=200   //outnet

include ./suos_vermake

C++ = g++
C   = cc
FLAGX= -g -Wall -O2 ${FLAG}
SIP_FLAG=-DRESEAL_SIP
FLAGX+=${SIP_FLAG}
RUN=${C++} ${FLAGX}
RUNLINK=${C++} ${FLAGX} -lrt -lz

CFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))

ROOT=./
LIBS=$(ROOT)lib/
LIBSV8=$(ROOT)libv8/
LIBSARM64_1043=$(ROOT)libarm64_1043/
LIBS_FT=$(ROOT)lib_ft/
COMINC=$(ROOT)include/
HOTBAK=$(ROOT)hotbak/
RECVMAIN=$(ROOT)recv_main/
AUTH=$(ROOT)auth/
SYSDATA=$(ROOT)sysdata/
PUBLIC=$(ROOT)public/
SCANCFG=$(ROOT)diffcfg/
IPQNETLINK=$(SYSDATA)ipq_netlink/
NFQNETLINK=$(SYSDATA)nfq_netlink/
RULES=$(SYSDATA)rules/
SUBFUNC=$(SYSDATA)subfunc/
SYSMODS=$(SYSDATA)mods/
SYSLOG=$(SYSDATA)syslog/
PUBLICINC=$(PUBLIC)inc/
WISINC=$(ROOT)3rd-party/opensource/wireshark-2.0.2/
WISEPINC=$(ROOT)wireshark_epan_print/
GLIBV6INC=$(ROOT)3rd-party/glib/inc_v6/
GLIBV8INC=$(ROOT)3rd-party/glib/inc_v8/
#GLIBFTLIB=$(ROOT)3rd-party/glib/lib_ft/

SIP=$(SYSMODS)sip/
PDT=$(SYSMODS)pdt/
RFC3261=$(SYSMODS)rfc3261/
SIP_INTERCONT=$(SYSMODS)sip_interconnect/
MULTICAST=$(SYSMODS)multicast/
DBSYNC=$(SYSMODS)dbsync/
FILESYNC=$(SYSMODS)filesync/
COMMODS=$(SYSMODS)com_mods/
USERMODS=$(SYSMODS)user_mods/
INDUSTRY=$(SYSMODS)industry/
DATABASE=$(SYSMODS)database/

MMSINC+=$(INDUSTRY)libiec61850/src/mms/inc_private/
MMSINC+=$(INDUSTRY)libiec61850/src/mms/inc/
MMSINC+=$(INDUSTRY)libiec61850/src/mms/iso_mms/asn1c/
MMSINC+=$(INDUSTRY)libiec61850/src/common/inc/
MMSINC+=$(INDUSTRY)libiec61850/src/hal/inc/
MMSINC+=$(INDUSTRY)libiec61850/config/
OPCINC=$(INDUSTRY)suricata/
PCREINC=$(COMINC)pcre/inc/
ZLOGINC=$(COMINC)

ifdef suosv8
	ZLOGLIB=-lzlog
	MYSQLLIB=-lmysqlclient_r -L/usr/local/mysql/lib
	MYSQLINC=/usr/local/mysql/include
	LIBSURICATA=$(LIBSV8)libsuricata.a
	LIBIEC61850=$(LIBSV8)libiec61850.a
	GLIB2INC=$(GLIBV8INC)glib-2.0/
	GLIB2HINC=$(GLIBV8INC)glib-2.0/glib/
	LIBWIS=$(WISEPINC)libwireshark_epan_print.a
	LIBWIRE=-lwireshark -L$(WISEPINC)lib
	LIBWSUTIL=-lwsutil -L$(WISEPINC)lib
	LIBWIRETAP=-lwiretap -L$(WISEPINC)lib
	SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
	ZLOGLIB=-lzlog
	MYSQLLIB=-lmysqlclient_r -L/usr/local/mysql/lib
	MYSQLINC=/usr/local/mysql/include
	LIBSURICATA=$(LIBSV8)libsuricata.a
	LIBIEC61850=$(LIBSV8)libiec61850.a
	GLIB2INC=$(GLIBV8INC)glib-2.0/
	GLIB2HINC=$(GLIBV8INC)glib-2.0/glib/
	LIBWIS=$(WISEPINC)libwireshark_epan_print.a
	LIBWIRE=-lwireshark -L$(WISEPINC)lib
	LIBWSUTIL=-lwsutil -L$(WISEPINC)lib
	LIBWIRETAP=-lwiretap -L$(WISEPINC)lib
	SUOSVERSION=-DSUOS_V=81
	LIBNFQPATH=$(ROOT)libnfqueue/
	LIBNFQ=${LIBNFQPATH}lib/libnetfilter_queue.a ${LIBNFQPATH}lib/libnfnetlink.a
else ifdef suos_arm64_1043
	ZLOGLIB=-lzlog
	MYSQLLIB=-lmysqlclient_r -L/usr/local/mysql/lib
	MYSQLINC=/usr/local/mysql/include
	LIBSURICATA=$(LIBSARM64_1043)libsuricata.a
	LIBIEC61850=$(LIBSARM64_1043)libiec61850.a
	GLIB2INC+=/usr/include/glib-2.0/
	GLIB2INC+=/usr/include/glib-2.0/glib/
	GLIB2INC+=/usr/lib64/glib-2.0/include/

	LIBWIS=$(WISEPINC)libwireshark_epan_print.a
	LIBWIRE=-lwireshark -L/usr/lib/
	LIBWSUTIL=-lwsutil -L/usr/lib/
	LIBWIRETAP=-lwiretap -L/usr/lib/ -lgthread-2.0 -lglib-2.0
	SUOSVERSION=-DSUOS_V=1000
	LIBNFQPATH=/usr/local/libnfqueue/include/
	LIBNFQ=-lnetfilter_queue -lnfnetlink
else ifdef suos_ft
	ZLOGLIB=-lzlog
	MYSQLLIB=-lmysqlclient_r -L/usr/lib
	MYSQLINC=/usr/include/mysql/
	LIBSURICATA=$(LIBS_FT)libsuricata.a
	LIBIEC61850=$(LIBS_FT)libiec61850.a
	GLIB2INC+=$(GLIBV8INC)glib-2.0/
	LIBWIS=$(WISEPINC)libwireshark_epan_print.a
	LIBWIRE=-lwireshark -L/usr/lib/
	LIBWSUTIL=-lwsutil -L/usr/lib/
	LIBWIRETAP=-lwiretap -lgthread-2.0 -lglib-2.0
	SUOSVERSION=-DSUOS_V=2000
	LIBNFQPATH=/usr/local/libnfqueue/include/
	LIBNFQ=-lnetfilter_queue -lnfnetlink
else ifdef suosv6
	ZLOGLIB=$(LIBS)libzlog.a
	MYSQLLIB=$(LIBS)libmyisammrg.a $(LIBS)libmysqlclient_r.a
	MYSQLINC=$(ROOT)mysql/
	LIBSURICATA=$(LIBS)libsuricata.a
	LIBIEC61850=$(LIBS)libiec61850.a
	GLIB2INC=$(GLIBV6INC)glib-2.0/
	GLIB2HINC=$(GLIBV6INC)glib-2.0/glib/
	SUOSVERSION=-DSUOS_V=6
endif

VPATH += $(ROOT):$(COMINC):$(SIP):$(PDT):$(SIP_INTERCONT):$(MULTICAST):$(DBSYNC):$(FILESYNC)
VPATH += $(SYSDATA):$(SYSMODS):$(COMMODS):$(USERMODS):$(INDUSTRY):$(DATABASE)
VPATH += $(MMSINC):$(OPCINC):$(PCREINC):$(ZLOGINC):$(MYSQLINC):$(AUTH):$(SYSLOG)
VPATH += $(SUBFUNC):$(RULES):$(IPQNETLINK):$(NFQNETLINK):$(LIBNFQPATH):$(PUBLICINC)
VPATH += $(WISINC):$(WISEPINC):$(GLIB2INC):$(GLIB2HINC):$(RFC3261):$(SCANCFG)

FILESRC += $(PUBLIC)fileoperator.cpp
FILESRC += $(PUBLIC)filename.cpp
FILESRC += $(PUBLIC)syscfg.cpp
FILESRC += $(PUBLIC)stringex.cpp
FILESRC += $(PUBLIC)sha1.cpp

SOURCE += $(wildcard $(SYSDATA)*.cpp)
SOURCE += $(wildcard $(SIP)*.cpp)
SOURCE += $(wildcard $(PDT)*.cpp)
SOURCE += $(wildcard $(RFC3261)*.cpp)
SOURCE += $(wildcard $(SIP_INTERCONT)*.cpp)
SOURCE += $(wildcard $(MULTICAST)*.cpp)
SOURCE += $(wildcard $(DBSYNC)*.cpp)
SOURCE += $(wildcard $(FILESYNC)*.cpp)
SOURCE += $(wildcard $(COMMODS)*.cpp)
SOURCE += $(wildcard $(USERMODS)*.cpp)
SOURCE += $(wildcard $(INDUSTRY)*.cpp)
SOURCE += $(wildcard $(DATABASE)*.cpp)
SOURCE += $(wildcard $(SYSMODS)*.cpp)
SOURCE += $(wildcard $(IPQNETLINK)*.cpp)
SOURCE += $(wildcard $(NFQNETLINK)*.cpp)
SOURCE += $(wildcard $(RULES)*.cpp)
SOURCE += $(wildcard $(SUBFUNC)*.cpp)
#SOURCE += $(wildcard $(SYSLOG)*.cpp)
SOURCE += $(PUBLIC)ip6str.cpp
SOURCE += $(FILESRC)
SOURCE += FCLicenseMod.cpp FCBSTX.cpp common.cpp simple.cpp FCLogManage.cpp FCDelSpace.cpp FCMD5.cpp \
 FCTimeToPeer.cpp FCVirusAPI.cpp FCMsgAck.cpp FCPeerExecuteCMD.cpp FCSendFileUdp.cpp FCKey.cpp \
 au_api.cpp FCThread.cpp network.cpp hardinfo.cpp speaker.cpp tbl_err_comm.cpp localip_api.cpp slog.cpp \
 nic.cpp
OBJECTS = $(patsubst %.cpp,%.o,$(SOURCE))

SOURCERECV=$(wildcard $(RECVMAIN)*.cpp)
SOURCERECV += $(PUBLIC)ip6str.cpp
SOURCERECV += $(FILESRC)
SOURCERECV += FCMsgAck.cpp FCTimeToPeer.cpp FCLogManage.cpp FCSendFileUdp.cpp FCMD5.cpp simple.cpp \
 hardinfo.cpp FCPeerExecuteCMD.cpp common.cpp FCDelSpace.cpp speaker.cpp tbl_err_comm.cpp localip_api.cpp \
 slog.cpp sendfiletcp.cpp nic.cpp
OBJECTSRECV=$(patsubst %.cpp,%.o,$(SOURCERECV))

SOURCEHOT=$(wildcard $(HOTBAK)*.cpp)
SOURCEHOT += $(PUBLIC)ip6str.cpp
SOURCEHOT += $(FILESRC)
SOURCEHOT += simple.cpp hardinfo.cpp FCMsgAck.cpp FCMD5.cpp FCLogManage.cpp FCPeerExecuteCMD.cpp \
 FCThread.cpp common.cpp FCDelSpace.cpp tbl_err_comm.cpp slog.cpp
OBJECTSHOT=$(patsubst %.cpp,%.o,$(SOURCEHOT))

ALLOBJS = $(OBJECTS) $(OBJECTSRECV) $(OBJECTSHOT)
ALLSOURCE = $(patsubst %.o,%.cpp, $(ALLOBJS))

all:sys6 recvmain hotbakmain

sys6:$(OBJECTS)
	$(RUNLINK) -o $@ $^ $(MYSQLLIB) $(ZLOGLIB) $(LIBSURICATA) $(LIBIEC61850) $(LIBNFQ) $(LIBWIS) $(LIBWIRE) $(LIBWSUTIL) $(LIBWIRETAP) $(CPPFLAGS) -lpthread
recvmain:$(OBJECTSRECV)
	$(RUNLINK) -o $@ $^ $(MYSQLLIB) $(ZLOGLIB) $(CPPFLAGS)  -lpthread
hotbakmain:$(OBJECTSHOT)
	$(RUNLINK) -o $@ $^ $(MYSQLLIB) $(ZLOGLIB) $(CPPFLAGS)  -lpthread

.PHONY : clean
clean:
	rm -f sys6 recvmain hotbakmain
	rm -f $(ALLOBJS)
	rm -f $(patsubst %.o,%.d,$(ALLOBJS))
	rm -f $(patsubst %.o,%.d.*,$(ALLOBJS))

include $(ALLSOURCE:.cpp=.d)

%.o:%.cpp
	$(RUN) -c $< -o $@ $(CPPFLAGS) $(SUOSVERSION)

#get all dependencies
%.d:%.cpp
	@set -e; rm -f $@; \
	$(C++) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
#	rm -f $@.$$$$
