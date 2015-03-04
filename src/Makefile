# $Id: Makefile,v 2.14 2010/03/29 20:57:55 fknobbe Exp $
#
#
# Makefile for snortsam
#
# To use automated OS detection just type "make".  Uncomment the macros below
# if you want DEBUG and/or OPSEC support.
#
# Alternatively, the "make snortsam-<os>[-opsec]" target syntax may be used
# (eg "make snortsam-linux" or "make snortsam-sunos-opsec").
#

# uncomment for debugging
#DEBUG  = -DFWSAMDEBUG

# uncomment for OPSEC support
#OPSEC  = -opsec

# OpenBSD only: Default is now the new pf2 plugin.
# To build the old pf plugin uncomment PFPLUGIN
#PFPLUGIN = -DUSE_SSP_PF

# generic plugins for all builds
SSP_GENERIC = ssp_fwexec.o ssp_ciscoacl.o ssp_cisco_nullroute.o ssp_email.o \
	      ssp_opsec.o ssp_fwsam.o ssp_pix.o ssp_netscreen.o ssp_wgrd.o \
              ssp_snmp_interface_down.o ssp_forward.o ssp_cisco_nullroute2.o

# OS specific stuff compiles only on these platforms (need headers/libs)
#SSP_OBSD    = ssp_ipf.o ssp_pf.o ssp_pf2.o
SSP_OBSD    = ssp_pf.o ssp_pf2.o
SSP_BSD     = ssp_ipf.o ssp_ipfw2.o ssp_pf2.o
SSP_LINUX   = ssp_ipchains.o ssp_iptables.o ssp_ebtables.o
SSP_SUNOS   = ssp_ipf.o


OBJS    = snortsam.o twofish.o $(SSP_GENERIC)
PROG    = snortsam
SAMTOOL = samtool
CC      = gcc
CFLAGS  = -O2 -D$(SYSTYPE) $(DEBUG)
LDFLAGS =
SYSTYPE = `uname`

# OS specific flags
OBSD_CFLAGS   = -DBSD ${PFPLUGIN}
OBSD_LDFLAGS  = -lpthread
BSD_CFLAGS    = -DBSD
BSD_LDFLAGS   = -lpthread
SUNOS_CFLAGS  = -DSOLARIS
SUNOS_LDFLAGS = -lpthread -lnsl -lsocket -lresolv
LINUX_CFLAGS  =
LINUX_LDFLAGS = -lpthread

# OPSEC
OPSEC_CFLAGS  = -Iopsec/include/opsec -DENABLE_OPSEC
OPSEC_LDFLAGS = -lnsl
OPSEC_SUNOS_CFLAGS  = -I/usr/local/pkg_rel/include -DENABLE_OPSEC
OPSEC_SUNOS_LDFLAGS = -L/usr/local/pkg_rel/lib/release.dynamic -lopsec
OPSEC_LIBS    = opsec/lib/release.static/libcpcert.a \
		opsec/lib/release.static/libckpssl.a \
		opsec/lib/release.static/libopsec.a \
		opsec/lib/release.static/libckpssl.a \
		opsec/lib/release.static/libasn1cpp.a \
		opsec/lib/release.static/libcpopenssl.a \
		opsec/lib/release.static/libDataStruct.a \
		opsec/lib/release.static/libskey.a \
		opsec/lib/release.static/libDataStruct.a \
		opsec/lib/release.static/libcpcert.a \
		opsec/lib/release.static/liblogfilter.a \
		opsec/lib/release.static/libCPSrvIS.a \
		opsec/lib/release.static/libEncode.a \
		opsec/lib/release.static/libResolver.a \
		opsec/lib/release.static/libAppUtils.a \
		opsec/lib/release.static/libcpca.a \
		opsec/lib/release.static/libCPMIBase501.a \
		opsec/lib/release.static/libCPMIClient501.a \
		opsec/lib/release.static/libcp_policy.a \
		opsec/lib/release.static/libComUtils.a \
		opsec/lib/release.static/libsicauth.a \
		opsec/lib/release.static/libndb.a \
		opsec/lib/release.static/libcpopenssl.a \
		opsec/lib/release.static/libOS.a \
		opsec/lib/release.static/libcpcryptutil.a \
		opsec/lib/release.static/libcpbcrypt.a \
		opsec/lib/release.static/libopsecext.a \
		opsec/lib/release.static/libcpprod50.a \
		opsec/lib/release.static/libckpssl.a \
		opsec/lib/release.static/libEventUtils.a \
		opsec/lib/release.static/libsic.a \
		opsec/lib/release.static/libResolve.a \
		opsec/lib/release.static/libcpprng.a \
		opsec/lib/release.static/libobjlibclient.a \
		opsec/lib/release.static/libasn1cpp.a \
		opsec/lib/release.static/libopsec.a \
		opsec/lib/release.static/libDataStruct.a \
		opsec/lib/release.static/libcpbcrypt.a \
		opsec/lib/release.static/libOS.a \
		opsec/lib/release.static/libcpcert.a \
		opsec/lib/release.static/libcpbcrypt.a \
		opsec/lib/release.static/libComUtils.a \
		opsec/lib/release.static/libOS.a \
		opsec/lib/release.static/libcpca.a \
		opsec/lib/release.static/libcpcert.a \
		opsec/lib/release.static/libcpcryptutil.a \
		opsec/lib/release.static/libskey.a \
		opsec/lib/lib/static/libcpc++-3-libc6.1-2-2.10.0.a

all:
	case "$(SYSTYPE)" in \
		OpenBSD*) what=obsd;; \
		*BSD)     what=bsd;; \
		Linux)    what=linux;; \
		SunOS)    what=sunos;; \
	esac && make snortsam-$$what$(OPSEC)

$(PROG)-obsd:
	make $(PROG) "CFLAGS=$(CFLAGS) $(OBSD_CFLAGS)" \
	  "LDFLAGS=$(LDFLAGS) $(OBSD_LDFLAGS)" "OBJS=$(OBJS) $(SSP_OBSD)"
$(PROG)-obsd-opsec:
	make $(PROG) "CFLAGS=$(CFLAGS) $(OBSD_CFLAGS) $(OPSEC_CFLAGS)" \
	  "LDFLAGS=$(LDFLAGS) $(OBSD_LDFLAGS) $(OPSEC_LDFLAGS)" \
	  "OBJS=$(OBJS) $(SSP_OBSD) $(OPSEC_LIBS)"

$(PROG)-bsd:
	make $(PROG) "CFLAGS=$(CFLAGS) $(BSD_CFLAGS)" \
	  "LDFLAGS=$(LDFLAGS) $(BSD_LDFLAGS)" "OBJS=$(OBJS) $(SSP_BSD)"
$(PROG)-bsd-opsec:
	make $(PROG) "CFLAGS=$(CFLAGS) $(BSD_CFLAGS) $(OPSEC_CFLAGS)" \
	  "LDFLAGS=$(LDFLAGS) $(BSD_LDFLAGS) $(OPSEC_LDFLAGS)" \
	  "OBJS=$(OBJS) $(SSP_BSD) $(OPSEC_LIBS)"

$(PROG)-linux:
	make $(PROG) "CFLAGS=$(CFLAGS) $(LINUX_CFLAGS)" \
	  "LDFLAGS=$(LDFLAGS) $(LINUX_LDFLAGS)" "OBJS=$(OBJS) $(SSP_LINUX)"
$(PROG)-linux-opsec:
	make $(PROG) "CFLAGS=$(CFLAGS) $(LINUX_CFLAGS) $(OPSEC_CFLAGS)" \
	  "LDFLAGS=$(LDFLAGS) $(LINUX_LDFLAGS) $(OPSEC_LDFLAGS)" \
	  "OBJS=$(OBJS) $(SSP_LINUX) $(OPSEC_LIBS)"

$(PROG)-sunos:
	make $(PROG) "CFLAGS=$(CFLAGS) $(SUNOS_CFLAGS)" \
	  "LDFLAGS=$(LDFLAGS) $(SUNOS_LDFLAGS)" "OBJS=$(OBJS) $(SSP_SUNOS)"
$(PROG)-sunos-opsec:
	make $(PROG) "CFLAGS=$(CFLAGS) $(SUNOS_CFLAGS) $(OPSEC_SUNOS_CFLAGS)" \
	  "LDFLAGS=$(LDFLAGS) $(SUNOS_LDFLAGS) $(OPSEC_SUNOS_LDFLAGS)" \
	  "OBJS=$(OBJS) $(SSP_SUNOS)"

.SUFFIXES: .o .c

.c.o:
	$(CC) $(CFLAGS) -c $<

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o ../$(PROG) $(OBJS)

clean:
	rm -f ../$(PROG) ../${SAMTOOL} *.o

$(SAMTOOL): samtool.o twofish.o
	case "$(SYSTYPE)" in \
                OpenBSD*) twhat=obsd;; \
                *BSD)     twhat=bsd;; \
                Linux)    twhat=linux;; \
                SunOS)    twhat=sunos;; \
	esac && make $(SAMTOOL)-$$twhat

$(SAMTOOL)-obsd:
	$(CC) $(LDFLAGS) $(OBSD_LDFLAGS) -o ../$(SAMTOOL) samtool.o twofish.o

$(SAMTOOL)-bsd:
	$(CC) $(LDFLAGS) $(BSD_LDFLAGS) -o ../$(SAMTOOL) samtool.o twofish.o

$(SAMTOOL)-linux:
	$(CC) $(LDFLAGS) $(LINUX_LDFLAGS) -o ../$(SAMTOOL) samtool.o twofish.o

$(SAMTOOL)-sunos:
	$(CC) $(LDFLAGS) $(SUNOS_LDFLAGS) -o ../$(SAMTOOL) samtool.o twofish.o


