#! /bin/sh
#
#  This script builds the SnortSam release and debug versions
#  with the OPSEC libraries from Checkpoint. These have to reside
#  in the OPSEC subdirectory. You can always adjust the directory
#  by editing the lines below.
#
#  Note: On Linux, the pthread stuff is in the libpthread library.
#        On FreeBSD, it is in the libc_r library. Now switchable.
#
#        Under Solaris, the OPSEC stuff is linked dynamically.
#        On other platforms, statically.

# *BSD only: uncomment to build with '-lc_r', default is '-lpthread'
#BSDTHREADLIB='-lc_r'

# OpenBSD only: Default is now the new pf2 plugin.
# To build the old pf plugin uncomment PFPLUGIN
#PFPLUGIN="-DUSE_SSP_PF"


# ========================
# snortsam
#SSP_GENERIC_SRC="snortsam.c twofish.c ssp_ciscoacl.c ssp_cisco_nullroute.c ssp_cisco_nullroute2.c ssp_email.c ssp_forward.c ssp_fwexec.c ssp_fwsam.c ssp_netscreen.c ssp_opsec.c ssp_pix.c ssp_snmp_interface_down.c ssp_wgrd.c"
SSP_GENERIC_SRC="snortsam.c twofish.c ssp_email.c"

systype=`uname`
SNORTSAM=../snortsam
SAMTOOL=../samtool

# samtool
SAMTOOL_SRC="samtool.c twofish.c"

# OS specific stuff compiles only on these platforms (need headers/libs)
#SSP_LINUX_SRC="ssp_ipchains.c ssp_iptables.c ssp_ebtables.c"
SSP_LINUX_SRC="ssp_iptables.c ssp_ebtables.c"
SSP_OBSD_SRC="ssp_pf.c ssp_pf2.c"
SSP_BSD_SRC="ssp_ipf.c ssp_ipfw2.c ssp_pf2.c"
SSP_SUNOS_SRC="ssp_ipf.c"

CFLAGS="-O2 -D${systype}"
LDFLAGS=

# OS specific flags
LINUX_CFLAGS=
LINUX_LDFLAGS="-lpthread"
OBSD_CFLAGS="-DBSD ${PFPLUGIN}"
OBSD_LDFLAGS="-lpthread"
BSD_CFLAGS="-DBSD"
BSD_LDFLAGS=${BSDTHREADLIB:-"-lpthread"}
SUNOS_CFLAGS="-DSOLARIS"
SUNOS_LDFLAGS="-lpthread -lnsl -lsocket -lresolv"

# OPSEC 22 SDK
OPSEC_CFLAGS="-Iopsec/include/opsec -Iopsec/include -DENABLE_OPSEC"
OPSEC_LDFLAGS="-lnsl"
OPSEC_SUNOS_CFLAGS="-I/usr/local/pkg_rel/include -DENABLE_OPSEC"
OPSEC_SUNOS_LDFLAGS="-L/usr/local/pkg_rel/lib/release.dynamic -lopsec"


case "$1" in
	[oO][pP][sS][eE][cC])

	OPSEC_LIBS="opsec/lib/release.static/libcpcert.a opsec/lib/release.static/libckpssl.a opsec/lib/release.static/libopsec.a opsec/lib/release.static/libckpssl.a opsec/lib/release.static/libasn1cpp.a opsec/lib/release.static/libcpopenssl.a opsec/lib/release.static/libDataStruct.a opsec/lib/release.static/libskey.a opsec/lib/release.static/libDataStruct.a opsec/lib/release.static/libcpcert.a opsec/lib/release.static/liblogfilter.a opsec/lib/release.static/libCPSrvIS.a opsec/lib/release.static/libEncode.a opsec/lib/release.static/libResolver.a opsec/lib/release.static/libAppUtils.a opsec/lib/release.static/libcpca.a opsec/lib/release.static/libCPMIBase501.a opsec/lib/release.static/libCPMIClient501.a opsec/lib/release.static/libcp_policy.a opsec/lib/release.static/libComUtils.a opsec/lib/release.static/libsicauth.a opsec/lib/release.static/libndb.a opsec/lib/release.static/libcpopenssl.a opsec/lib/release.static/libOS.a opsec/lib/release.static/libcpcryptutil.a opsec/lib/release.static/libcpbcrypt.a opsec/lib/release.static/libopsecext.a opsec/lib/release.static/libcpprod50.a opsec/lib/release.static/libckpssl.a opsec/lib/release.static/libEventUtils.a opsec/lib/release.static/libsic.a opsec/lib/release.static/libResolve.a opsec/lib/release.static/libcpprng.a opsec/lib/release.static/libobjlibclient.a opsec/lib/release.static/libasn1cpp.a opsec/lib/release.static/libopsec.a opsec/lib/release.static/libDataStruct.a opsec/lib/release.static/libcpbcrypt.a opsec/lib/release.static/libOS.a opsec/lib/release.static/libcpcert.a opsec/lib/release.static/libcpbcrypt.a opsec/lib/release.static/libComUtils.a opsec/lib/release.static/libOS.a opsec/lib/release.static/libcpca.a opsec/lib/release.static/libcpcert.a opsec/lib/release.static/libcpcryptutil.a opsec/lib/release.static/libskey.a opsec/lib/lib/static/libcpc++-3-libc6.1-2-2.10.0.a"

		echo "-------------------------------------------------------------------------------"
		echo "Building SnortSam (release) with OPSEC libraries"
		echo "-------------------------------------------------------------------------------"

		cd src
		rm -f ${SNORTSAM}
		rm -f ${SNORTSAM}-debug
		rm -f *.o

		case "${systype}" in
			Linux*)
				${CC} ${CFLAGS} ${LINUX_CFLAGS} ${OPSEC_CFLAGS} ${LDFLAGS} ${LINUX_LDFLAGS} ${OPSEC_LDFLAGS} ${OPSEC_LIBS} \
					${SSP_GENERIC_SRC} ${SSP_LINUX_SRC} -o ${SNORTSAM}
				;;

			OpenBSD*)
				#${CC} ${CFLAGS} ${OBSD_CFLAGS} ${OPSEC_CFLAGS} ${LDFLAGS} ${OBSD_LDFLAGS} ${OPSEC_LIBS} /usr/lib/libnsl.a -o ${SNORTSAM}
				${CC} ${CFLAGS} ${OBSD_CFLAGS} ${OPSEC_CFLAGS} ${LDFLAGS} ${OBSD_LDFLAGS} ${OPSEC_LDFLAGS} ${OPSEC_LIBS} \
					${SSP_GENERIC_SRC} ${SSP_OBSD_SRC} -o ${SNORTSAM}
				;;

			*BSD*)
				${CC} ${CFLAGS} ${BSD_CFLAGS} ${OPSEC_CFLAGS} ${LDFLAGS} ${BSD_LDFLAGS} ${OPSEC_LDFLAGS} ${OPSEC_LIBS} \
					${SSP_GENERIC_SRC} ${SSP_BSD_SRC} -o ${SNORTSAM}
				;;

			SunOS*)
				${CC} ${CFLAGS} ${SUNOS_CFLAGS} ${OPSEC_SUNOS_CFLAGS} ${LDFLAGS} ${SUNOS_LDFLAGS} ${OPSEC_SUNOS_LDFLAGS} \
					${SSP_GENERIC_SRC} ${SSP_SUNOS_SRC} -o ${SNORTSAM}
				;;
		esac


		echo "-------------------------------------------------------------------------------"
		echo "Building SnortSam (debug) with OPSEC libraries"
		echo "-------------------------------------------------------------------------------"

		rm -f *.o
		CFLAGS="${CFLAGS} -DFWSAMDEBUG"
		SNORTSAM="${SNORTSAM}-debug"

		case "${systype}" in
			Linux*)
				${CC} ${CFLAGS} ${LINUX_CFLAGS} ${OPSEC_CFLAGS} ${LDFLAGS} ${LINUX_LDFLAGS} ${OPSEC_LDFLAGS} ${OPSEC_LIBS} \
					${SSP_GENERIC_SRC} ${SSP_LINUX_SRC} -o ${SNORTSAM}
				;;

			OpenBSD*)
				#${CC} ${CFLAGS} ${OBSD_CFLAGS} ${OPSEC_CFLAGS} ${LDFLAGS} ${OBSD_LDFLAGS} ${OPSEC_LIBS} /usr/lib/libnsl.a -o ${SNORTSAM}
				${CC} ${CFLAGS} ${OBSD_CFLAGS} ${OPSEC_CFLAGS} ${LDFLAGS} ${OBSD_LDFLAGS} ${OPSEC_LDFLAGS} ${OPSEC_LIBS} \
					${SSP_GENERIC_SRC} ${SSP_OBSD_SRC} -o ${SNORTSAM}
				;;

			*BSD*)
				${CC} ${CFLAGS} ${BSD_CFLAGS} ${OPSEC_CFLAGS} ${LDFLAGS} ${BSD_LDFLAGS} ${OPSEC_LDFLAGS} ${OPSEC_LIBS} \
					${SSP_GENERIC_SRC} ${SSP_BSD_SRC} -o ${SNORTSAM}
				;;

			SunOS*)
				${CC} ${CFLAGS} ${SUNOS_CFLAGS} ${OPSEC_SUNOS_CFLAGS} ${LDFLAGS} ${SUNOS_LDFLAGS} ${OPSEC_SUNOS_LDFLAGS} \
					${SSP_GENERIC_SRC} ${SSP_SUNOS_SRC} -o ${SNORTSAM}
				;;
		esac
		cd ..
		;;

	[Cc][Ll][Ee][Aa][Nn])
		echo "-------------------------------------------------------------------------------"
		echo "Cleanup ..."
		echo "-------------------------------------------------------------------------------"

		cd src
		rm -f *.o
		rm -f ${SNORTSAM}
		rm -f ${SNORTSAM}-debug
		rm -f ${SAMTOOL}
		rm -f ${SAMTOOL}-debug
		cd ..
	;;

	[Ss][Aa][Mm][Tt][Oo][Oo][Ll])
		echo "-------------------------------------------------------------------------------"
		echo "Building samtool (release)"
		echo "-------------------------------------------------------------------------------"

		cd src
		rm -f *.o
		rm -f ${SAMTOOL}
		rm -f ${SAMTOOL}-debug

		case "${systype}" in
			Linux*)   ${CC} ${CFLAGS} ${LINUX_CFLAGS} ${LDFLAGS} ${LINUX_LDFLAGS} ${SAMTOOL_SRC} -o ${SAMTOOL} ;;
			OpenBSD*) ${CC} ${CFLAGS} ${OBSD_CFLAGS}  ${LDFLAGS} ${OBSD_LDFLAGS}  ${SAMTOOL_SRC} -o ${SAMTOOL} ;;
			*BSD*)    ${CC} ${CFLAGS} ${BSD_CFLAGS}   ${LDFLAGS} ${BSD_LDFLAGS}   ${SAMTOOL_SRC} -o ${SAMTOOL} ;;
			SunOS)    ${CC} ${CFLAGS} ${SUNOS_CFLAGS} ${LDFLAGS} ${SUNOS_LDFLAGS} ${SAMTOOL_SRC} -o ${SAMTOOL} ;;
		esac

		echo "-------------------------------------------------------------------------------"
		echo "Building samtool (debug)"
		echo "-------------------------------------------------------------------------------"

		rm -f *.o
		CFLAGS="${CFLAGS} -DFWSAMDEBUG"
		SAMTOOL="${SAMTOOL}-debug"

		case "${systype}" in
			Linux*)   ${CC} ${CFLAGS} ${LINUX_CFLAGS} ${LDFLAGS} ${LINUX_LDFLAGS} ${SAMTOOL_SRC} -o ${SAMTOOL} ;;
			OpenBSD*) ${CC} ${CFLAGS} ${OBSD_CFLAGS}  ${LDFLAGS} ${OBSD_LDFLAGS}  ${SAMTOOL_SRC} -o ${SAMTOOL} ;;
			*BSD*)    ${CC} ${CFLAGS} ${BSD_CFLAGS}   ${LDFLAGS} ${BSD_LDFLAGS}   ${SAMTOOL_SRC} -o ${SAMTOOL} ;;
			SunOS)    ${CC} ${CFLAGS} ${SUNOS_CFLAGS} ${LDFLAGS} ${SUNOS_LDFLAGS} ${SAMTOOL_SRC} -o ${SAMTOOL} ;;
		esac
		cd ..
	;;

	*)
		echo "-------------------------------------------------------------------------------"
		echo "Building SnortSam (release)"
		echo "-------------------------------------------------------------------------------"

		cd src
		rm -f *.o
		rm -f ${SNORTSAM}
		rm -f ${SNORTSAM}-debug

		case "${systype}" in
			Linux*)   ${CC} ${CFLAGS} ${LINUX_CFLAGS} ${LDFLAGS} ${LINUX_LDFLAGS} ${SSP_GENERIC_SRC} ${SSP_LINUX_SRC} -o ${SNORTSAM} ;;
			OpenBSD*) ${CC} ${CFLAGS} ${OBSD_CFLAGS}  ${LDFLAGS} ${OBSD_LDFLAGS}  ${SSP_GENERIC_SRC} ${SSP_OBSD_SRC}  -o ${SNORTSAM} ;;
			*BSD*)    ${CC} ${CFLAGS} ${BSD_CFLAGS}   ${LDFLAGS} ${BSD_LDFLAGS}   ${SSP_GENERIC_SRC} ${SSP_BSD_SRC}   -o ${SNORTSAM} ;;
			SunOS*)   ${CC} ${CFLAGS} ${SUNOS_CFLAGS} ${LDFLAGS} ${SUNOS_LDFLAGS} ${SSP_GENERIC_SRC} ${SSP_SUNOS_SRC} -o ${SNORTSAM} ;;
		esac


		echo "-------------------------------------------------------------------------------"
		echo "Building SnortSam (debug)"
		echo "-------------------------------------------------------------------------------"

		rm -f *.o
		CFLAGS="${CFLAGS} -DFWSAMDEBUG"
		SNORTSAM="${SNORTSAM}-debug"

		case "${systype}" in
			Linux*)   ${CC} ${CFLAGS} ${LINUX_CFLAGS} ${LDFLAGS} ${LINUX_LDFLAGS} ${SSP_GENERIC_SRC} ${SSP_LINUX_SRC} -o ${SNORTSAM} ;;
			OpenBSD*) ${CC} ${CFLAGS} ${OBSD_CFLAGS}  ${LDFLAGS} ${OBSD_LDFLAGS}  ${SSP_GENERIC_SRC} ${SSP_OBSD_SRC}  -o ${SNORTSAM} ;;
			*BSD*)    ${CC} ${CFLAGS} ${BSD_CFLAGS}   ${LDFLAGS} ${BSD_LDFLAGS}   ${SSP_GENERIC_SRC} ${SSP_BSD_SRC}   -o ${SNORTSAM} ;;
			SunOS*)   ${CC} ${CFLAGS} ${SUNOS_CFLAGS} ${LDFLAGS} ${SUNOS_LDFLAGS} ${SSP_GENERIC_SRC} ${SSP_SUNOS_SRC} -o ${SNORTSAM} ;;

		esac
		cd ..
		;;
esac

${STRIP} snortsam
${STRIP} snortsam-debug

echo "Done."

