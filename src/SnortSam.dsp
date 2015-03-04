# Microsoft Developer Studio Project File - Name="SnortSam" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=SnortSam - Win32 Debug ISA2004
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "SnortSam.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "SnortSam.mak" CFG="SnortSam - Win32 Debug ISA2004"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "SnortSam - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "SnortSam - Win32 Release OPSEC" (based on "Win32 (x86) Console Application")
!MESSAGE "SnortSam - Win32 Release ISA2002" (based on "Win32 (x86) Console Application")
!MESSAGE "SnortSam - Win32 Release ISA2004" (based on "Win32 (x86) Console Application")
!MESSAGE "SnortSam - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "SnortSam - Win32 Debug OPSEC" (based on "Win32 (x86) Console Application")
!MESSAGE "SnortSam - Win32 Debug ISA2002" (based on "Win32 (x86) Console Application")
!MESSAGE "SnortSam - Win32 Debug ISA2004" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "SnortSam - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "SnortSam___Win32_Release"
# PROP BASE Intermediate_Dir "SnortSam___Win32_Release"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "SnortSam___Win32_Release"
# PROP Intermediate_Dir "SnortSam___Win32_Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /G5 /MT /W3 /GX /O2 /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /FR /YX /FD /c
# ADD CPP /nologo /G5 /MT /W3 /GX /O2 /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /FR /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib oldnames.lib libc.lib advapi32.lib wsock32.lib uuid.lib ole32.lib oleaut32.lib comsupp.lib /nologo /subsystem:console /machine:I386 /nodefaultlib /libpath:"opsec/lib/release.static"
# ADD LINK32 kernel32.lib oldnames.lib libc.lib advapi32.lib wsock32.lib uuid.lib ole32.lib oleaut32.lib comsupp.lib /nologo /subsystem:console /machine:I386 /nodefaultlib /libpath:"opsec/lib/release.static"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release OPSEC"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "SnortSam___Win32_Release_OPSEC"
# PROP BASE Intermediate_Dir "SnortSam___Win32_Release_OPSEC"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "SnortSam___Win32_Release_OPSEC"
# PROP Intermediate_Dir "SnortSam___Win32_Release_OPSEC"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /G5 /MT /W3 /GX /O2 /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "ENABLE_OPSEC" /D "ENABLE_WIN32_SERVICE" /FR /YX /FD /c
# SUBTRACT BASE CPP /WX
# ADD CPP /nologo /G5 /MT /W3 /GX /O2 /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "ENABLE_OPSEC" /D "ENABLE_WIN32_SERVICE" /FR /YX /FD /c
# SUBTRACT CPP /WX
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib oldnames.lib msvcrt.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib comsupp.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib opsec.lib opsecext.lib AppUtils.lib asn1cpp.lib ckpssl.lib ComUtils.lib cpbcrypt.lib cpca.lib cpcert.lib cpcryptutil.lib CPMIBase501.lib CPMIClient501.lib cpopenssl.lib cpprng.lib cpprod50.lib CPSrvIS.lib cp_policy.lib DataStruct.lib Encode.lib EventUtils.lib logfilter.lib ndb.lib objlibclient.lib OS.lib Resolve.lib sic.lib sicauth.lib skey.lib /nologo /subsystem:console /machine:I386 /nodefaultlib /libpath:"opsec/lib/release.static"
# ADD LINK32 kernel32.lib user32.lib gdi32.lib oldnames.lib msvcrt.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib comsupp.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib opsec.lib opsecext.lib AppUtils.lib asn1cpp.lib ckpssl.lib ComUtils.lib cpbcrypt.lib cpca.lib cpcert.lib cpcryptutil.lib CPMIBase501.lib CPMIClient501.lib cpopenssl.lib cpprng.lib cpprod50.lib CPSrvIS.lib cp_policy.lib DataStruct.lib Encode.lib EventUtils.lib logfilter.lib ndb.lib objlibclient.lib OS.lib Resolve.lib sic.lib sicauth.lib skey.lib /nologo /subsystem:console /machine:I386 /nodefaultlib /libpath:"opsec/lib/release.static"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2002"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "SnortSam___Win32_Release_ISA2002"
# PROP BASE Intermediate_Dir "SnortSam___Win32_Release_ISA2002"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "SnortSam___Win32_Release_ISA2002"
# PROP Intermediate_Dir "SnortSam___Win32_Release_ISA2002"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /G5 /MT /W3 /GX /O2 /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /FR /YX /FD /c
# ADD CPP /nologo /G5 /MT /W3 /GX /O2 /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /D "WITH_ISA2002" /FR /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib oldnames.lib libc.lib advapi32.lib wsock32.lib uuid.lib ole32.lib oleaut32.lib comsupp.lib /nologo /subsystem:console /machine:I386 /nodefaultlib /libpath:"opsec/lib/release.static"
# ADD LINK32 kernel32.lib oldnames.lib libc.lib advapi32.lib wsock32.lib uuid.lib ole32.lib oleaut32.lib comsupp.lib /nologo /subsystem:console /machine:I386 /nodefaultlib /libpath:"opsec/lib/release.static"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2004"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "SnortSam___Win32_Release_ISA2004"
# PROP BASE Intermediate_Dir "SnortSam___Win32_Release_ISA2004"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "SnortSam___Win32_Release_ISA2004"
# PROP Intermediate_Dir "SnortSam___Win32_Release_ISA2004"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /G5 /MT /W3 /GX /O2 /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /FR /YX /FD /c
# ADD CPP /nologo /G5 /MT /W3 /GX /O2 /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /D "WITH_ISA2004" /FR /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib oldnames.lib libc.lib advapi32.lib wsock32.lib uuid.lib ole32.lib oleaut32.lib comsupp.lib /nologo /subsystem:console /machine:I386 /nodefaultlib /libpath:"opsec/lib/release.static"
# ADD LINK32 kernel32.lib oldnames.lib libc.lib advapi32.lib wsock32.lib uuid.lib ole32.lib oleaut32.lib comsupp.lib /nologo /subsystem:console /machine:I386 /nodefaultlib /libpath:"opsec/lib/release.static"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "SnortSam___Win32_Debug"
# PROP BASE Intermediate_Dir "SnortSam___Win32_Debug"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "SnortSam___Win32_Debug"
# PROP Intermediate_Dir "SnortSam___Win32_Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /G5 /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_CONSOLE" /D "DEBUG" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /Fr /YX /FD /GZ /c
# ADD CPP /nologo /G5 /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_CONSOLE" /D "DEBUG" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /Fr /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib oldnames.lib libcd.lib advapi32.lib wsock32.lib ole32.lib oleaut32.lib uuid.lib comsupp.lib /nologo /subsystem:console /debug /machine:I386 /nodefaultlib /pdbtype:sept /libpath:"opsec/lib/debug.static"
# ADD LINK32 kernel32.lib oldnames.lib libcd.lib advapi32.lib wsock32.lib ole32.lib oleaut32.lib uuid.lib comsupp.lib /nologo /subsystem:console /debug /machine:I386 /nodefaultlib /pdbtype:sept /libpath:"opsec/lib/debug.static"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug OPSEC"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "SnortSam___Win32_Debug_OPSEC"
# PROP BASE Intermediate_Dir "SnortSam___Win32_Debug_OPSEC"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "SnortSam___Win32_Debug_OPSEC"
# PROP Intermediate_Dir "SnortSam___Win32_Debug_OPSEC"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /G5 /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_CONSOLE" /D "DEBUG" /D "_MBCS" /D "ENABLE_OPSEC" /D "ENABLE_WIN32_SERVICE" /FR /YX /FD /GZ /c
# ADD CPP /nologo /G5 /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_CONSOLE" /D "DEBUG" /D "_MBCS" /D "ENABLE_OPSEC" /D "ENABLE_WIN32_SERVICE" /FR /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib oldnames.lib msvcrtd.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib comsupp.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib opsec.lib opsecext.lib AppUtils.lib asn1cpp.lib ckpssl.lib ComUtils.lib cpbcrypt.lib cpca.lib cpcert.lib cpcryptutil.lib CPMIBase501.lib CPMIClient501.lib cpopenssl.lib cpprng.lib cpprod50.lib CPSrvIS.lib cp_policy.lib DataStruct.lib Encode.lib EventUtils.lib logfilter.lib ndb.lib objlibclient.lib OS.lib Resolve.lib sic.lib sicauth.lib skey.lib /nologo /subsystem:console /debug /machine:I386 /nodefaultlib /pdbtype:sept /libpath:"opsec/lib/debug.static"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib oldnames.lib msvcrtd.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib comsupp.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib opsec.lib opsecext.lib AppUtils.lib asn1cpp.lib ckpssl.lib ComUtils.lib cpbcrypt.lib cpca.lib cpcert.lib cpcryptutil.lib CPMIBase501.lib CPMIClient501.lib cpopenssl.lib cpprng.lib cpprod50.lib CPSrvIS.lib cp_policy.lib DataStruct.lib Encode.lib EventUtils.lib logfilter.lib ndb.lib objlibclient.lib OS.lib Resolve.lib sic.lib sicauth.lib skey.lib /nologo /subsystem:console /debug /machine:I386 /nodefaultlib /pdbtype:sept /libpath:"opsec/lib/debug.static"
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2002"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "SnortSam___Win32_Debug_ISA2002"
# PROP BASE Intermediate_Dir "SnortSam___Win32_Debug_ISA2002"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "SnortSam___Win32_Debug_ISA2002"
# PROP Intermediate_Dir "SnortSam___Win32_Debug_ISA2002"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /G5 /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_CONSOLE" /D "DEBUG" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /Fr /YX /FD /GZ /c
# ADD CPP /nologo /G5 /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_CONSOLE" /D "DEBUG" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /D "WITH_ISA2002" /Fr /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib oldnames.lib libcd.lib advapi32.lib wsock32.lib ole32.lib oleaut32.lib uuid.lib comsupp.lib /nologo /subsystem:console /debug /machine:I386 /nodefaultlib /pdbtype:sept /libpath:"opsec/lib/debug.static"
# ADD LINK32 kernel32.lib oldnames.lib libcd.lib advapi32.lib wsock32.lib ole32.lib oleaut32.lib uuid.lib comsupp.lib /nologo /subsystem:console /debug /machine:I386 /nodefaultlib /pdbtype:sept /libpath:"opsec/lib/debug.static"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2004"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "SnortSam___Win32_Debug_ISA2004"
# PROP BASE Intermediate_Dir "SnortSam___Win32_Debug_ISA2004"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "SnortSam___Win32_Debug_ISA2004"
# PROP Intermediate_Dir "SnortSam___Win32_Debug_ISA2004"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /G5 /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_CONSOLE" /D "DEBUG" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /Fr /YX /FD /GZ /c
# ADD CPP /nologo /G5 /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_CONSOLE" /D "DEBUG" /D "_MBCS" /D "ENABLE_WIN32_SERVICE" /D "WITH_ISA2004" /Fr /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib oldnames.lib libcd.lib advapi32.lib wsock32.lib ole32.lib oleaut32.lib uuid.lib comsupp.lib /nologo /subsystem:console /debug /machine:I386 /nodefaultlib /pdbtype:sept /libpath:"opsec/lib/debug.static"
# ADD LINK32 kernel32.lib oldnames.lib libcd.lib advapi32.lib wsock32.lib ole32.lib oleaut32.lib uuid.lib comsupp.lib /nologo /subsystem:console /debug /machine:I386 /nodefaultlib /pdbtype:sept /libpath:"opsec/lib/debug.static"

!ENDIF 

# Begin Target

# Name "SnortSam - Win32 Release"
# Name "SnortSam - Win32 Release OPSEC"
# Name "SnortSam - Win32 Release ISA2002"
# Name "SnortSam - Win32 Release ISA2004"
# Name "SnortSam - Win32 Debug"
# Name "SnortSam - Win32 Debug OPSEC"
# Name "SnortSam - Win32 Debug ISA2002"
# Name "SnortSam - Win32 Debug ISA2004"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\snortsam.c
# End Source File
# Begin Source File

SOURCE=.\ssp_8signs.c
# End Source File
# Begin Source File

SOURCE=.\ssp_chxi.c
# End Source File
# Begin Source File

SOURCE=.\ssp_cisco_nullroute.c
# End Source File
# Begin Source File

SOURCE=.\ssp_cisco_nullroute2.c
# End Source File
# Begin Source File

SOURCE=.\ssp_ciscoacl.c
# End Source File
# Begin Source File

SOURCE=.\ssp_email.c
# End Source File
# Begin Source File

SOURCE=.\ssp_forward.c
# End Source File
# Begin Source File

SOURCE=.\ssp_fwexec.c
# End Source File
# Begin Source File

SOURCE=.\ssp_fwsam.c
# End Source File
# Begin Source File

SOURCE=.\ssp_isa.cpp

!IF  "$(CFG)" == "SnortSam - Win32 Release"

# PROP Exclude_From_Build 1
# ADD BASE CPP /w /W0
# ADD CPP /w /W0

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release OPSEC"

# PROP Exclude_From_Build 1
# ADD BASE CPP /w /W0
# ADD CPP /w /W0

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2002"

# ADD BASE CPP /w /W0
# ADD CPP /w /W0

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2004"

# PROP Exclude_From_Build 1
# ADD BASE CPP /w /W0
# ADD CPP /w /W0

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug"

# PROP Exclude_From_Build 1
# ADD BASE CPP /w /W0
# ADD CPP /w /W0

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug OPSEC"

# PROP Exclude_From_Build 1
# ADD BASE CPP /w /W0
# ADD CPP /w /W0

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2002"

# ADD BASE CPP /w /W0
# ADD CPP /w /W0

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2004"

# PROP Exclude_From_Build 1
# ADD BASE CPP /w /W0
# ADD CPP /w /W0

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ssp_isa2004.cpp

!IF  "$(CFG)" == "SnortSam - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release OPSEC"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2002"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2004"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug OPSEC"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2002"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2004"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ssp_netscreen.c
# End Source File
# Begin Source File

SOURCE=.\ssp_opsec.c

!IF  "$(CFG)" == "SnortSam - Win32 Release"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release OPSEC"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2002"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2004"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug OPSEC"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2002"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2004"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ssp_pix.c
# End Source File
# Begin Source File

SOURCE=.\ssp_snmp_interface_down.c
# End Source File
# Begin Source File

SOURCE=.\ssp_wgrd.c
# End Source File
# Begin Source File

SOURCE=.\twofish.c
# End Source File
# Begin Source File

SOURCE=.\win32_service.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\plugins.h
# End Source File
# Begin Source File

SOURCE=.\snortsam.h
# End Source File
# Begin Source File

SOURCE=.\ssp_8signs.h
# End Source File
# Begin Source File

SOURCE=.\ssp_chxi.h
# End Source File
# Begin Source File

SOURCE=.\ssp_cisco_nullroute.h
# End Source File
# Begin Source File

SOURCE=.\ssp_cisco_nullroute2.h
# End Source File
# Begin Source File

SOURCE=.\ssp_ciscoacl.h
# End Source File
# Begin Source File

SOURCE=.\ssp_email.h
# End Source File
# Begin Source File

SOURCE=.\ssp_forward.h
# End Source File
# Begin Source File

SOURCE=.\ssp_fwexec.h
# End Source File
# Begin Source File

SOURCE=.\ssp_fwsam.h
# End Source File
# Begin Source File

SOURCE=.\ssp_isa.h

!IF  "$(CFG)" == "SnortSam - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release OPSEC"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2002"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2004"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug OPSEC"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2002"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2004"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ssp_isa2004.h

!IF  "$(CFG)" == "SnortSam - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release OPSEC"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2002"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2004"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug OPSEC"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2002"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2004"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ssp_netscreen.h
# End Source File
# Begin Source File

SOURCE=.\ssp_opsec.h

!IF  "$(CFG)" == "SnortSam - Win32 Release"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release OPSEC"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2002"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Release ISA2004"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug OPSEC"

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2002"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SnortSam - Win32 Debug ISA2004"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ssp_pix.h
# End Source File
# Begin Source File

SOURCE=.\ssp_snmp_interface_down.h
# End Source File
# Begin Source File

SOURCE=.\ssp_wgrd.h
# End Source File
# Begin Source File

SOURCE=.\twofish.h
# End Source File
# Begin Source File

SOURCE=.\win32_service.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
