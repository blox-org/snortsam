/* $Id: plugins.h,v 2.54 2009/11/27 01:39:39 fknobbe Exp $
 *
 *
 * Copyright (c) 2001-2008 Frank Knobbe <frank@knobbe.us>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 * This file contains the plugins registry.
 *
 */


#ifndef		__PLUGINS_H__
#define		__PLUGINS_H__


#include "snortsam.h"

#if 0
#include "ssp_opsec.h"
#include "ssp_fwexec.h"
#include "ssp_fwsam.h"
#include "ssp_pix.h"
#include "ssp_ciscoacl.h"
#include "ssp_cisco_nullroute.h"
#include "ssp_cisco_nullroute2.h"
#endif
#include "ssp_email.h"
#if 0
#include "ssp_netscreen.h"
#include "ssp_ipf.h"
#include "ssp_pf.h"
#include "ssp_pf2.h"
#include "ssp_ipchains.h"
#endif
#include "ssp_iptables.h"
#include "ssp_ebtables.h"
#if 0
#include "ssp_wgrd.h"
#include "ssp_8signs.h"
#include "ssp_isa.h"
#include "ssp_isa2004.h"
#include "ssp_chxi.h"
#include "ssp_ipfw2.h"
#include "ssp_snmp_interface_down.h"
#include "ssp_forward.h"
#endif

#define TH_NONE			0		/* Threading model: See below for more info */
#define TH_SINGLE		1
#define TH_MULTI		2


typedef struct _plugins
{	int (*PluginInit)(DATALIST *);			/* Pointer to init routine, or NULL if not needed */
	void (*PluginConfigParse)(char *,		/* Pointer to config file parsing routine, or NULL if not needed */
		  char *,unsigned long,
		  DATALIST *);
	void (*PluginBlock)(BLOCKINFO *,		/* Pointer to blocking routine, or NULL if not needed (huh?) */
		  void *,unsigned long);				
	void (*PluginExit)(DATALIST *);			/* Pointer to exit routine, or NULL if not needed */
	void (*PluginKeepAlive)(DATALIST *);	/* Pointer to keep-alive routing for support of persistent connections to firewalls */
	int PluginNeedsExpiration;				/* Set this to TRUE, if SnortSam needs to expire the block */
	int PluginDoesReblockOnSignal;			/* Set this to FALSE to avoid blocking again on USR1 reload (for forward and email) */
	int PluginThreading;					/* Set this to TH_MULTI, TH_SINGLE, TH_NONE. */
	char PluginHandle[40];					/* Short handle, used in config file */
	char PluginAuthor[100];					/* Your name here (or "" if not used) */
	char PluginVersion[30];					/* Version of your plugin (or "" if not used) */
} PLUGINREGISTRY;

/* 
PluginInit:				A function SnortSam calls when it encounters a plugin in the 
						configuration file. The function returns either TRUE or FALSE,
						indicating a successful or unsuccessful initialization. If functions 
						returns FALSE, SnortSam will disable the plugin.
						The parameter is a pointer to the first element in the device/parameter list.
						(Plugin may use it at it's own discretion)

PluginConfigParse:		A function SnortSam calls on every configuration line for the plugin.
						The first parameter is the config line. The second parameter is the
						config file name itself, the third parameter is the line number.
						(the last two are useful for logging purposes.)
						The third parameter is a pointer to a device/parameter structure (not the list).
						If the plugin allocates it, SnortSam will link it into the list for you.

PluginBlock:			A function SnortSam calls when it needs to block an IP address.
						The first parameter is a pointer to the BLOCKINFO struct which contains
						the IP address, port, protocol, etc and also the flag for block or unblock.
						The second parameter is a pointer to a device/parameter structure (not the list).

PluginExit:				A function SnortSam calls when it terminates. This gives the plugin a 
						chance to clean itself up before exiting.
						The parameter is a pointer to the device/parameter list if the plugin uses one.
						(If not, it would still be NULL).
						NOTE: The plugin does not need to free the elements itself anymore. Snortsam will
						free the elements and clean up the chain itself. The parameter is provided for final
						communication to devices if the plugin needs to perform this.

PluginKeepAlive:		This function is called during "keepalive" intervals in order to maintain an external
                        connection with the given plugin device (ie router). This was added in preparation for
                        persistent TCP connections to telnet based firewalls/routers in order to avoid frequent
                        login/logout sequences. Not implemented in any plugin yet.

PluginNeedsExpiration:	This can be set to TRUE if SnortSam has to time-out the blocks.
						Can be set to FALSE if the firewall will time-out itself.
						If set to TRUE, SnortSam will keep track of blocks and even create
						a state file so that timeouts/unblocks can be processed even if
						SnortSam is restarted.
						
PluginReblockOnSignal:  Most plugins (all firewalls) can be reloaded with USR1 which causes block from the
                        statefile to be blocked again. However, "forward" should not forward blocks on reload,
                        and emails would also cause a flood. Thus these to don't need to act on reload.
					    With this flag at FALSE, the plugin can avoid to be called on USR1 reloads. *

PluginThreading:		This can be set to TH_MULTI if the plugin can be executed more than once (for multiple
						firewalls) and can run simultaneously, and is capable if being launched in separate
						threads. The plugin will be launched in parallel with other plugins, and with other
						instances of itself. If the plugin is capable of multithreading, but should only contact
						its own devices sequentially, set this flag to TH_SINGLE. This plugin will then be
						executed in parallel to the other plugins, but it will only process one device at a time.
						If the plugin has problems with threads, set this flag to TH_NONE. In that case SnortSam
						will not launch it in its own thread(s), but run it inline the main thread/process.
						Currently, the OPSEC plugin suffers from this and has to be run that way.
					
PluginHandle:			Short text handle. This is used in config files to pass the config line
						on to the plugin.

PluginAuthor:			The name entered here is listed on startup of SnortSam.

PluginVersion:			The version entered here is listed on startup of SnortSam.

*/

PLUGINREGISTRY Plugins[]={
#if 0
/* ------------------------------------------------------------ */
/* Native FW-Sam plugin (self assembled packet) */
{	NULL,
	FWSamParse,
	FWSamBlock,
	NULL,
	NULL,
	FALSE,
	TRUE,
	TH_MULTI,
	"fwsam",
	"Frank Knobbe",
	"2.5"
},
/* ------------------------------------------------------------ */
/* Old fwexec, now plugin */
{	NULL,
	FWExecParse,
	FWExecBlock,
	NULL,
	NULL,
	FALSE,
	TRUE,
	TH_SINGLE,
	"fwexec",
	"Frank Knobbe",
	"2.7"
},
/* ------------------------------------------------------------ */
/* OPSEC compliant plugin */
#ifdef ENABLE_OPSEC
{	NULL,
	OPSEC_Parse,
	OPSEC_Block,
	NULL,
	NULL,
	FALSE,
	TRUE,
	TH_NONE,
	"opsec",
	"Frank Knobbe",
	"2.6"
},
#endif
/* ------------------------------------------------------------ */
/* PIX Plugin (using the SHUN command) */
{	NULL,
	PIXParse,
	PIXBlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_MULTI,
	"pix",
	"Frank Knobbe",
	"2.9"
},
/* ------------------------------------------------------------ */
/* CISCO ACL Plugin  */
{	NULL,
	CISCOACLParse,
	CISCOACLBlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_SINGLE,
	"ciscoacl",
	"Ali Basel <alib@sabanciuniv.edu>",
	"2.12"
},
/* ------------------------------------------------------------ */
/* Cisco Null Route Plugin  */
{	NULL,
	CiscoNullRouteParse,
	CiscoNullRouteBlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_MULTI,
	"cisconullroute",
	"Frank Knobbe",
	"2.5"
},
/* ------------------------------------------------------------ */
/* Cisco Null Route2 Plugin  */
{	NULL,
	CiscoNullRoute2Parse,
	CiscoNullRoute2Block,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_MULTI,
	"cisconullroute2",
	"Wouter de Jong <maddog2k@maddog2k.net>",
	"2.2"
},
/* ------------------------------------------------------------ */
/* Netscreen Plugin (deny-group) */
{	NULL,
	NetScrnParse,
	NetScrnBlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_MULTI,
	"netscreen",
	"Frank Knobbe",
	"2.10"
},
#endif
/* ------------------------------------------------------------ */
#if !defined(WIN32) && !defined(Linux) && !defined(OpenBSD)
/* IPFilter Plugin */
{	NULL,
	IPFParse,
	IPFBlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_SINGLE,
	"ipf",
	"Erik Sneep <erik@webflex.nl>",
	"2.16"
},
#endif
#if 0
/* ------------------------------------------------------------ */
#ifdef USE_SSP_PF	
#if defined(OpenBSD) || defined(FreeBSD) || defined(NetBSD)
/* PF Plugin */
{	NULL,
	PFParse,
	PFBlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_SINGLE,
	"pf",
	"Hector Paterno <apaterno@dsnsecurity.com>",
 	"3.6"
},
#endif
#endif /* USE_SSP_PF */
/* ------------------------------------------------------------ */
#ifndef USE_SSP_PF
#if defined(OpenBSD) || defined(FreeBSD) || defined(NetBSD)
/* PF2 Plugin */
{     NULL,
      PF2Parse,
      PF2Block,
      NULL,
      NULL,
      TRUE,
      TRUE,
      TH_SINGLE,
      "pf2",
      "Olaf Schreck <chakl@syscall.de>",
      "3.3"
},
#endif
#endif  /* !USE_SSP_PF */
/* ------------------------------------------------------------ */
#ifdef FreeBSD
/* IPFW2 Plugin */
{	NULL,
	IPFW2Parse,
	IPFW2Block,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_SINGLE,
	"ipfw2",
	"Robert Rolfe <rob@wehostwebpages.com>",
 	"2.4"
},
#endif
#endif
/* ------------------------------------------------------------ */
#ifdef Linux
#if 0
/* Ipchains Plugin */
{	NULL,
	IPCHParse,
	IPCHBlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_SINGLE,
	"ipchains",
	"Hector A. Paterno <apaterno@dsnsecurity.com>",
	"2.8"
},
#endif
/* ------------------------------------------------------------ */
/* Iptables Plugin */
{	NULL,
	IPTParse, 
	IPTBlock,   
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_SINGLE, 
	"iptables",
	"Fabrizio Tivano <fabrizio@sad.it>, Luis Marichal <luismarichal@gmail.com>",
	"2.9"
},
/* ------------------------------------------------------------ */
/* EBtables Plugin */
{	NULL,
	EBTParse,
	EBTBlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_SINGLE, 
	"ebtables",
	"Bruno Scatolin <ipsystems@uol.com.br>",
	"2.4"
},
#endif
#if 0
/* ------------------------------------------------------------ */
/* Watchguard plugin */
{	NULL,
	WGRDParse,
	WGRDBlock,
	NULL,
	NULL,
	FALSE,
	TRUE,
	TH_MULTI,
	"watchguard",
	"Thomas Maier <thomas.maier@arcos.de>",
	"2.7"
},
/* ------------------------------------------------------------ */
#ifdef WIN32
/* 8signs plugin */
{	NULL,
	DFWParse,
	DFWBlock,
	NULL,
	NULL,
	TRUE,		/* Actually FALSE since it can expire itself. But it only... */
	TRUE,		/* ...takes day, week, or forever, so we just time-out ourselves. */
	TH_SINGLE,	
	"8signs",
	"Frank Knobbe"
	"2.3"
},
/* ------------------------------------------------------------ */
/* CHX-I plugin */
{	NULL,
	CHXIParse,
	CHXIBlock,
	NULL,
	NULL,
	FALSE,
	TRUE,
	TH_SINGLE,
	"chx-i",
	"Frank Knobbe"
	"2.4"
},
/* ------------------------------------------------------------ */
#ifdef WITH_ISA2002
/* Microsoft ISA Server plugin */
{	NULL,
	ISAParse,
	ISABlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_NONE,	/* Maybe single. (COM interfaces calling restrictions) */
	"isa",
	"Nima Sharifi Mehr <nimahacker@yahoo.com>",
	"2.4"
},
#endif
/* ------------------------------------------------------------ */
#ifdef WITH_ISA2004
/* Microsoft ISA 2004 Server plugin */
{	NULL,
	ISAParse2004,
	ISABlock2004,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_NONE,	/* Maybe single. (COM interfaces calling restrictions) */
	"isa2004",
	"Mark P Clift <mark_clift@yahoo.com>",
	"2.2"
},
#endif
#endif /* WIN32 */
#endif
/* ------------------------------------------------------------ */
/* Email Notifcation plugin */
{	NULL,
	EmailParse,
	EmailSend,
	NULL,
	NULL,
	TRUE,
	FALSE,
	TH_MULTI,
	"email",
	"Frank Knobbe",
	"2.12"
},/* ------------------------------------------------------------ */
/* Email Block only Notifcation plugin */
{	NULL,
	EmailParse,
	EmailSendBlockOnly,
	NULL,
	NULL,
	FALSE,
	FALSE,
	TH_MULTI,
	"email-blocks-only",
	"Frank Knobbe",
	"2.12"
},
/* ------------------------------------------------------------ */
#if 0
/* SNMP Interface Down plugin */
{	NULL,
	SNMPINTERFACEDOWNParse,
	SNMPINTERFACEDOWNBlock,
	NULL,
	NULL,
	TRUE,
	TRUE,
	TH_SINGLE,
	"snmpinterfacedown",
	"Ali BASEL <ali@basel.name.tr>",
	"2.3"
},
/* ------------------------------------------------------------ */
/* Forwarder plugin */
{	NULL,
	ForwardParse,
	ForwardBlock,
	ForwardExit,
	NULL,
	FALSE,
	FALSE,
	TH_MULTI,
	"forward",
	"Frank Knobbe",
	"2.8"
}/* ------------------------------------------------------------ */
#endif
/* add other plugins here */
};


#endif /* __PLUGINS_H__ */
