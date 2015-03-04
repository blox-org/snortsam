/* $Id: ssp_snmp_interface_down.c,v 2.3 2009/11/27 01:39:40 fknobbe Exp $
 *
 * Copyright (c) 2005-2008 Ali BASEL <ali@basel.name.tr>
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
 * ssp_snmp_interface_shutdown.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin calls the trackersnmp program of the tracker(http://www.basel.name.tr) to
 * shutdown the switch ports of the local intruders to block the IP addresses.
 *
 */

#ifndef		__SSP_SNMPINTERFACEDOWN_C__
#define		__SSP_SNMPINTERFACEDOWN_C__


#include "snortsam.h"
#include "ssp_snmp_interface_down.h"


#include <stdio.h>
#include <string.h>


/* Parsing config options
*/
void SNMPINTERFACEDOWNParse(char *val, char *file, unsigned long line, DATALIST *plugindatalist)
{	
	char *p2,msg[STRBUFSIZE+2];
	
	SNMPINTERFACEDOWNDATA *snmpinterfacedownp=NULL;

#ifdef FWSAMDEBUG
	printf("Debug: [snmp_interface_down] Plugin Parsing...\n");
#endif
    
	/* Allocate data structure */
	snmpinterfacedownp=(SNMPINTERFACEDOWNDATA *)safemalloc(sizeof(SNMPINTERFACEDOWNDATA),"SNMPDOWNParse","snmpinterfacedownp");
	plugindatalist->data=snmpinterfacedownp;
	snmpinterfacedownp->trackersnmppath[0]=0; /* Set defaults */
	snmpinterfacedownp->logflag=FALSE;
	
	while(*val)	/* cycle through the line options */
	{	p2=val;
		while(*p2 && !myisspace(*p2))
			p2++;
		if(*p2) 
			*p2++ =0;

		if(!stricmp(val,"log"))	/* If the option is log, we set the logging flag */
			snmpinterfacedownp->logflag=TRUE;
		else
			safecopy(snmpinterfacedownp->trackersnmppath, val); /* Otherwise is should be the path to fltcon.exe */
		
		val=p2;
		while(*val && myisspace(*val)) /* skip over spaces */
			val++;
	}
	if(*(snmpinterfacedownp->trackersnmppath))
	{	snprintf(msg,sizeof(msg)-1,"snmp_interface_down: Will call '%s' to initiate blocks%s.",snmpinterfacedownp->trackersnmppath, snmpinterfacedownp->logflag?" with logging":"");
		logmessage(3,msg,"snmp_interface_down",0);
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Warning: [%s: %lu] No trackersnmp executable specified. Using just \"trackersnmp\" by default (and hope it's in the path...)",file,line);
		safecopy(snmpinterfacedownp->trackersnmppath,"trackersnmp");
		logmessage(2,msg,"snmp_interface_down",0);
	}
}


/* This routine initiates the block by calling trackersnmp
*/
void SNMPINTERFACEDOWNBlock(BLOCKINFO *bd,void *data,unsigned long qp)
{	
	char cmd[STRBUFSIZE+2],msg[STRBUFSIZE+2];
	const char pref[]="ldap do nostdout host scanner.sabanciuniv.edu to netadmin@scanner.sabanciuniv.edu ";
/* #ifdef FWSAMDEBUG
	unsigned long threadid=GetCurrentThreadId();
#endif
*/
	SNMPINTERFACEDOWNDATA *snmpinterfacedownp;
	
	if(!data) return;
	snmpinterfacedownp=(SNMPINTERFACEDOWNDATA *)data;
	
	if(bd->block) {	
		snprintf(cmd,sizeof(cmd)-1,"%s %s %s shut", snmpinterfacedownp->trackersnmppath, inettoa(bd->blockip), pref);
		logmessage(2, cmd, "snmp_interface_down",0);	
/*		#ifdef FWSAMDEBUG
		printf("Debug: [snmp_interface_down][%lx] Calling: %s\n", threadid, cmd);
		#endif
*/
		/* Run the command */
                if( system(cmd) ) {
			snprintf(msg,sizeof(msg)-1,"Error: Command \"%s\" Failed", cmd);
                        logmessage(1,msg,"snmpinterfacedown",0);
                }
                else {
			snprintf(msg,sizeof(msg)-1,"Info: Command \"%s\" Executed Successfully", cmd);
                        logmessage(1, msg, "snmpinterfacedown",0);
                }
	}
	else {
		snprintf(cmd,sizeof(cmd)-1,"%s %s %s noshut", snmpinterfacedownp->trackersnmppath, inettoa(bd->blockip), pref);
                logmessage(2, cmd, "snmp_interface_down",0);  
		/* Run the command */
                if( system(cmd) ) {
			snprintf(msg,sizeof(msg)-1,"Error: Command \"%s\" Failed", cmd);
                        logmessage(1, msg, "snmpinterfacedown", 0);
                }
                else {
			snprintf(msg,sizeof(msg)-1,"Info: Command \"%s\" Executed Successfully", cmd);
                        logmessage(1, msg, "snmpinterfacedown", 0);
                }	
	}
}

#endif /* __SSP_SNMPINTERFACEDOWN_C__ */
