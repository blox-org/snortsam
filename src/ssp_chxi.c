/* $Id: ssp_chxi.c,v 2.4 2009/11/27 01:39:40 fknobbe Exp $
 *
 *
 * Copyright (c) 2004-2008 Frank Knobbe <frank@knobbe.us>
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
 * ssp_chxi.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin calls the fltcon.exe program of the CHX-I firewall to
 * block IP addresses.
 *
 */

#if defined(WIN32)

#ifndef		__SSP_CHXI_C__
#define		__SSP_CHXI_C__


#include "snortsam.h"
#include "ssp_chxi.h"

#include <stdio.h>
#include <string.h>


/* Parsing config options
*/
void CHXIParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	char *p2,msg[STRBUFSIZE+2];
	CHXIDATA *chxip=NULL;

#ifdef FWSAMDEBUG
	printf("Debug: [chx-i] Plugin Parsing...\n");
#endif
    
    chxip=(CHXIDATA *)safemalloc(sizeof(CHXIDATA),"CHXIParse","chxip");		/* Allocate data structure */
	plugindatalist->data=chxip;
	chxip->fltconpath[0]=0;			/* Set defaults */
	chxip->logflag=FALSE;
	
	while(*val)		/* cycle through the line options */
	{	p2=val;
		while(*p2 && !myisspace(*p2))
			p2++;
		if(*p2) 
			*p2++ =0;

		if(!stricmp(val,"log"))		/* If the option is log, we set the logging flag */
			chxip->logflag=TRUE;
		else
			safecopy(chxip->fltconpath,val); /* Otherwise is should be the path to fltcon.exe */
		
		val=p2;
		while(*val && myisspace(*val)) /* skip over spaces */
			val++;
	}
	if(*(chxip->fltconpath))
	{	snprintf(msg,sizeof(msg)-1,"chx-i: Will call '%s' to initiate blocks%s.",chxip->fltconpath, chxip->logflag?" with logging":"");
		logmessage(3,msg,"chx-i",0);
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Warning: [%s: %lu] No fltcon.exe executable specified. Using just \"fltcon\" by default (and hope it's in the path...)",file,line);
		safecopy(chxip->fltconpath,"fltcon");
		logmessage(2,msg,"chx-i",0);
	}
}


/* This routine initiates the block by calling fltcon
*/
void CHXIBlock(BLOCKINFO *bd,void *data,unsigned long qp)
{	char cmd[STRBUFSIZE+2],msg[STRBUFSIZE+2];
	CHXIDATA *chxip;
	const char pref[]="start /low /min ";
#ifdef FWSAMDEBUG
	unsigned long threadid=GetCurrentThreadId();
#endif

	if(!data)
		return;
	chxip=(CHXIDATA *)data;
	
	if(bd->block)	
	{	switch(bd->mode&FWSAM_HOW)
		{	case FWSAM_HOW_IN:		snprintf(cmd,sizeof(cmd)-1,"%s%s /ADD /T %lu /PY %i /DIR 0 /SA %s /A 1%s",pref,chxip->fltconpath,bd->duration,CHXI_PRIORITY,inettoa(bd->blockip),chxip->logflag?" /L":"");

#ifdef FWSAMDEBUG
									printf("Debug: [chx-i][%lx] Calling: %s\n",threadid,cmd);
#endif
									system(cmd);
									break;

			case FWSAM_HOW_INOUT: 	; 	
			default:				snprintf(cmd,sizeof(cmd)-1,"%s%s /ADD /T %lu /PY %i /DIR 0 /SA %s /A 1%s",pref,chxip->fltconpath,bd->duration,CHXI_PRIORITY,inettoa(bd->blockip),chxip->logflag?" /L":"");
			
#ifdef FWSAMDEBUG
									printf("Debug: [chx-i][%lx] Calling: %s\n",threadid,cmd);
#endif
									system(cmd);

			case FWSAM_HOW_OUT:		snprintf(cmd,sizeof(cmd)-1,"%s%s /ADD /T %lu /PY %i /DIR 1 /DA %s /A 1%s",pref,chxip->fltconpath,bd->duration,CHXI_PRIORITY,inettoa(bd->blockip),chxip->logflag?" /L":"");

#ifdef FWSAMDEBUG
									printf("Debug: [chx-i][%lx] Calling: %s\n",threadid,cmd);
#endif
									system(cmd);
									break;
			case FWSAM_HOW_THIS:	snprintf(cmd,sizeof(cmd)-1,"%s%s /ADD /T %lu /PY %i /SA %s /DA %s /P %u /DP %u /A 1%s",pref,chxip->fltconpath,bd->duration,CHXI_PRIORITY,inettoa(bd->blockip),inettoa(bd->peerip),bd->proto,bd->port,chxip->logflag?" /L":"");

#ifdef FWSAMDEBUG
									printf("Debug: [chx-i][%lx] Calling: %s\n",threadid,cmd);
#endif
									system(cmd);
									break;
		}
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Info: Currently, the CHX-I plugin does not forcefully unblock. To clear hosts that are added to a whitelist, please restart the CHX-I service which will clear all temporary blocks.");
		logmessage(3,msg,"chx-i",0);
	}
}


#endif /* __SSP_CHXI_C__ */
#endif /* WIN32 */
