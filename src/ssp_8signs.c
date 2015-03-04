/* $Id: ssp_8signs.c,v 2.3 2008/04/26 19:53:21 fknobbe Exp $
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
 * ssp_8signs.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin calls the dfw.exe program of the 8Signs firewall to
 * block/unblock IP addresses.
 *
 */

#if defined(WIN32)

#ifndef		__SSP_8SIGNS_C__
#define		__SSP_8SIGNS_C__


#include "snortsam.h"
#include "ssp_8signs.h"

#include <stdio.h>
#include <string.h>


/* Parsing config options
*/
void DFWParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	char *filename,*p2,msg[STRBUFSIZE+2];

#ifdef FWSAMDEBUG
	printf("Debug: [8signs] Plugin Parsing...\n");
#endif
    
	if(*val)
	{	p2=val;
		while(*p2 && !myisspace(*p2))
			p2++;
		if(*p2) 
			*p2++ =0;
		filename=safemalloc(strlen(val)+2,"DFWParse","filename");
		strcpy(filename+1,val);	/* save exectuable path/name */
		*filename='n';				/* Flag for NO TARPIT */
		plugindatalist->data=filename;
			
		if(*p2)
		{	val=p2;
			while(*val && myisspace(*val))	/* now parse the remaining text */
				val++;
			if(val)					/* if there's more, it should be tar */
			{	p2=val;
				while(*p2 && !myisspace(*p2))
					p2++;
				*p2=0;
				if(!stricmp(val,"tarpit"))
					*filename='t';
			}
		}
						
		snprintf(msg,sizeof(msg)-1,"8signs: Will call '%s' to initiate blocks%s.",filename+1, *filename=='t'?" with tarpit":"");
		logmessage(3,msg,"8signs",0);
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] No dfw.exe executable specified.",file,line);
		logmessage(1,msg,"8signs",0);
	}
}


/* This routine initiates the block by calling dfw.exe.
*/
void DFWBlock(BLOCKINFO *bd,void *data,unsigned long qp)
{	char cmd[STRBUFSIZE+2],*filename;
	const char pref[]="start /low /min ";
#ifdef FWSAMDEBUG
	unsigned long threadid=GetCurrentThreadId();
#endif

	if(!data)
		return;
	filename=(char *)data;
	
	if(bd->block)	
		snprintf(cmd,sizeof(cmd)-1,"%s%s -ban %s -expiry n %s -reason \"Blocked by Snort SID %lu\"",pref,filename+1,inettoa(bd->blockip),*filename=='t'?"-tarpit":"",bd->sig_id);
	else
		snprintf(cmd,sizeof(cmd)-1,"%s%s -unban %s",pref,filename+1,inettoa(bd->blockip));

#ifdef FWSAMDEBUG
	printf("Debug: [8signs][%lx] Calling: %s\n",threadid,cmd);
#endif

	system(cmd);		/* or maybe use spawnlp */
}


#endif /* __SSP_8SIGNS_C__ */
#endif /* WIN32 */
