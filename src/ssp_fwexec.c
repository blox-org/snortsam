/* $Id: ssp_fwexec.c,v 2.7 2008/04/26 19:53:21 fknobbe Exp $
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
 * ssp_fwexec.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin calls the fw.exe program of Firewall-1 to block/unblock.
 * (This used to be a built-in function but has now been moved to a plugin as
 * an example for other executable plugins. Hopefully this will be wrapped into
 * a generic script wrapper at some time.)
 *
 */


#ifndef		__SSP_FWEXEC_C__
#define		__SSP_FWEXEC_C__


#include "snortsam.h"
#include "ssp_fwexec.h"

#include <stdio.h>
#include <string.h>


/* This routine parses the fwexec statement in the config file.
*/
void FWExecParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	char *filename,msg[STRBUFSIZE+2];
	int len;

#ifdef FWSAMDEBUG
	printf("Debug: [fwexec] Plugin Parsing...\n");
#endif
    
	if(*val)
	{	len=strlen(val);
		filename=safemalloc(len+1,"FWExecParse","filename");
		strncpy(filename,val,len);
		filename[len]=0;
		plugindatalist->data=filename;
		snprintf(msg,sizeof(msg)-1,"fwexec: Will call '%s' to initiate blocks.",filename);
		logmessage(3,msg,"fwexec",0);
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] No fw.exe executable specified.",file,line);
		logmessage(1,msg,"fwexec",0);
	}
}

/* This routine initiates the block by calling fw.exe.
*/
void FWExecBlock(BLOCKINFO *bd,void *fwexec,unsigned long qp)
{	char cmd[STRBUFSIZE+2],dura[32];
#ifdef WIN32
	const char pref[]="start /low /min ";
#else
	const char pref[]="";
#endif
#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif
#endif

	if(!fwexec)
		return;

	*dura=0;
	if(bd->duration>0)
		snprintf(dura,sizeof(dura)-1,"-t %lu ",(unsigned long)bd->duration);

	switch(bd->mode&FWSAM_HOW)
	{	case FWSAM_HOW_INOUT:	
			snprintf(cmd,sizeof(cmd)-1,"%s%s sam %s%s-I any %s",pref,(char *)fwexec,bd->block?"":"-C ",dura,inettoa(bd->blockip));
			break;
		case FWSAM_HOW_IN:
			snprintf(cmd,sizeof(cmd)-1,"%s%s sam %s%s-I src %s",pref,(char *)fwexec,bd->block?"":"-C ",dura,inettoa(bd->blockip));
			break;
		case FWSAM_HOW_OUT:
			snprintf(cmd,sizeof(cmd)-1,"%s%s sam %s%s-I dst %s",pref,(char *)fwexec,bd->block?"":"-C ",dura,inettoa(bd->blockip));
			break;
		case FWSAM_HOW_THIS:
			snprintf(cmd,sizeof(cmd)-1,"%s%s sam %s%s-I srv %s %s %u %u",pref,(char *)fwexec,bd->block?"":"-C ",dura,inettoa(bd->blockip),inettoa(bd->peerip),bd->port,bd->proto);
			break;
	}

#ifdef FWSAMDEBUG
	printf("Debug: [fwexec][%lx] Calling: %s\n",(unsigned long)threadid,cmd);
#endif

	system(cmd);		/* or maybe use spawnlp */
}


#endif /* __SSP_FWEXEC_C__ */






