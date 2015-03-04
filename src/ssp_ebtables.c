/* $Id: ssp_ebtables.c,v 2.4 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2003-2008 Fabrizio Tivano <fabrizio@sad.it>, 
 *                    Bruno Scatolin <ipsystems@uol.com.br>
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
 * ssp_ebtables.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin is meant for dynamic (un)blocking on ebtables firewall,
 * SnortSam will expire the blocks itself with  automatic time-out functionality.
 *
 * The plugin for ebtables, created by Bruno, is based on the iptables plugin
 * created by Fabrizio.
 *
 *
 *
 *
 */


#ifdef	Linux

#ifndef		__SSP_EBT_C__
#define		__SSP_EBT_C__

#include "snortsam.h"
#include "ssp_ebtables.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* Set this if you want IP tables to save the tables after every (un)block. */

#define SAVETABLES



/* This routine parses the ipf statements in the config file.
*/
void EBTParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	EBTDATA *ebtp=NULL;
	char *p2, msg[STRBUFSIZE+2];

#ifdef FWSAMDEBUG
	printf("Debug: [ebtables] Plugin Parsing...\n");
#endif

	if(*val)
	{	p2=val;
		while(*p2 && !myisspace(*p2)) p2++;
		if(*p2) *p2++ =0;
		ebtp=safemalloc(sizeof(EBTDATA),"EBTParse","ebtp");
		plugindatalist->data=ebtp;
		safecopy(ebtp->iface,val);	/* save interface */
					
		if(*p2)	/* if we have a loglevel defined */
		{	while(*p2 && myisspace(*p2)) p2++;
			safecopy(ebtp->loglv,p2); 		/* loglevel defined */
		} else {
			safecopy(ebtp->loglv,EBTLOGLEVEL); 	/* use default loglevel */
		}

#ifdef FWSAMDEBUG
		printf("Debug: [ebtables] Adding EBTABLES: interface \"%s\", loglevel \"%s\"\n", ebtp->iface, ebtp->loglv);
#endif

	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] EBTABLES defined without parameters!",file,line);
		logmessage(1,msg,"ebtables",0);
	}
}


/* This routine initiates the block. 
 */
void EBTBlock(BLOCKINFO *bd,void *data,unsigned long qp)
{   EBTDATA *ebtp;
	char ebtcmd[255], msg[STRBUFSIZE+2];
#ifdef SAVETABLES
	const char savecmd[]="/sbin/ebtables --atomic-file /etc/ebtables.conf --atomic-save";
#endif

#ifdef FWSAMDEBUG
	pthread_t threadid=pthread_self();
#endif

	if(!data) return;
		ebtp=(EBTDATA *)data;

#ifdef FWSAMDEBUG
	printf("Debug: [ebtables][%lx] Plugin Blocking...\n",threadid);
#endif

	if(bd->block)
	{ snprintf(msg,sizeof(msg)-1,"Info: Blocking ip %s", inettoa(bd->blockip));
	  logmessage(3,msg,"ebtables",0);

	  /* Assemble command */
	  if (snprintf(ebtcmd,sizeof(ebtcmd)-1,
		"/sbin/ebtables -A FORWARD -p IPv4 -i %s --ip-src %s -j DROP",
 		ebtp->iface, inettoa(bd->blockip)) >= sizeof(ebtcmd)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", ebtcmd);
                logmessage(1,msg,"ebtables",0);
		return;
          }
	} else {
	  snprintf(msg,sizeof(msg)-1,"Info: UnBlocking ip %s", inettoa(bd->blockip));
	  logmessage(1,msg,"ebtables",0);

          /* Assemble command */
          if (snprintf(ebtcmd,sizeof(ebtcmd)-1,
		"/sbin/ebtables -D FORWARD -p IPv4 -i %s --ip-src %s -j DROP",
	  	ebtp->iface, inettoa(bd->blockip)) >= sizeof(ebtcmd)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", ebtcmd);
                logmessage(1,msg,"ebtables",0);
		return;
          }
	}
#ifdef FWSAMDEBUG
        printf("Debug: [ebtables][%lx] command  %s\n", threadid, ebtcmd);
#endif
	/* Run the command */
        if (system(ebtcmd) != 0) { 
		snprintf(msg,sizeof(msg)-1,"Error: Command %s Failed", ebtcmd);
		logmessage(3,msg,"ebtables",0);
	} else {
                snprintf(msg,sizeof(msg)-1,"Info: Command %s Executed Successfully", ebtcmd);
                logmessage(3,msg,"ebtables",0);
	}


#ifdef SAVETABLES
/* Save command */    
        if (system(savecmd) != 0) {
            snprintf(msg,sizeof(msg)-1,"Error: Save command %s Failed",savecmd);
         logmessage(1,msg,"ebtables",0);
 } else {
                snprintf(msg,sizeof(msg)-1,"Info: Save command %s Executed Successfully", savecmd);
                logmessage(3,msg,"ebtables",0);
 }
#endif

	return;
}

#endif /* __SSP_EBT_C__ */
#endif /* Linux */

