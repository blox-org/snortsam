/* $Id: ssp_ipfw2.c,v 2.4 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2005-2008 Robert Rolfe <rob@wehostwebpages.com>, Frank Knobbe <frank@knobbe.us>
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
 * ssp_ipfw2.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin is meant for dynamic blocking on IPFW2 firewalls.
 * SnortSam will expire the blocks itself since IPFW2 does not have 
 * automatic time-out functionality.
 *
 */


#if defined(FreeBSD)

#ifndef		__SSP_IPFW2_C__
#define		__SSP_IPFW2_C__

#include "snortsam.h"
#include "ssp_ipfw2.h"


#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* This routine parses the ipf statements in the config file.
*/
void IPFW2Parse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	IPFW2DATA *ipfw2p=NULL;
	char *p2,msg[STRBUFSIZE+2],chk[STRBUFSIZE+2];
	
#ifdef FWSAMDEBUG
	printf("Debug: [ipfw2] Plugin Parsing...\n");
#endif

	if(*val)
	{	p2=val;
		while(*p2 && !myisspace(*p2)) p2++;
		if(*p2) *p2++ =0;
		ipfw2p=safemalloc(sizeof(IPFW2DATA),"IPFW2Parse","ipfw2p");
		plugindatalist->data=ipfw2p;
		safecopy(ipfw2p->interface,val);	/* save interface */
		ipfw2p->in_table=1;					/* Setting defaults for the tables */
		ipfw2p->out_table=2;
		if(*p2)
		{	while(*p2 && myisspace(*p2)) p2++;
			if(*p2)
			{	val=p2;
				while(*p2 && !myisspace(*p2)) p2++;
				if(*p2) *p2++ =0;
				ipfw2p->in_table=(unsigned short)atoi(val);
				if(*p2)
				{	while(*p2 && myisspace(*p2)) p2++;
					if(*p2)
					{	val=p2;
						while(*p2 && !myisspace(*p2)) p2++;
						if(*p2) *p2++ =0;
						ipfw2p->out_table=(unsigned short)atoi(val);
					}
				}
			}
		}
		/* Check if inbound table exists */
		snprintf(chk,sizeof(chk)-1,"/sbin/ipfw show | grep -q \"deny ip from any to table(%u) via %s\"",ipfw2p->in_table,ipfw2p->interface);
		if(system(chk))
		{	/* We just exist with an error for now. In the future, we'll set up the table automatically */
			snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Inbound block table (%u) not defined!",file,line,ipfw2p->in_table);
			logmessage(1,msg,"ipfw2",0);
			free(ipfw2p);
			plugindatalist->data=NULL;
		}	
		else	/* Check if oubound table exists */
		{	snprintf(chk,sizeof(chk)-1,"/sbin/ipfw show | grep -q \"deny ip from table(%u) to any via %s\"",ipfw2p->out_table,ipfw2p->interface);
			if(system(chk))
			{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Outbound block table (%u) not defined!",file,line,ipfw2p->out_table);
				logmessage(1,msg,"ipfw2",0);
				free(ipfw2p);
				plugindatalist->data=NULL;
			}
		}
				
#ifdef FWSAMDEBUG
		if(plugindatalist->data)
			printf("Debug: [ipfw2] Adding IPFW2: i/f '%s', tables %u (in) and %u (out)\n", ipfw2p->interface, ipfw2p->in_table,ipfw2p->out_table);
#endif
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] IPFW2 defined without parameters!",file,line);
		logmessage(1,msg,"ipfw2",0);
	}
}


/* This routine initiates the block. 
 */
void IPFW2Block(BLOCKINFO *bd,void *data,unsigned long qp)
{	IPFW2DATA *ipfw2p;
	int ret;
	char ipfw2cmd[STRBUFSIZE+2],msg[STRBUFSIZE+2];
	
#ifdef FWSAMDEBUG
	pthread_t threadid=pthread_self();
#endif

	if(!data) return;
	ipfw2p=(IPFW2DATA *)data;

#ifdef FWSAMDEBUG
	printf("Debug: [ipfw2][%lx] Plugin Blocking...\n",(unsigned long)threadid);
#endif

	switch(bd->mode&FWSAM_HOW)
	{	case FWSAM_HOW_IN:		ret=snprintf(ipfw2cmd,sizeof(ipfw2cmd)-1,
								"/sbin/ipfw table %u %s %s/32",
								ipfw2p->in_table, bd->block?"add":"delete",inettoa(bd->blockip));
								break;
		case FWSAM_HOW_OUT:		ret=snprintf(ipfw2cmd,sizeof(ipfw2cmd)-1,
								"/sbin/ipfw table %u %s %s/32",
								ipfw2p->out_table, bd->block?"add":"delete",inettoa(bd->blockip));
								break;
		case FWSAM_HOW_INOUT:;
		default:				ret=snprintf(ipfw2cmd,sizeof(ipfw2cmd)-1,
								"/sbin/ipfw table %u %s %s/32;/sbin/ipfw table %u %s %s/32",
								ipfw2p->in_table, bd->block?"add":"delete",inettoa(bd->blockip),
								ipfw2p->out_table, bd->block?"add":"delete",inettoa(bd->blockip));
								break;
	}
	if(ret >= sizeof(ipfw2cmd)-1)
	{	snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", ipfw2cmd);
		logmessage(1,msg,"ipfw2",0);
	} 
	else 
	{
#ifdef FWSAMDEBUG
		printf("Debug: [ipfw2][%lx] command \"%s\"\n", (unsigned long)threadid, ipfw2cmd);
#endif
		/* Run the command */
		if (system(ipfw2cmd) ) 
		{	snprintf(msg,sizeof(msg)-1,"Error: Command \"%s\" Failed", ipfw2cmd);
			logmessage(1,msg,"ipfw2",0);
		}
		else 
		{	snprintf(msg,sizeof(msg)-1,"Info: Command \"%s\" Executed Successfully", ipfw2cmd);
			logmessage(3,msg,"ipfw2",0);
		}
	}
}

#endif /* __SSP_IPFW2_C__ */
#endif /* FreeBSD */
