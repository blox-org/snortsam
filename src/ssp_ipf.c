/* $Id: ssp_ipf.c,v 2.16 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2002-2008 Frank Knobbe <frank@knobbe.us>, Erik Sneep <erik@webflex.nl>
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
 * ssp_ipf.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin is meant for dynamic (un)blocking on IPFilter firewall,
 * SnortSam will expire the blocks itself since IPFilter does not have 
 * automatic time-out functionality.
 *
 */


#if !defined(WIN32) && !defined(Linux)

#ifndef		__SSP_IPF_C__
#define		__SSP_IPF_C__

#include "snortsam.h"
#include "ssp_ipf.h"


#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* This routine parses the ipf statements in the config file.
*/
void IPFParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	IPFDATA *ipfp=NULL;
	char *p2, msg[STRBUFSIZE+2];

#ifdef FWSAMDEBUG
	printf("Debug: [ipf] Plugin Parsing...\n");
#endif

	if(*val)
	{	p2=val;
		while(*p2 && !myisspace(*p2)) p2++;
		if(*p2) *p2++ =0;
		ipfp=safemalloc(sizeof(IPFDATA),"IPFParse","ipfp");
		plugindatalist->data=ipfp;
		safecopy(ipfp->iface,val);	/* save interface */
					
		if(*p2)	/* if we have a loglevel defined */
		{	while(*p2 && myisspace(*p2)) p2++;
			safecopy(ipfp->loglv,p2); 		/* loglevel defined */
		} else {
			safecopy(ipfp->loglv,IPFLOGLEVEL); 	/* use default loglevel */
		}

#ifdef FWSAMDEBUG
		printf("Debug: [ipf] Adding IPF: interface \"%s\", loglevel \"%s\"\n", ipfp->iface, ipfp->loglv);
#endif

	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] IPF defined without parameters!",file,line);
		logmessage(1,msg,"ipf",0);
	}
}


/* This routine initiates the block. 
 */
void IPFBlock(BLOCKINFO *bd,void *data,unsigned long qp)
{   IPFDATA *ipfp;
	int ret;
	char ipfcmd[STRBUFSIZE+2], msg[STRBUFSIZE+2], interf[STRBUFSIZE+2]="";
#ifdef FWSAMDEBUG
	pthread_t threadid=pthread_self();
#endif

	if(!data) return;
	ipfp=(IPFDATA *)data;

#ifdef FWSAMDEBUG
	printf("Debug: [ipf][%lx] Plugin Blocking...\n",(unsigned long)threadid);
#endif

	if(bd->block)
	{ 	snprintf(msg,sizeof(msg)-1,"Info: Blocking IP %s", inettoa(bd->blockip));
	  	logmessage(3,msg,"ipf",0);
	}	  
	else
	{	snprintf(msg,sizeof(msg)-1,"Info: Unblocking IP %s", inettoa(bd->blockip));
	  	logmessage(3,msg,"ipf",0);
	}
	if(stricmp(ipfp->iface,"any"))
		snprintf(interf,sizeof(interf)-1,"on %s",ipfp->iface);
		
	
	/* Assemble command */
	switch(bd->mode&FWSAM_HOW)
	{	case FWSAM_HOW_IN:		if(bd->mode&FWSAM_WHO == FWSAM_WHO_SRC)
	  							{	ret=snprintf(ipfcmd,sizeof(ipfcmd)-1,
									"echo \"@1 block in log level %s quick %s from %s/32 to any\"|/sbin/ipf -%sf -",
									ipfp->loglv, interf, inettoa(bd->blockip), bd->block?"":"r");
								}
								else
	  							{	ret=snprintf(ipfcmd,sizeof(ipfcmd)-1,
									"echo \"@1 block in log level %s quick %s from any to %s/32\"|/sbin/ipf -%sf -",
									ipfp->loglv, interf, inettoa(bd->blockip), bd->block?"":"r");
								}
								
								break;
	  	case FWSAM_HOW_OUT:		if(bd->mode&FWSAM_WHO == FWSAM_WHO_SRC)
	  							{	ret=snprintf(ipfcmd,sizeof(ipfcmd)-1,
									"echo \"@1 block out log level %s quick %s from any to %s/32\"|/sbin/ipf -%sf -",
									ipfp->loglv, interf, inettoa(bd->blockip), bd->block?"":"r");
								}
								else
	  							{	ret=snprintf(ipfcmd,sizeof(ipfcmd)-1,
									"echo \"@1 block out log level %s quick %s from %s/32 to any\"|/sbin/ipf -%sf -",
									ipfp->loglv, interf, inettoa(bd->blockip), bd->block?"":"r");
								}
								
								break;
	  	case FWSAM_HOW_THIS:	if(bd->proto==6 || bd->proto==17)
								{	if(bd->mode&FWSAM_WHO == FWSAM_WHO_SRC)
									{	ret=snprintf(ipfcmd,sizeof(ipfcmd)-1,
										"echo \"@1 block in log level %s quick %s proto %s from %s/32 to %s/32 port = %i\"|/sbin/ipf -%sf -",
										ipfp->loglv, interf, bd->proto==6?"tcp":"udp", inettoa(bd->blockip),inettoa(bd->peerip), bd->port, bd->block?"":"r");
									}
									else
									{	ret=snprintf(ipfcmd,sizeof(ipfcmd)-1,
										"echo \"@1 block in log level %s quick %s proto %s from %s/32 to %s/32 port = %i\"|/sbin/ipf -%sf -",
										ipfp->loglv, interf, bd->proto==6?"tcp":"udp", inettoa(bd->blockip),inettoa(bd->peerip), bd->port, bd->block?"":"r");
									}									
								} 
								else  
								{	if(bd->mode&FWSAM_WHO == FWSAM_WHO_SRC)
									{	ret=snprintf(ipfcmd,sizeof(ipfcmd)-1,
										"echo \"@1 block in log level %s quick %s proto %i from %s/32 to %s/32\"|/sbin/ipf -%sf -",
										ipfp->loglv, interf, bd->proto, inettoa(bd->blockip), inettoa(bd->peerip), bd->block?"":"r");
									}
									else
									{	ret=snprintf(ipfcmd,sizeof(ipfcmd)-1,
										"echo \"@1 block in log level %s quick %s proto %i from %s/32 to %s/32\"|/sbin/ipf -%sf -",
										ipfp->loglv, interf, bd->proto, inettoa(bd->blockip), inettoa(bd->peerip), bd->block?"":"r");
									}
								}
								break;
	  	case FWSAM_HOW_INOUT:		
		default:				ret=snprintf(ipfcmd,sizeof(ipfcmd)-1,
								"echo \"@1 block in log level %s quick %s from %s/32 to any\"|/sbin/ipf -%sf -;echo \"@1 block out log level %s quick %s from any to %s/32\"|/sbin/ipf -%sf -;",
								ipfp->loglv, interf, inettoa(bd->blockip),bd->block?"":"r",ipfp->loglv, interf, inettoa(bd->blockip),bd->block?"":"r");
								break;
	}
	if(ret >= sizeof(ipfcmd))
	{	snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", ipfcmd);
		logmessage(1,msg,"ipf",0);
		return;
	}
#ifdef FWSAMDEBUG
	printf("Debug: [ipf][%lx] Command: %s\n", (unsigned long)threadid, ipfcmd);
#endif
	/* Run the command */
	if (system(ipfcmd) != 0)
	{	snprintf(msg,sizeof(msg)-1,"Error: Command %s Failed", ipfcmd);
		logmessage(1,msg,"ipf",0);
	} 
	else 
	{	snprintf(msg,sizeof(msg)-1,"Info: Command %s Executed Successfully", ipfcmd);
		logmessage(3,msg,"ipf",0);
	}
	return;
}

#endif /* __SSP_IPF_C__ */
#endif /* WIN32 */


