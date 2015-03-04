/* $Id: ssp_iptables.c,v 2.9 2008/12/17 22:16:23 fknobbe Exp $
 *
 *
 * Copyright (c) 2003-2008 Fabizio Tivano <fabrizio@sad.it>
 * Copyright (c) 2008 Modifications by Luis Marichal <luismarichal@gmail.com>
 * All rights reserved.
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
 * ssp_iptables.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin is meant for dynamic (un)blocking on iptables firewall,
 * SnortSam will expire the blocks itself with  automatic time-out functionality.
 *
 *
 *
 *
 *
 *
 *
 */


#ifdef	Linux

#ifndef		__SSP_IPT_C__
#define		__SSP_IPT_C__

#include "snortsam.h"
#include "ssp_iptables.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//SBC CHANGES STARTS
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

int get_network(in_addr_t addr, in_addr_t netmask, in_addr_t *interface_network) {
	unsigned long mask, network, hostmask, broadcast;
	int maskbits;
	int i;

	mask = ntohl(netmask);
	for (maskbits = 32; (mask & (1L << (32 - maskbits))) == 0; maskbits--)
		;
	*interface_network = ntohl(addr) & ntohl(netmask);
     return 0;
}
//SBC CHANGES ENDS


/* Set this if you want IP tables to save the tables after every (un)block. */

/* #define SAVETABLES */



/* This routine parses the ipf statements in the config file.
*/
void IPTParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	IPTDATA *iptp=NULL;
	char *p2, msg[STRBUFSIZE+2];

#ifdef FWSAMDEBUG
	printf("Debug: [iptables] Plugin Parsing...\n");
#endif

	if(*val)
	{	p2=val;
		while(*p2 && !myisspace(*p2)) p2++;
		if(*p2) *p2++ =0;
		iptp=safemalloc(sizeof(IPTDATA),"IPTParse","iptp");
		plugindatalist->data=iptp;
		safecopy(iptp->iface,val);	/* save interface */
					
		if(*p2)	/* if we have a loglevel defined */
		{	while(*p2 && myisspace(*p2)) p2++;
			safecopy(iptp->loglv,p2); 		/* loglevel defined */
		} else {
			safecopy(iptp->loglv,IPTLOGLEVEL); 	/* use default loglevel */
		}

#ifdef FWSAMDEBUG
		printf("Debug: [iptables] Adding IPTABLES: interface \"%s\", loglevel \"%s\"\n", iptp->iface, iptp->loglv);
#endif

	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] IPTABLES defined without parameters!",file,line);
		logmessage(1,msg,"iptables",0);
	}
}


/* This routine initiates the block. 
 */
void IPTBlock(BLOCKINFO *bd,void *data,unsigned long qp)
{   IPTDATA *iptp;
	char iptcmd[255], iptcmd2[255], msg[STRBUFSIZE+2];

	//SBC CHANGES STARTS
	in_addr_t interface_network, packet_network, int_netmask, int_address;
	int fd;
	struct ifreq ifr;
	//SBC CHANGES ENDS

	/*Nuevo*/
	char iptcmd1[255],iptcmd4[255];
#ifdef SAVETABLES
	const char savecmd[]="iptables-save -c > /etc/sysconfig/iptables";
#endif

#ifdef FWSAMDEBUG
	pthread_t threadid=pthread_self();
#endif

	if(!data) return;
		iptp=(IPTDATA *)data;
    //SBC CHANGES STARTS
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iptp->iface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFNETMASK, &ifr);

	int_netmask = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
    strncpy(ifr.ifr_name, iptp->iface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
    int_address = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
	close(fd);
    get_network(int_address, int_netmask, &interface_network);
	//SBC CHANGES ENDS

#ifdef FWSAMDEBUG
	printf("Debug: [iptables][%lx] Plugin Blocking...\n",threadid);
#endif

	if(bd->block)
	{ snprintf(msg,sizeof(msg)-1,"Info: Blocking ip %s", inettoa(bd->blockip));
	  logmessage(3,msg,"iptables",0);

    //SBC CHANGES STARTS
     get_network(bd->blockip,int_netmask, &packet_network);
		if (packet_network != interface_network) {
			return;
		}
	//SBC CHANGES ENDS

	  switch(bd->mode&FWSAM_HOW)
		{	case FWSAM_HOW_IN:	
	  /* Assemble command */
	  if (snprintf(iptcmd,sizeof(iptcmd)-1,
		"iptables -I DYNAMIC_BLACKLIST_FORWARD -i %s  -s %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", iptcmd);
                logmessage(1,msg,"iptables",0);
		return;
          }
#if 0
	  if (snprintf(iptcmd2,sizeof(iptcmd2)-1,
		"iptables -I DYNAMIC_BLACKLIST_INPUT -i %s  -s %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd2)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command2 %s is too long", iptcmd2);
                logmessage(1,msg,"iptables",0);
		return;
          }
#endif
		  break;
		  case FWSAM_HOW_OUT:	
	  /* Assemble command */
	  if (snprintf(iptcmd,sizeof(iptcmd)-1,
		"iptables -I DYNAMIC_BLACKLIST_FORWARD -i %s  -d %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", iptcmd);
                logmessage(1,msg,"iptables",0);
		return;
          }
#if 0
	  if (snprintf(iptcmd2,sizeof(iptcmd2)-1,
		"iptables -I DYNAMIC_BLACKLIST_INPUT -i %s  -d %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd2)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command2 %s is too long", iptcmd2);
                logmessage(1,msg,"iptables",0);
		return;
          }
#endif
		  break;
		  case FWSAM_HOW_INOUT:	
	  /* Assemble command - block src*/
		if ((snprintf(iptcmd,sizeof(iptcmd)-1,
		"iptables -I DYNAMIC_BLACKLIST_FORWARD -i %s  -s %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd)) || (snprintf(iptcmd1,sizeof(iptcmd1)-1,
		"iptables -I DYNAMIC_BLACKLIST_FORWARD -i %s  -d %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd1))) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", iptcmd);
                logmessage(1,msg,"iptables",0);
		return;
          }
#if 0
		if ((snprintf(iptcmd2,sizeof(iptcmd2)-1,
		"iptables -I DYNAMIC_BLACKLIST_INPUT -i %s  -s %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd2)) || (snprintf(iptcmd4,sizeof(iptcmd4)-1,
		"iptables -I DYNAMIC_BLACKLIST_INPUT -i %s  -d %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd4))) {
                snprintf(msg,sizeof(msg)-1,"Error: Command2 %s is too long", iptcmd2);
                logmessage(1,msg,"iptables",0);
		return;
          }
#endif
		  break;
		  case FWSAM_HOW_THIS:	
	  /* Assemble command */
	  if (snprintf(iptcmd,sizeof(iptcmd)-1,
		"iptables -I DYNAMIC_BLACKLIST_FORWARD -i %s  -s %s  -d %s  -p %d  --dport %d -j DROP",
 		iptp->iface, inettoa(bd->blockip), inettoa(bd->peerip), bd->proto, bd->port) >= sizeof(iptcmd)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", iptcmd);
                logmessage(1,msg,"iptables",0);
		return;
          }
#if 0
	  if (snprintf(iptcmd2,sizeof(iptcmd2)-1,
		"iptables -I DYNAMIC_BLACKLIST_INPUT -i %s  -s %s  -d %s  -p %d  --dport %d -j DROP",
 		iptp->iface, inettoa(bd->blockip), inettoa(bd->peerip), bd->proto, bd->port) >= sizeof(iptcmd2)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command2 %s is too long", iptcmd2);
                logmessage(1,msg,"iptables",0);
		return;
          }
#endif
		  break;
		  }
	} 
	else 
	{
	  snprintf(msg,sizeof(msg)-1,"Info: UnBlocking ip %s", inettoa(bd->blockip));
	  logmessage(1,msg,"iptables",0);
switch(bd->mode&FWSAM_HOW)
	{	case FWSAM_HOW_IN:	
          /* Assemble command */
          if (snprintf(iptcmd,sizeof(iptcmd)-1,
		"iptables -D DYNAMIC_BLACKLIST_FORWARD -i %s  -s %s -j DROP",
	  	iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", iptcmd);
                logmessage(1,msg,"iptables",0);
		return;
        }
#if 0
	    if (snprintf(iptcmd2,sizeof(iptcmd2)-1,
		"iptables -D DYNAMIC_BLACKLIST_INPUT -i %s  -s %s -j DROP",
	  	iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd2)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command2 %s is too long", iptcmd2);
                logmessage(1,msg,"iptables",0);
		return;
	    }
#endif
		break;
		case FWSAM_HOW_OUT:	
		 /* Assemble command */
          if (snprintf(iptcmd,sizeof(iptcmd)-1,
		"iptables -D DYNAMIC_BLACKLIST_FORWARD -i %s  -d %s -j DROP",
	  	iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", iptcmd);
                logmessage(1,msg,"iptables",0);
		return;
        }
#if 0
	    if (snprintf(iptcmd2,sizeof(iptcmd2)-1,
		"iptables -D DYNAMIC_BLACKLIST_INPUT -i %s  -d %s -j DROP",
	  	iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd2)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command2 %s is too long", iptcmd2);
                logmessage(1,msg,"iptables",0);
		return;
	    }
#endif
		break;
		case FWSAM_HOW_INOUT:	
	  /* Assemble command - block src*/
		if ((snprintf(iptcmd,sizeof(iptcmd)-1,
		"iptables -D DYNAMIC_BLACKLIST_FORWARD -i %s  -s %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd)) || (snprintf(iptcmd1,sizeof(iptcmd1)-1,
		"iptables -D DYNAMIC_BLACKLIST_FORWARD -i %s  -d %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd1))) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", iptcmd);
                logmessage(1,msg,"iptables",0);
		return;
          }
#if 0
		if ((snprintf(iptcmd2,sizeof(iptcmd2)-1,
		"iptables -D DYNAMIC_BLACKLIST_INPUT -i %s  -s %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd2)) || (snprintf(iptcmd4,sizeof(iptcmd4)-1,
		"iptables -D DYNAMIC_BLACKLIST_INPUT -i %s  -d %s -j DROP",
 		iptp->iface, inettoa(bd->blockip)) >= sizeof(iptcmd4))) {
                snprintf(msg,sizeof(msg)-1,"Error: Command2 %s is too long", iptcmd2);
                logmessage(1,msg,"iptables",0);
		return;
          }
#endif
		  break;
		  case FWSAM_HOW_THIS:	
	  /* Assemble command */
	  if (snprintf(iptcmd,sizeof(iptcmd)-1,
		"iptables -D DYNAMIC_BLACKLIST_FORWARD -i %s  -s %s  -d %s  -p %d  --dport %d -j DROP",
 		iptp->iface, inettoa(bd->blockip), inettoa(bd->peerip), bd->proto, bd->port) >= sizeof(iptcmd)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", iptcmd);
                logmessage(1,msg,"iptables",0);
		return;
          }
#if 0
	  if (snprintf(iptcmd2,sizeof(iptcmd2)-1,
		"iptables -D DYNAMIC_BLACKLIST_INPUT -i %s  -s %s  -d %s  -p %d  --dport %d -j DROP",
 		iptp->iface, inettoa(bd->blockip), inettoa(bd->peerip), bd->proto, bd->port) >= sizeof(iptcmd)) {
                snprintf(msg,sizeof(msg)-1,"Error: Command2 %s is too long", iptcmd2);
                logmessage(1,msg,"iptables",0);
		return;
          }
#endif
		  break;
		}
	}
#ifdef FWSAMDEBUG
        printf("Debug: [iptables][%lx] command  %s\n", threadid, iptcmd);
        printf("Debug: [iptables][%lx] command2 %s\n", threadid, iptcmd2);
#endif
	/* Run the command */
        if (system(iptcmd) != 0) { 
		snprintf(msg,sizeof(msg)-1,"Error: Command %s Failed", iptcmd);
		logmessage(3,msg,"iptables",0);
	} else {
                snprintf(msg,sizeof(msg)-1,"Info: Command %s Executed Successfully", iptcmd);
                logmessage(3,msg,"iptables",0);
	}
        if (system(iptcmd2) != 0) { 
		snprintf(msg,sizeof(msg)-1,"Error: Command2 %s Failed", iptcmd2);
		logmessage(1,msg,"iptables",0);
	} else {
                snprintf(msg,sizeof(msg)-1,"Info: Command2 %s Executed Successfully", iptcmd2);
                logmessage(3,msg,"iptables",0);
	}

/*inventiva-recorte*/
	if((bd->mode&FWSAM_HOW)==FWSAM_HOW_INOUT)
	{
		if (system(iptcmd1) != 0) { 
			snprintf(msg,sizeof(msg)-1,"Error: Command %s Failed", iptcmd1);
			logmessage(3,msg,"iptables",0);
		} else {
					snprintf(msg,sizeof(msg)-1,"Info: Command %s Executed Successfully", iptcmd1);
					logmessage(3,msg,"iptables",0);
		}
			if (system(iptcmd4) != 0) { 
			snprintf(msg,sizeof(msg)-1,"Error: Command2 %s Failed", iptcmd4);
			logmessage(1,msg,"iptables",0);
		} else {
				snprintf(msg,sizeof(msg)-1,"Info: Command2 %s Executed Successfully", iptcmd4);
                logmessage(3,msg,"iptables",0);
		}
	}


#ifdef SAVETABLES
/* Save command */    
        if (system(savecmd) != 0) {
            snprintf(msg,sizeof(msg)-1,"Error: Save command %s Failed",savecmd);
         logmessage(1,msg,"iptables",0);
 } else {
                snprintf(msg,sizeof(msg)-1,"Info: Save command %s Executed Successfully", savecmd);
                logmessage(3,msg,"iptables",0);
 }
#endif

	return;
}

#endif /* __SSP_IPT_C__ */
#endif /* Linux */


