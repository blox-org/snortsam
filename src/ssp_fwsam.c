/* $Id: ssp_fwsam.c,v 2.5 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2005-2008 Frank Knobbe <frank@knobbe.us>
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
 * ssp_fwsam.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin sends a self-assembled OPSEC packet to a Firewall-1
 * firewall in order to block/unblock. (Like the OPSEC method, but doesn't
 * use the official OPSEC libraries and is faster.)
 *
 */


#ifndef		__SSP_FWSAM_C__
#define		__SSP_FWSAM_C__


#include "snortsam.h"
#include "ssp_fwsam.h"

extern unsigned int fwsamipflip;

/* This routine parses the fwsam statements in the config file.
 * They should all be firewall IP addresses.
*/
void FWSamParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	FWDATA *fwp;
	struct in_addr ipip;
	char msg[STRBUFSIZE+2];
	
#ifdef FWSAMDEBUG
	printf("Debug: [fwsam] Plugin Parsing...\n");
#endif

	remspace(val);
	ipip.s_addr=getip(val);
	if(ipip.s_addr)					/* if valid entry */
	{	fwp=safemalloc(sizeof(FWDATA),"FWSamParse","fwp");	/* create new host */
		plugindatalist->data=fwp;
		fwp->ip.s_addr=ipip.s_addr;
		snprintf(msg,sizeof(msg)-1,"fwsam: Adding firewall module: %s",inettoa(ipip.s_addr));
		logmessage(3,msg,"fwsam",0);
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Unknown fwsam parameter '%s' ignored.",file,line,val);
		logmessage(1,msg,"fwsam",0);
	}
}

/* This routine initiates the block via a self constructed
 * SAM packet to port 18183 on the IP in the list.
*/
void FWSamBlock(BLOCKINFO *bd,void *datapointer,unsigned long qp)
{	int plen;
    FWDATA *fwp; 
	struct sockaddr_in mysocketaddr,fwsocketaddr;
	SOCKET fwsocket;
	unsigned long ll;
	char tmp[STRBUFSIZE+1],msg[STRBUFSIZE+1];
	unsigned char tempchar,CPpacket[]=		/* we're not including the OPSEC library but instead send */
	{	0,0,0,0xc,					/* our own OPSEC compliant packet. This is the frame work */
		1,1,0,1,					/* for it. */
		0,0,0,3,
		0,0,0,0xc,
		1,1,6,2,
		0,0,0,3,
		0,0,0,0,	/* len of data */
		1,1,6,3,
		0,0,0,3,
		0,0,0,1,
		0,0,0,0,	/* ip addr */
		0,0,0,0,	/* action */
		0,0,0,0,	/* duration */
		0,0,0,4,	/* log/alert/nolog */
		0,0,0,4,	/* followed by string 'All' or 'Gateways' or firewall object/group name */
					/* then append modem source, port, and protocol if mode is 'service' (this). */
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif
#endif

	if(!datapointer)
		return;
		
	fwp=(FWDATA *)datapointer;
#ifdef FWSAMDEBUG
	printf("Debug: [fwsam][%lx] Plugin Blocking...\n",(unsigned long)threadid);
#endif

	/*  we assemble our own packet */
	if((bd->mode&FWSAM_HOW)==FWSAM_HOW_THIS)  /* set the length of the data segment */
		CPpacket[CP_DATALEN+3]=0x34; 
	else
		CPpacket[CP_DATALEN]=0x2c;
	plen=CPpacket[CP_DATALEN]+24;


	*((unsigned long *)(CPpacket+CP_IPADDR))=bd->blockip;
	if(fwsamipflip)
	{	tempchar=CPpacket[CP_IPADDR+3]; CPpacket[CP_IPADDR+3]=CPpacket[CP_IPADDR+0]; CPpacket[CP_IPADDR+0]=tempchar;
		tempchar=CPpacket[CP_IPADDR+2]; CPpacket[CP_IPADDR+2]=CPpacket[CP_IPADDR+1]; CPpacket[CP_IPADDR+1]=tempchar;
	}

#ifdef S_MANUALFLIP
#ifdef S_REVERSED
	CPpacket[CP_IPADDR+3]=(unsigned char)(bd->blockip);
	CPpacket[CP_IPADDR+2]=(unsigned char)(bd->blockip>>8);
	CPpacket[CP_IPADDR+1]=(unsigned char)(bd->blockip>>16);
	CPpacket[CP_IPADDR+0]=(unsigned char)(bd->blockip>>24);	/* set the IP to be blocked */

#else
	CPpacket[CP_IPADDR]=(unsigned char)(bd->blockip);
	CPpacket[CP_IPADDR+1]=(unsigned char)(bd->blockip>>8);
	CPpacket[CP_IPADDR+2]=(unsigned char)(bd->blockip>>16);
	CPpacket[CP_IPADDR+3]=(unsigned char)(bd->blockip>>24);	/* set the IP to be blocked */
#endif
#endif

	CPpacket[CP_DURATION+3]=(unsigned char)bd->duration;	/* set the duration (duration is in big endian format) */
	CPpacket[CP_DURATION+2]=(unsigned char)(bd->duration>>8);
	CPpacket[CP_DURATION+1]=(unsigned char)(bd->duration>>16);
	CPpacket[CP_DURATION]=(unsigned char)(bd->duration>>24);
	CPpacket[CP_LOGTYPE]=(unsigned char)(bd->mode&FWSAM_LOG);	  /* set the logging mode */
	CPpacket[CP_ACTION]=3;					/* set 'inhibit and close' */
	if(!bd->block)
		CPpacket[CP_ACTION]|=8;			 /* if need to unblock, set the cancel flag */
	strcpy(CPpacket+CP_MODSTR,"All");  /* set modules to ALL (add individual FW modules later) */
	CPpacket[CP_MODSTR+4]=CPpacket[CP_MODSTR+5]=CPpacket[CP_MODSTR+6]=0; /* null to next long boundary */
	switch(bd->mode&FWSAM_HOW)			 /* set blocking mode */
	{	case FWSAM_HOW_THIS:
			CPpacket[CP_MODSTR+7]=0x20;		/* if type service, set the peer IP... */

			*((unsigned long *)(CPpacket+CP_MODSTR+8))=bd->peerip;
			if(fwsamipflip)
			{	tempchar=CPpacket[CP_MODSTR+11]; CPpacket[CP_MODSTR+11]=CPpacket[CP_MODSTR+8]; CPpacket[CP_MODSTR+8]=tempchar;
				tempchar=CPpacket[CP_MODSTR+10]; CPpacket[CP_MODSTR+10]=CPpacket[CP_MODSTR+9]; CPpacket[CP_MODSTR+9]=tempchar;
			}

#ifdef S_MANUAL_FLIP
#ifdef S_REVERSED
			CPpacket[CP_MODSTR+11]=(unsigned char)(bd->peerip);		/* ip */
			CPpacket[CP_MODSTR+10]=(unsigned char)(bd->peerip>>8);
			CPpacket[CP_MODSTR+9]=(unsigned char)(bd->peerip>>16);
			CPpacket[CP_MODSTR+8]=(unsigned char)(bd->peerip>>24);
#else
			CPpacket[CP_MODSTR+8]=(unsigned char)(bd->peerip);		/* ip */
			CPpacket[CP_MODSTR+9]=(unsigned char)(bd->peerip>>8);
			CPpacket[CP_MODSTR+10]=(unsigned char)(bd->peerip>>16);
			CPpacket[CP_MODSTR+11]=(unsigned char)(bd->peerip>>24);
#endif
#endif
			CPpacket[CP_MODSTR+13]=(unsigned char)bd->port;				/* ...and port */ 
			CPpacket[CP_MODSTR+12]=(unsigned char)(bd->port>>8);
			CPpacket[CP_MODSTR+15]=(unsigned char)bd->proto;	/* ...and protocol (all big endian) */
			CPpacket[CP_MODSTR+14]=(unsigned char)(bd->proto>>8);
			break;
		case FWSAM_HOW_IN:
			CPpacket[CP_MODSTR+7]=0x2;
			break;
		case FWSAM_HOW_OUT:
			CPpacket[CP_MODSTR+7]=0x4;
			break;
		case FWSAM_HOW_INOUT:
			CPpacket[CP_MODSTR+7]=0x1;
			break;
	}

	/* set the socket stuff for the fw module */
	mysocketaddr.sin_port=htons(0);	
	mysocketaddr.sin_addr.s_addr=0;
	mysocketaddr.sin_family=AF_INET;
	fwsocketaddr.sin_port=htons(18183);
	fwsocketaddr.sin_addr=fwp->ip;
	fwsocketaddr.sin_family=AF_INET;

	fwsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
	if(fwsocket==INVALID_SOCKET)
	{	snprintf(msg,sizeof(msg)-1,"Error: [SAM] Could not create socket for %s!",inettoa(fwp->ip.s_addr));
		logmessage(1,msg,"fwsam",fwp->ip.s_addr);
		return;
	}
	if(bind(fwsocket,(struct sockaddr *)&(mysocketaddr),sizeof(struct sockaddr)))
	{	snprintf(msg,sizeof(msg)-1,"Error: [SAM] Could not bind socket for %s!",inettoa(fwp->ip.s_addr));
		logmessage(1,msg,"fwsam",fwp->ip.s_addr);
		return;
	}
	if(connect(fwsocket,(struct sockaddr *)&fwsocketaddr,sizeof(struct sockaddr)))
	{	snprintf(msg,sizeof(msg)-1,"Error: [SAM] Could not connect to %s:18183!",inettoa(fwp->ip.s_addr));
		logmessage(1,msg,"fwsam",fwp->ip.s_addr);
	}
	else			
	{
#ifdef FWSAMDEBUG
		printf("Debug: [fwsam][%lx] Connected to %s:18183.\n",(unsigned long)threadid,inettoa(fwp->ip.s_addr));
#endif				
		if(send(fwsocket,CPpacket,plen,0)!=plen)  /* send the packet */
		{	snprintf(msg,sizeof(msg)-1,"Error: [SAM] Could not send packet to %s:18183!",inettoa(fwp->ip.s_addr));
			logmessage(1,msg,"fwsam",fwp->ip.s_addr);
		}
		else
		{	/* and wait for response. This is important. If we close the connection too
			 * early, the block will not be executed. We need to wait at least until we
			 * get the 'block accepted' message. (But we don't need to wait for 
			 * the 'block completed' message.)
			 */
			ll=1000;			/* wait a maximum of 10 secs for response */

			ioctlsocket(fwsocket,FIONBIO,&ll);
			while(ll-- >1)
			{	waitms(10);				
				while(recv(fwsocket,tmp,1,0)>0)
				{	ll=0;
#ifdef FWSAMDEBUG
					printf(".");
#endif					
				}
			}
#ifdef FWSAMDEBUG
			printf("\n");
			if(ll)
				printf("Got response from firewall.\n");
#endif					
			if(!ll) /* time up? */
			{	snprintf(msg,sizeof(msg)-1,"Error: [SAM] No response from %s.",inettoa(fwp->ip.s_addr));
				logmessage(1,msg,"fwsam",fwp->ip.s_addr);
			}
		}
		closesocket(fwsocket);
	}
}

#endif /* __SSP_FWSAM_C__ */






