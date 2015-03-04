/* $Id: ssp_cisco_nullroute.c,v 2.5 2009/10/16 22:19:36 fknobbe Exp $
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
 * Acknowledgements:
 *
 * Brent Erickson and Sergio Salazar for the idea and sample commands.
 *
 *
 * ssp_cisco_nullroute.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin telnet's into one or more Cisco routers and issues
 * a route command to effectively "null-route" the intruding IP address.
 * SnortSam will remove the added routes when the blocks expire.
 *
 *
 */


#ifndef		__SSP_CISCO_NULLROUTE_C__
#define		__SSP_CISCO_NULLROUTE_C__


#include "snortsam.h"
#include "ssp_cisco_nullroute.h"


#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif




/* This routine parses the cisconullroute statements in the config file.
 * It builds a list of routers)
*/
void CiscoNullRouteParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	CISCONULLROUTEDATA *ciscop;
	char *p2,msg[STRBUFSIZE+2],*p3;
	struct in_addr routerip;

#ifdef FWSAMDEBUG
	printf("Debug: [cisconullroute] Plugin Parsing...\n");
#endif

	if(*val)
	{	p2=val;
		while(*p2 && !myisspace(*p2))
			p2++;
		if(*p2)
			*p2++ =0;
		routerip.s_addr=getip(val);
		if(routerip.s_addr)			/* If we have a valid IP address */
		{	ciscop=safemalloc(sizeof(CISCONULLROUTEDATA),"cisconullrouteparse","ciscop");	/* create new router */
			plugindatalist->data=ciscop;
			ciscop->ip.s_addr=routerip.s_addr;
			ciscop->routersocket=0;
			ciscop->loggedin=FALSE;
			ciscop->username[0]=ciscop->enablepw[0]=ciscop->userlogin=0;
			ciscop->telnetpw=ciscop->username;

			if(*p2)
			{	val=p2;
				while(*val && myisspace(*val))	/* now parse the remaining text */
					val++;
				if(val)
				{	p2=val;
					while(*p2 && !myisspace(*p2))
						p2++;
					if(*p2)
						*p2++ =0;
					safecopy(ciscop->username,val);	/* save telnet password */

					p3=strchr(ciscop->username,'/');  /* Check if a username is given */
					if(p3)
					{	*p3++ =0;
						ciscop->telnetpw=p3;
						ciscop->userlogin=TRUE;
					}
					
					if(*p2)									/* if we have a second password */
					{	while(*p2 && myisspace(*p2))
							p2++;
						safecopy(ciscop->enablepw,p2);/* it would be the enable password */
					}
					else
						safecopy(ciscop->enablepw,ciscop->telnetpw); /* if only one password was found, use it for both */
				}
			}
			if(!ciscop->telnetpw[0])
			{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Cisco Router defined without passwords!",file,line);
				logmessage(1,msg,"cisconullroute",0);
				free(ciscop);
				plugindatalist->data=NULL;
			}
#ifdef FWSAMDEBUG
			else
				printf("Debug: [cisconullroute] Adding Cisco Router: IP \"%s\", PW \"%s\", EN \"%s\"\n",inettoa(ciscop->ip.s_addr),ciscop->telnetpw,ciscop->enablepw);
#endif
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid CiscoNullRoute parameter '%s' ignored.",file,line,val);
			logmessage(1,msg,"cisconullroute",0);
		}
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Empty CiscoNullRoute parameter.",file,line);
		logmessage(1,msg,"cisconullroute",0);
	}
}


/* This routine initiates the block. It walks the list of routers
 * telnet's in, and issues the route command.
 */
void CiscoNullRouteBlock(BLOCKINFO *bd,void *data,unsigned long qp)
{   CISCONULLROUTEDATA *ciscop;
	struct sockaddr_in thissocketaddr,routersocketaddr;
	unsigned long flag;
	char cnrmsg[STRBUFSIZE+1],cnrat[STRBUFSIZE+1];
#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif
#endif

	if(!data)
		return;
    ciscop=(CISCONULLROUTEDATA *)data;

#ifdef FWSAMDEBUG
	printf("Debug: [cisconullroute][%lx] Plugin Blocking...\n",(unsigned long)threadid);
#endif
	
	snprintf(cnrat,sizeof(cnrat)-1,"router at %s",inettoa(ciscop->ip.s_addr));
	
	if(!ciscop->routersocket)
	{	routersocketaddr.sin_port=htons(23); /* telnet */
		routersocketaddr.sin_addr.s_addr=ciscop->ip.s_addr;
		routersocketaddr.sin_family=AF_INET;

		thissocketaddr.sin_port=htons(0); /* get a dynamic port  */
		thissocketaddr.sin_addr.s_addr=0;
		thissocketaddr.sin_family=AF_INET;

		/* create socket */
		ciscop->routersocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
		if(ciscop->routersocket==INVALID_SOCKET)
		{	snprintf(cnrmsg,sizeof(cnrmsg)-1,"Error: [cisconullroute] Couldn't create socket!");
			logmessage(1,cnrmsg,"cisconullroute",ciscop->ip.s_addr);
			ciscop->routersocket=0;
			return;
		}
		/* bind it */
		if(bind(ciscop->routersocket,(struct sockaddr *)&(thissocketaddr),sizeof(struct sockaddr)))
		{	snprintf(cnrmsg,sizeof(cnrmsg)-1,"Error: [cisconullroute] Couldn't bind socket!");
			logmessage(1,cnrmsg,"ciscocnullroute",ciscop->ip.s_addr);
			ciscop->routersocket=0;
			return;
		}
		/* and connect to router */
		if(connect(ciscop->routersocket,(struct sockaddr *)&routersocketaddr,sizeof(struct sockaddr))) 
		{	snprintf(cnrmsg,sizeof(cnrmsg)-1,"Error: [cisconullroute] Could not connect to %s! Will try later.",cnrat);
			logmessage(1,cnrmsg,"cisconullroute",ciscop->ip.s_addr);
			closesocket(ciscop->routersocket);
			ciscop->routersocket=0;
		}
	}
	if(ciscop->routersocket)
	{	do
		{
#ifdef FWSAMDEBUG
			printf("Debug: [cisconullroute][%lx] Connected to %s.\n",(unsigned long)threadid,cnrat);
#endif
			flag=-1;
			ioctlsocket(ciscop->routersocket,FIONBIO,&flag);	/* set non blocking  */
			flag=FALSE;
			
			if(!ciscop->loggedin)
			{	if(ciscop->userlogin)
				{	if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,"","username","waiting for user logon prompt from ",cnrat))
					{	flag=TRUE;
						continue;
					}
					snprintf(cnrmsg,sizeof(cnrmsg)-1,"%s\r",ciscop->username);	/* Send username password */

					if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,cnrmsg,"pass","at password prompt from ",cnrat))
					{	flag=TRUE;
						continue;
					}
					snprintf(cnrmsg,sizeof(cnrmsg)-1,"%s\r",ciscop->telnetpw);	/* Send telnet password */
				}
				else
				{	if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,"","pass","waiting for logon prompt from ",cnrat))
					{	flag=TRUE;
						continue;
					}
					snprintf(cnrmsg,sizeof(cnrmsg)-1,"%s\r",ciscop->telnetpw);	/* Send telnet password */
				}

				if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,cnrmsg,">","at logon prompt of ",cnrat))
				{	flag=TRUE;
					continue;
				}
			
				/* Send enable */																
				if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,"enable\r","pass","at enable command of ",cnrat))
				{	flag=TRUE;
					continue;
				}

				/* Send enable password */
				snprintf(cnrmsg,sizeof(cnrmsg)-1,"%s\r",ciscop->enablepw);	
				if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,cnrmsg,"#","at enable prompt of ",cnrat))
				{	flag=TRUE;
					continue;
				}

				/* Send config */
				if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,"config t\r","#","at config command of ",cnrat))
				{	flag=TRUE;
					continue;
				}
				ciscop->loggedin=TRUE;
			}
			
			/* send route command */
			snprintf(cnrmsg,sizeof(cnrmsg)-1,"%sip route %s 255.255.255.255 null 0\r",bd->block?"":"no ",inettoa(bd->blockip));
			if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,cnrmsg,"#","at route command of ",cnrat))
			{	flag=TRUE;
				continue;
			}

			if(!moreinqueue(qp))
			{	/* End input */
				if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,"\032","#","at CTRL-Z of ",cnrat))
				{	flag=TRUE;
					continue;
				}

				/* Save config */
				if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,"write mem\r","#","at write mem command of ",cnrat))
				{	flag=TRUE;
					continue;
				}

				/* and we're outta here... */
				sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute",ciscop->ip,"quit\r","","at quit command of ",cnrat);
				flag=TRUE;
			}
		}while(FALSE);

		if(flag)
		{	closesocket(ciscop->routersocket);
			ciscop->routersocket=0;
			ciscop->loggedin=FALSE;
		}
	}
}

#endif /* __SSP_CISCO_NULLROUTE_C__ */






