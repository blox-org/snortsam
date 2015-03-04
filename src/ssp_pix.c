/* $Id: ssp_pix.c,v 2.9 2008/04/26 19:50:01 fknobbe Exp $
 *
 *
 * Copyright (c) 2002-2004 Frank Knobbe <frank@knobbe.us>
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
 * Thanks to Aaron Carr for letting me use his PIX and making test machines
 * accessible.
 *
 *
 *
 * ssp_pix.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin telnet's into one or more Cisco PIX firewalls,
 * and issues the shun command. SnortSam will also expire the blocks
 * itself since the PIX does not have automatic time-out functionality.
 *
 * Comments:
 *
 * Even though the SHUN command has options for peerip, port and protocol,
 * in my tests this didn't work. It would still block the whole IP.
 * SnortSam will default to the whole IP and not even attempt to
 * send peer, port, and protocol information.
 *
 * Is this a bug in the PIX? This can be revisited lated.
 *
 * UPDATE: I think I know why the service didn't work in my tests.
 * I entered the protocol as 6 (and 17) instead of tcp (and udp).
 * My guess is that the PIX was expecting tcp, couldn't interpret
 * 7 and just blocked the whole IP. NEED TO TRY THIS AGAIN.
 *
 * UPDATE: Tried it again. The problem is that the PIX only accepts one
 * connection per IP. Also, there is no specific (IP/service pair) 
 * unshunning of IPs. That means full IP blocks will remain the default
 * until something changes in the PIX IOS to support specific connection
 * shuns.
 *
 *
 */


#ifndef		__SSP_PIX_C__
#define		__SSP_PIX_C__


#include "snortsam.h"
#include "ssp_pix.h"


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




/* This routine parses the pix statements in the config file.
 * It builds a list of pixes)
*/
void PIXParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	PIXDATA *pixp;
	char *p2,msg[STRBUFSIZE+2],*p3;
	struct in_addr pixip;

#ifdef FWSAMDEBUG
	printf("Debug: [pix] Plugin Parsing...\n");
#endif

	if(*val)
	{	p2=val;
		while(*p2 && !myisspace(*p2))
			p2++;
		if(*p2)
			*p2++ =0;
		pixip.s_addr=getip(val);
		if(pixip.s_addr)			/* If we have a valid IP address */
		{	pixp=safemalloc(sizeof(PIXDATA),"PIXParse","pixp");	/* create new pix */
			plugindatalist->data=pixp;
			pixp->ip.s_addr=pixip.s_addr;
			pixp->pixsocket=0;
			pixp->loggedin=FALSE;
			pixp->username[0]=pixp->enablepw[0]=pixp->userlogin=0;
			pixp->telnetpw=pixp->username;

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
					safecopy(pixp->username,val);	/* save telnet password */

					p3=strchr(pixp->username,'/');  /* Check if a username is given */
					if(p3)
					{	*p3++ =0;
						pixp->telnetpw=p3;
						pixp->userlogin=TRUE;
					}
					
					if(*p2)									/* if we have a second password */
					{	while(*p2 && myisspace(*p2))
							p2++;
						safecopy(pixp->enablepw,p2);/* it would be the enable password */
					}
					else
						safecopy(pixp->enablepw,pixp->telnetpw); /* if only one password was found, use it for both */
				}
			}
			if(!pixp->telnetpw[0])
			{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] PIX defined without passwords!",file,line);
				logmessage(1,msg,"pix",0);
				free(pixp);
				plugindatalist->data=NULL;
			}
#ifdef FWSAMDEBUG
			else
				printf("Debug: [pix] Adding PIX: IP \"%s\", PW \"%s\", EN \"%s\"\n",inettoa(pixp->ip.s_addr),pixp->telnetpw,pixp->enablepw);
#endif
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid PIX parameter '%s' ignored.",file,line,val);
			logmessage(1,msg,"pix",0);
		}
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Empty PIX parameter.",file,line);
		logmessage(1,msg,"pix",0);
	}
}


/* This routine initiates the block. It walks the list of PIX'es
 * telnet's in, and issues the shun command.
 */
void PIXBlock(BLOCKINFO *bd,void *data,unsigned long qp)
{   PIXDATA *pixp;
	struct sockaddr_in thissocketaddr,pixsocketaddr;
	unsigned long flag;
	char pixmsg[STRBUFSIZE+1],pixat[STRBUFSIZE+1];
#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif
#endif

	if(!data)
		return;
    pixp=(PIXDATA *)data;

#ifdef FWSAMDEBUG
	printf("Debug: [pix][%lx] Plugin Blocking...\n",(unsigned long)threadid);
#endif
	
	snprintf(pixat,sizeof(pixat)-1,"PIX at %s",inettoa(pixp->ip.s_addr));
	
	if(!pixp->pixsocket)
	{	pixsocketaddr.sin_port=htons(23); /* telnet */
		pixsocketaddr.sin_addr.s_addr=pixp->ip.s_addr;
		pixsocketaddr.sin_family=AF_INET;

		thissocketaddr.sin_port=htons(0); /* get a dynamic port  */
		thissocketaddr.sin_addr.s_addr=0;
		thissocketaddr.sin_family=AF_INET;

		/* create socket */
		pixp->pixsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
		if(pixp->pixsocket==INVALID_SOCKET)
		{	snprintf(pixmsg,sizeof(pixmsg)-1,"Error: [pix] Couldn't create socket!");
			logmessage(1,pixmsg,"pix",pixp->ip.s_addr);
			pixp->pixsocket=0;
			return;
		}
		/* bind it */
		if(bind(pixp->pixsocket,(struct sockaddr *)&(thissocketaddr),sizeof(struct sockaddr)))
		{	snprintf(pixmsg,sizeof(pixmsg)-1,"Error: [pix] Couldn't bind socket!");
			logmessage(1,pixmsg,"pix",pixp->ip.s_addr);
			pixp->pixsocket=0;
			return;
		}
		/* and connect to pix */
		if(connect(pixp->pixsocket,(struct sockaddr *)&pixsocketaddr,sizeof(struct sockaddr))) 
		{	snprintf(pixmsg,sizeof(pixmsg)-1,"Error: [pix] Could not connect to %s! Will try later.",pixat);
			logmessage(1,pixmsg,"pix",pixp->ip.s_addr);
			closesocket(pixp->pixsocket);
			pixp->pixsocket=0;
		}
	}	
	if(pixp->pixsocket)
	{   do
		{
#ifdef FWSAMDEBUG
			printf("Debug: [pix][%lx] Connected to %s.\n",(unsigned long)threadid,pixat);
#endif
			flag=-1;
			ioctlsocket(pixp->pixsocket,FIONBIO,&flag);	/* set non blocking  */
			flag=FALSE;
			
			if(!pixp->loggedin)
			{
				if(pixp->userlogin)
				{	if(!sendreceive(pixp->pixsocket,PIXNETWAIT,"pix",pixp->ip,"","username","waiting for user logon prompt from ",pixat))
					{	flag=TRUE;
						continue;
					}
					snprintf(pixmsg,sizeof(pixmsg)-1,"%s\r",pixp->username);	/* send username password */

					if(!sendreceive(pixp->pixsocket,PIXNETWAIT,"pix",pixp->ip,pixmsg,"pass","at password prompt from ",pixat))
					{	flag=TRUE;
						continue;
					}
					snprintf(pixmsg,sizeof(pixmsg)-1,"%s\r",pixp->telnetpw);	/* send telnet password */
				}
				else
				{	if(!sendreceive(pixp->pixsocket,PIXNETWAIT,"pix",pixp->ip,"","pass","waiting for logon prompt from ",pixat))
					{	flag=TRUE;
						continue;
					}
					snprintf(pixmsg,sizeof(pixmsg)-1,"%s\r",pixp->telnetpw);	/* send telnet password */
				}

				if(!sendreceive(pixp->pixsocket,PIXNETWAIT,"pix",pixp->ip,pixmsg,"> ","at logon prompt of ",pixat))
				{	flag=TRUE;
					continue;
				}
																				/* send enable */
				if(!sendreceive(pixp->pixsocket,PIXNETWAIT,"pix",pixp->ip,"enable\r","pass","at enable command of ",pixat))
				{	flag=TRUE;
					continue;
				}

				snprintf(pixmsg,sizeof(pixmsg)-1,"%s\r",pixp->enablepw);	/* send enable password */
				if(!sendreceive(pixp->pixsocket,PIXNETWAIT,"pix",pixp->ip,pixmsg,"# ","at enable prompt of ",pixat))
				{	flag=TRUE;
					continue;
				}
				pixp->loggedin=TRUE;
			}
			/* send shun command with IP only (see comments section on top of source) */
			snprintf(pixmsg,sizeof(pixmsg)-1,"%sshun %s\r",bd->block?"":"no ",inettoa(bd->blockip));
			if(!sendreceive(pixp->pixsocket,PIXNETWAIT,"pix",pixp->ip,pixmsg,"# ","at shun command of ",pixat))
			{	flag=TRUE;
				continue;
			}

			if(!moreinqueue(qp))
			{	sendreceive(pixp->pixsocket,PIXNETWAIT,"pix",pixp->ip,"quit\r","","at quit command of ",pixat);
				flag=TRUE;
			}					
		}while(FALSE);

		if(flag)
		{	closesocket(pixp->pixsocket);
			pixp->pixsocket=0;
			pixp->loggedin=FALSE;
		}
	}
}

#endif /* __SSP_PIX_C__ */






