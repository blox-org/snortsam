/*
 *
 * Copyright (c) 2009 Wouter de Jong <maddog2k@maddog2k.net>
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
 * Heavily based on ssp_cisco_nullroute of Frank Knobbe <frank@knobbe.us>
 *
 *
 * ssp_cisco_nullroute2.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin telnet's into one or more Cisco routers and issues
 * a route command to effectively "null-route" the intruding IP address.
 * SnortSam will remove the added routes when the blocks expire.
 * This plugin is an improved version, that add's the option to add 
 * a tag to a route, and to use 'auto-enable' mode.
 *
 *
 */


#ifndef		__SSP_CISCO_NULLROUTE2_C__
#define		__SSP_CISCO_NULLROUTE2_C__


#include "snortsam.h"
#include "ssp_cisco_nullroute2.h"


#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
#include <winsock.h>

#ifndef strsep
/* Okay, I'm lazy today. Below a copy of strsep which doesn't exist on Windows,
 * at least my old compiler. Remove/disable this section as necessary.
*/
/* ---8<------8<------8<------8<------8<------8<------8<------8<------8<--- */
/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Get next token from string *stringp, where tokens are possibly-empty
 * strings separated by characters from delim.
 *
 * Writes NULs into the string at *stringp to end tokens.
 * delim need not remain constant from call to call.
 * On return, *stringp points past the last NUL written (if there might
 * be further tokens), or is NULL (if there are definitely no more tokens).
 *
 * If *stringp is NULL, strsep returns NULL.
 */

char *strsep(char **, const char *);

char *strsep(stringp, delim)
	char **stringp;
	const char *delim;
{
	char *s;
	const char *spanp;
	int c, sc;
	char *tok;

	if ((s = *stringp) == NULL)
		return (NULL);
	for (tok = s;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}

/* --->8------>8------>8------>8------>8------>8------>8------>8------>8--- */
#endif /* strsep */
 
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */




/* This routine parses the cisconullroute2 statements in the config file.
 * It builds a list of routers)
*/
void CiscoNullRoute2Parse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{
	CISCONULLROUTE2DATA *ciscop;
	char *p2,msg[STRBUFSIZE+2],*p3,*p4,*p5;
	struct in_addr routerip;
	
#ifdef FWSAMDEBUG
	printf("Debug: [cisconullroute2] Plugin Parsing...\n");
#endif
	
	if(*val)
	{
		p2=val;
		ciscop=safemalloc(sizeof(CISCONULLROUTE2DATA),"cisconullroute2parse","ciscop");	/* create new router */
		plugindatalist->data=ciscop;
		ciscop->routersocket=0;
		ciscop->loggedin=FALSE;
		ciscop->username[0]=ciscop->telnetpw[0]=ciscop->enablepw[0]=ciscop->routetag[0]=ciscop->userlogin=0;
		ciscop->autoenable=FALSE;
		
		while ((p3 = strsep(&p2, " ")) != NULL)
		{
			if (!p3)
				continue;
			
			p4	= strsep(&p3, "=");
			if(p4 != NULL)
			{
				p5	= strsep(&p3, "=");
				
				if(p5 == NULL)
				{
					snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Skipping unknown option '%s'",file,line,p4);
					logmessage(1,msg,"cisconullroute2",0);
					continue;
				}
				
				if (!strcmp(p4, "r"))
				{
					routerip.s_addr=getip(p5);
					if(routerip.s_addr)
						ciscop->ip.s_addr=routerip.s_addr;	/* save router ip */
					continue;
				}
				if(!strcmp(p4, "u"))
				{
					safecopy(ciscop->username,p5);			/* save username */
					continue;
				}
				if(!strcmp(p4, "p"))
				{
					safecopy(ciscop->telnetpw,p5);			/* save telnet password */
					continue;
				}
				if(!strcmp(p4, "e"))
				{
					safecopy(ciscop->enablepw,p5);			/* save enable password */
					continue;
				}
				if(!strcmp(p4, "t"))
				{
					safecopy(ciscop->routetag,p5);			/* save route tag */
					continue;
				}
				if(!strcmp(p4, "a"))
				{
					if(!strcasecmp(p5, "y"))
						ciscop->autoenable=TRUE;		/* set autoenable */
					continue;
				}
				
				snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Skipping unknown option '%s' (%s)",file,line,p4,p5);
				logmessage(1,msg,"cisconullroute2",0);
			}
		}
		
		if(!ciscop->ip.s_addr)
		{
			snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] No router specified, CiscoNullRoute2 Plugin disabled",file,line);
			logmessage(1,msg,"cisconullroute2",0);
			free(ciscop);
			plugindatalist->data=NULL;
			return;
		}
		
		if(ciscop->username[0])
			ciscop->userlogin=TRUE;
		
		if(!ciscop->telnetpw[0])
		{
			snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] No password specified, CiscoNullRoute2 Plugin disabled",file,line);
			logmessage(1,msg,"cisconullroute2",0);
			free(ciscop);
			plugindatalist->data=NULL;
			return;
		}
		
		if(ciscop->routetag[0] && !((strtoul(ciscop->routetag,NULL,10))>=(unsigned long)RTAGVAL_MIN && (strtoul(ciscop->routetag,NULL,10))<=(unsigned long)RTAGVAL_MAX))
		{
			snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid CiscoNullRoute2 route tag value '%s' (min: %lu, max: %lu), CiscoNullRoute2 Plugin disabled",
				file,line,ciscop->routetag,(unsigned long)RTAGVAL_MIN,(unsigned long)RTAGVAL_MAX);
			logmessage(1,msg,"cisconullroute2",0);
			free(ciscop);
			plugindatalist->data=NULL;
			return;
		}			
		
		if(!ciscop->enablepw[0])
			safecopy(ciscop->enablepw,ciscop->telnetpw);	/* If no enable password specified, make it the same as telnet password */

#ifdef FWSAMDEBUG
		printf("Debug: [cisconullroute2] Adding Cisco Router: IP \"%s\", USER \"%s\", PW \"%s\", EN \"%s\", TAG \"%s\", AUTO-ENABLE \"%s\"\n",
			inettoa(ciscop->ip.s_addr),ciscop->userlogin?ciscop->username:"(none)",ciscop->telnetpw,ciscop->enablepw,ciscop->routetag[0]?ciscop->routetag:"(none)",ciscop->autoenable?"y":"n");
#endif
	}
	else
	{	
		snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Empty CiscoNullRoute2 parameter.",file,line);
		logmessage(1,msg,"cisconullroute2",0);
	}
}


/* This routine initiates the block. It walks the list of routers
 * telnet's in, and issues the route command.
 */
void CiscoNullRoute2Block(BLOCKINFO *bd,void *data,unsigned long qp)
{
	CISCONULLROUTE2DATA *ciscop;
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
    ciscop=(CISCONULLROUTE2DATA *)data;
	
#ifdef FWSAMDEBUG
	printf("Debug: [cisconullroute2][%lx] Plugin Blocking...\n",(unsigned long)threadid);
#endif
	
	snprintf(cnrat,sizeof(cnrat)-1,"router at %s",inettoa(ciscop->ip.s_addr));
	
	if(!ciscop->routersocket)
	{	
		routersocketaddr.sin_port=htons(23); /* telnet */
		routersocketaddr.sin_addr.s_addr=ciscop->ip.s_addr;
		routersocketaddr.sin_family=AF_INET;
		
		thissocketaddr.sin_port=htons(0); /* get a dynamic port  */
		thissocketaddr.sin_addr.s_addr=0;
		thissocketaddr.sin_family=AF_INET;
		
		/* create socket */
		ciscop->routersocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
		if(ciscop->routersocket==INVALID_SOCKET)
		{	
			snprintf(cnrmsg,sizeof(cnrmsg)-1,"Error: [cisconullroute2] Couldn't create socket!");
			logmessage(1,cnrmsg,"cisconullroute2",ciscop->ip.s_addr);
			ciscop->routersocket=0;
			return;
		}
		/* bind it */
		if(bind(ciscop->routersocket,(struct sockaddr *)&(thissocketaddr),sizeof(struct sockaddr)))
		{	
			snprintf(cnrmsg,sizeof(cnrmsg)-1,"Error: [cisconullroute2] Couldn't bind socket!");
			logmessage(1,cnrmsg,"ciscocnullroute",ciscop->ip.s_addr);
			ciscop->routersocket=0;
			return;
		}
		/* and connect to router */
		if(connect(ciscop->routersocket,(struct sockaddr *)&routersocketaddr,sizeof(struct sockaddr))) 
		{	
			snprintf(cnrmsg,sizeof(cnrmsg)-1,"Error: [cisconullroute2] Could not connect to %s! Will try later.",cnrat);
			logmessage(1,cnrmsg,"cisconullroute2",ciscop->ip.s_addr);
			closesocket(ciscop->routersocket);
			ciscop->routersocket=0;
		}
	}
	if(ciscop->routersocket)
	{	
		do
		{
#ifdef FWSAMDEBUG
			printf("Debug: [cisconullroute2][%lx] Connected to %s.\n",(unsigned long)threadid,cnrat);
#endif
			flag=-1;
			ioctlsocket(ciscop->routersocket,FIONBIO,&flag);	/* set non blocking  */
			flag=FALSE;
			
			if(!ciscop->loggedin)
			{	
				if(ciscop->userlogin)
				{	
					if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,"","username","waiting for user logon prompt from ",cnrat))
					{	
						flag=TRUE;
						continue;
					}
					snprintf(cnrmsg,sizeof(cnrmsg)-1,"%s\r",ciscop->username);	/* Send username */
					
					if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,cnrmsg,"pass","at password prompt from ",cnrat))
					{	
						flag=TRUE;
						continue;
					}
				}
				else
				{	
					if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,"","pass","waiting for logon prompt from ",cnrat))
					{	
						flag=TRUE;
						continue;
					}
				}
				
				snprintf(cnrmsg,sizeof(cnrmsg)-1,"%s\r",ciscop->telnetpw);	/* Send telnet password */
				
				if(ciscop->autoenable)
				{
					if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,cnrmsg,"#","at enable prompt of ",cnrat))
					{	
						flag=TRUE;
						continue;
					}
				}
				else
				{
					if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,cnrmsg,">","at logon prompt of ",cnrat))
					{	
						flag=TRUE;
						continue;
					}
					
					/* Send enable */																
					if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,"enable\r","pass","at enable command of ",cnrat))
					{	
						flag=TRUE;
						continue;
					}
				
					/* Send enable password */
					snprintf(cnrmsg,sizeof(cnrmsg)-1,"%s\r",ciscop->enablepw);	
					if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,cnrmsg,"#","at enable prompt of ",cnrat))
					{	
						flag=TRUE;
						continue;
					}
				}
				
				/* Send config */
				if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,"config t\r","#","at config command of ",cnrat))
				{	
					flag=TRUE;
					continue;
				}
				ciscop->loggedin=TRUE;
			}
			
			/* send route command */
			snprintf(cnrmsg,sizeof(cnrmsg)-1,"%sip route %s 255.255.255.255 null 0%s%s\r",
				bd->block?"":"no ",inettoa(bd->blockip),ciscop->routetag[0]?" tag ":"",ciscop->routetag[0]?ciscop->routetag:"");
			if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,cnrmsg,"#","at route command of ",cnrat))
			{	
				flag=TRUE;
				continue;
			}
			
			if(!moreinqueue(qp))
			{	
				/* End input */
				if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,"\032","#","at CTRL-Z of ",cnrat))
				{	
					flag=TRUE;
					continue;
				}
				
				/* Save config */
				if(!sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,"write mem\r","#","at write mem command of ",cnrat))
				{	
					flag=TRUE;
					continue;
				}
				
				/* and we're outta here... */
				sendreceive(ciscop->routersocket,CNRNETWAIT,"cisconullroute2",ciscop->ip,"quit\r","","at quit command of ",cnrat);
				flag=TRUE;
			}
		}while(FALSE);
		
		if(flag)
		{	
			closesocket(ciscop->routersocket);
			ciscop->routersocket=0;
			ciscop->loggedin=FALSE;
		}
	}
}

#endif /* __SSP_CISCO_NULLROUTE2_C__ */






