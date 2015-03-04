/* $Id: ssp_netscreen.c,v 2.10 2009/11/27 01:39:40 fknobbe Exp $
 *
 *
 * Copyright (c) 2002-2008 Frank Knobbe <frank@knobbe.us>
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
 * Thanks to Christopher Lyon for his assistance in the concept, support,
 * and providing a test environment.
 *
 *
 *
 * ssp_netscreen.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin telnet's into one or more Netscreen firewalls,
 * setups up a global group for blocked addresses, and then adds
 * blocked IP address to this group. SnortSam will also expire the blocks
 * itself since the Netscreen does not have automatic time-out functionality.
 *
 * Comments:
 *
 * Since only whole IP's can be placed into the address group for blocking,
 * only complete addresses are blocked. That means that service pairs
 * (src-dst:port) can not be individually be blocked. Any such request
 * will result in the whole IP being blocked.
 *
 * It is theoratically possible to block service pairs, but that would require
 * rewriting the existing rulebase completely to insert the service pairs on
 * top of the rule base. Because this is very invasive and time consuming,
 * the only practical way of blocking is by adding addresses to the Blocked group.
 *
 */


#ifndef		__SSP_NETSCREEN_C__
#define		__SSP_NETSCREEN_C__


#include "snortsam.h"
#include "ssp_netscreen.h"


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



						
/* This routine checks the version of the given NetScreen box. It is called as part of parse,
 * but also as part of Block if it didn't run before.
 * It issues the GET SYSTEM command and note the software version. 
*/

int NetScrnCheckVersion(SOCKET nssocket,NETSCRNDATA *nsp,char *nsat)
{	char *p,*p2,msg[STRBUFSIZE+1];

	if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,"get system\r","software version: ","at get system command ",nsat))
		return FALSE;
	recv(nssocket,msg,40,0);
	msg[40]=0;
	p2=msg;
	while(*p2 && !myisdigit(*p2))
		p2++;
	p=p2;
	while(*p2 && myisdigit(*p2))
		p2++;
	*p2=0;
	nsp->software_version=(unsigned char)atoi(p);
	
	if(!*(nsp->zone))
	{	switch(nsp->software_version)
		{	case 4:		safecopy(nsp->zone,"V1-Untrust");
					break;
			case 3:
			default:	safecopy(nsp->zone,"untrust");
					break;
		}
	}
	return TRUE;
}

/* This routine parses the netscreen statements in the config file.
 * It builds a list of firewalls)
*/
void NetScrnParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	NETSCRNDATA *nsp;
	char *p2,msg[STRBUFSIZE+1],nsat[STRBUFSIZE+1];
	struct in_addr nsip;
	struct sockaddr_in thissocketaddr,nssocketaddr;
	SOCKET nssocket;
	unsigned long flag;

#ifdef FWSAMDEBUG
	printf("Debug: [netscrn] Plugin Parsing...\n");
#endif

	if(*val)
	{	p2=val;
		while(*p2 && !myisspace(*p2))
			p2++;
		if(*p2)
			*p2++ =0;
		nsip.s_addr=getip(val);
		if(nsip.s_addr)			/* If we have a valid IP address */
		{	nsp=safemalloc(sizeof(NETSCRNDATA),"NetScrnParse","nsp");	/* create new netscreen */
			plugindatalist->data=nsp;
			nsp->ip.s_addr=nsip.s_addr;
			nsp->software_version=0;			/* no version discovered yet */
			nsp->loginid[0]=nsp->loginpw[0]=0;
			safecopy(nsp->denygroup,"SnortSam");  /* set default group */
			nsp->zone[0]=0;

			if(*p2)
			{	val=p2;
				while(*val && myisspace(*val))		/* skip spaces */
					val++;
				if(val)
				{	p2=val;
					while(*p2 && !myisspace(*p2))	/* parse id */
						p2++;
					if(*p2)
						*p2++ =0;
					safecopy(nsp->loginid,val);	/* save user id */
					
					if(*p2)									/* if we have a password */
					{	val=p2;
						while(*val && myisspace(*val))		/* skip spaces */
							val++;
						if(val)
						{	p2=val;
							while(*p2 && !myisspace(*p2))	/* parse it */
								p2++;
							if(*p2)
								*p2++ =0;
							safecopy(nsp->loginpw,val);	/* save password */
	
							if(*p2)									/* if we have a group name */
							{	val=p2;
								while(*val && myisspace(*val))		/* skip spaces */
									val++;
								if(val)
								{	p2=val;
									while(*p2 && !myisspace(*p2))	/* parse it */
										p2++;
									if(*p2)
										*p2++ =0;
									safecopy(nsp->denygroup,val);	/* save group name */
								}

								if(*p2)									/* if we have a zone name */
								{	val=p2;
									while(*val && myisspace(*val))		/* skip spaces */
										val++;
									if(val)
									{	p2=val;
										while(*p2 && !myisspace(*p2))	/* parse it */
											p2++;
										if(*p2)
											*p2++ =0;
										safecopy(nsp->zone,val);		/* save optional zone name */
									}
								}
							}
						}
					}
				}
			}
			if(!nsp->loginid[0])
			{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Netscreen defined without login ID!",file,line);
				logmessage(1,msg,"netscrn",0);
				free(nsp);
				plugindatalist->data=NULL;
			}
			else if(!nsp->loginpw[0])
			{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Netscreen defined without login password!",file,line);
				logmessage(1,msg,"netscrn",0);
				free(nsp);
				plugindatalist->data=NULL;
			}
			else
			{
				snprintf(nsat,sizeof(nsat)-1,"NetScreen at %s",inettoa(nsp->ip.s_addr));

				nssocketaddr.sin_port=htons(23); /* telnet */
				nssocketaddr.sin_addr.s_addr=nsp->ip.s_addr;
				nssocketaddr.sin_family=AF_INET;

				thissocketaddr.sin_port=htons(0); /* get a dynamic port  */
				thissocketaddr.sin_addr.s_addr=0;
				thissocketaddr.sin_family=AF_INET;

				/* create socket */
				nssocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
				if(nssocket==INVALID_SOCKET)
				{	snprintf(msg,sizeof(msg)-1,"Error: [netscrn] Couldn't create socket!");
					logmessage(1,msg,"netscrn",nsp->ip.s_addr);
					return;
				}
				/* bind it */
				if(bind(nssocket,(struct sockaddr *)&(thissocketaddr),sizeof(struct sockaddr)))
				{	snprintf(msg,sizeof(msg)-1,"Error: [netsrcn] Couldn't bind socket!");
					logmessage(1,msg,"netscrn",nsp->ip.s_addr);
					return;
				}
				/* and connect to netscreen */
				if(connect(nssocket,(struct sockaddr *)&nssocketaddr,sizeof(struct sockaddr))) 
				{	snprintf(msg,sizeof(msg)-1,"Error: [netscrn] Could not connect to %s! Will try later.",nsat);
					logmessage(1,msg,"netscrn",nsp->ip.s_addr);
				}
				else
				{	do
					{
						flag=-1;
						ioctlsocket(nssocket,FIONBIO,&flag);	/* set non blocking  */
			
						if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,"","login","waiting for logon prompt from ",nsat))
							continue;

						snprintf(msg,sizeof(msg)-1,"%s\r",nsp->loginid);	/* send login id */
						if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,msg,"password","at logon prompt of ",nsat))
							continue;

						snprintf(msg,sizeof(msg)-1,"%s\r",nsp->loginpw);	/* send login password */
						if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,msg,"->","at password prompt of ",nsat))
							continue;
				
						/* Check for the version of the NetScreen box */
						if(!NetScrnCheckVersion(nssocket,nsp,nsat))
							continue;
						
						sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,"exit\r","","at exit ",nsat); /* exit */
					}while(FALSE);
				}
#ifdef FWSAMDEBUG
				printf("Debug: [netscrn] Adding Netscreen: IP \"%s\", ID \"%s\", PW \"%s\", Group \"%s\", Version \"%u\"\n",inettoa(nsp->ip.s_addr),nsp->loginid,nsp->loginpw,nsp->denygroup,(unsigned int)nsp->software_version);
#endif
				}
			}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid NetSscreen parameter '%s' ignored.",file,line,val);
			logmessage(1,msg,"netscrn",0);
		}
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Empty NetScreen parameter.",file,line);
		logmessage(1,msg,"netscrn",0);
	}
}


/* This routine initiates the block. It walks the list of Netscreen
 * firewalls, telnet's in, and adds IP address to the deny group.
 */
void NetScrnBlock(BLOCKINFO *bd,void *data,unsigned long qp)
{   NETSCRNDATA *nsp;
	struct sockaddr_in thissocketaddr,nssocketaddr;
	SOCKET nssocket;
	unsigned long flag;
	char msg[STRBUFSIZE+1],nsat[STRBUFSIZE+1];
#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif
#endif

	if(!data)
		return;
	nsp=(NETSCRNDATA *)data;

#ifdef FWSAMDEBUG
	printf("Debug: [netsrcn][%lx] Plugin Blocking...\n",(unsigned long)threadid);
#endif
	
	snprintf(nsat,sizeof(nsat)-1,"NetScreen at %s",inettoa(nsp->ip.s_addr));
	
	nssocketaddr.sin_port=htons(23); /* telnet */
	nssocketaddr.sin_addr.s_addr=nsp->ip.s_addr;
	nssocketaddr.sin_family=AF_INET;

	thissocketaddr.sin_port=htons(0); /* get a dynamic port  */
	thissocketaddr.sin_addr.s_addr=0;
	thissocketaddr.sin_family=AF_INET;

	/* create socket */
	nssocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
	if(nssocket==INVALID_SOCKET)
	{	snprintf(msg,sizeof(msg)-1,"Error: [netscrn] Couldn't create socket!");
		logmessage(1,msg,"netscrn",nsp->ip.s_addr);
		return;
	}
	/* bind it */
	if(bind(nssocket,(struct sockaddr *)&(thissocketaddr),sizeof(struct sockaddr)))
	{	snprintf(msg,sizeof(msg)-1,"Error: [netsrcn] Couldn't bind socket!");
		logmessage(1,msg,"netscrn",nsp->ip.s_addr);
		return;
	}
	/* and connect to netscreen */
	if(connect(nssocket,(struct sockaddr *)&nssocketaddr,sizeof(struct sockaddr))) 
	{	snprintf(msg,sizeof(msg)-1,"Error: [netscrn] Could not connect to %s! Will try later.",nsat);
		logmessage(1,msg,"netscrn",nsp->ip.s_addr);
	}
	else
	{	do
		{
#ifdef FWSAMDEBUG
			printf("Debug: [netscrn][%lx] Connected to %s.\n",(unsigned long)threadid,nsat);
#endif
			flag=-1;
			ioctlsocket(nssocket,FIONBIO,&flag);	/* set non blocking  */

			if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,"","login","waiting for logon prompt from ",nsat))
				continue;

			snprintf(msg,sizeof(msg)-1,"%s\r",nsp->loginid);	/* send login id */
			if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,msg,"password","at logon prompt of ",nsat))
				continue;

			snprintf(msg,sizeof(msg)-1,"%s\r",nsp->loginpw);	/* send login password */
			if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,msg,"->","at password prompt of ",nsat))
				continue;
				
			/* If we weren't able to get the version of the Netscreen box at startup, we'll try now. */
			if(!nsp->software_version)
			{	if(!NetScrnCheckVersion(nssocket,nsp,nsat))	/* If we still can't get a version, we'll assume version 3. */			
				{	safecopy(nsp->zone,"untrusted");
					nsp->software_version=3;
				}
			}
				
/* The deny group is set up at every block. This could be done just once, but if the group were to become erase on the firewall, */
/* Snortsam would have to be restarted to recreate the group. This seems safer... */

						if(bd->block)
						{	snprintf(msg,sizeof(msg)-1,"set group address %s \"%s\" comment \"SnortSam Block Rule\"\r",nsp->zone,nsp->denygroup);	/* setup deny group */
							if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,msg,"->","at group setup ",nsat))
								continue;

							snprintf(msg,sizeof(msg)-1,"set address %s \"Blocked_%s\" %s 255.255.255.255\r",nsp->zone,inettoa(bd->blockip),inettoa(bd->blockip)); /* create host object */
							if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,msg,"->","at set address ",nsat))
								continue;

							snprintf(msg,sizeof(msg)-1,"set group address %s \"%s\" add \"Blocked_%s\"\r",nsp->zone,nsp->denygroup,inettoa(bd->blockip)); /* add host to group */
							if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,msg,"->","at set group add ",nsat))
								continue;
						}
						else
						{	snprintf(msg,sizeof(msg)-1,"unset group address %s \"%s\" remove \"Blocked_%s\"\r",nsp->zone,nsp->denygroup,inettoa(bd->blockip)); /* remove host from group */
							if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,msg,"->","at unset group remove ",nsat))
								continue;

							snprintf(msg,sizeof(msg)-1,"unset address %s \"Blocked_%s\"\r",nsp->zone,inettoa(bd->blockip)); /* remove host object */
							if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,msg,"->","at set group add ",nsat))
								continue;
						}
						break;
	
			if(!sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,"save\r","->","at save ",nsat)) /* save config */
				continue;

			sendreceive(nssocket,NETSCRN_NETWAIT,"netscrn",nsp->ip,"exit\r","","at exit ",nsat); /* exit */

		}while(FALSE);
	}
	closesocket(nssocket);
}

#endif /* __SSP_NETSCREEN_C__ */






