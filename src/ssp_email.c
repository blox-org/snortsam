/* $Id: ssp_email.c,v 2.12 2008/04/26 19:50:56 fknobbe Exp $
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
 *
 * ssp_email.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin sends an email with a notification of the block/unblock.
 * It connects to a specified mail server and sends to a specified recipient via
 * standard SMTP (not ESMTP) commands.
 *
 * AUTHENTICATION (AUTH) AND/OR ENCRYPTION (OVER SSL) IS NOT SUPPORTED.
 * If you need to authenticate to your mail server, or prefer SMTP over SSL,
 * please use a program like swatch to check for changes in the log file and
 * have a third party mailer send them. (This is recommended for performance
 * reasons anyway). 
 *
 *
 */


#ifndef		__SSP_EMAIL_C__
#define		__SSP_EMAIL_C__


#include "snortsam.h"
#include "ssp_email.h"

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


extern unsigned int disablereverselookups;


/* This routine parses the email statements in the config file
 * and builds a list of email servers/recipients.
*/
void EmailParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	EMAILDATA *emailp;
	char *p2,msg[STRBUFSIZE+2],*port=NULL;
	struct in_addr emailip;

#ifdef FWSAMDEBUG
	printf("Debug: [email] Plugin Parsing...\n");
#endif

	if(*val)
	{	p2=val;
		while(*p2 && !myisspace(*p2) && *p2!=':')
			p2++;
		if(*p2==':')
		{	*p2++ =0;
			while(*p2==':' || myisspace(*p2))
				p2++;
			port=p2;
			while(*p2 && !myisspace(*p2))
				p2++;
		}	
		*p2++ =0;
		
		emailip.s_addr=getip(val);
		if(emailip.s_addr)			/* If we have a valid IP address */
		{	emailp=safemalloc(sizeof(EMAILDATA),"EmailParse","emailp");	/* create new email struct */
			plugindatalist->data=emailp;
			emailp->ip.s_addr=emailip.s_addr;
			emailp->recipient[0]=emailp->sender[0]=0;
			emailp->mailsocket=0;
			emailp->loggedin=FALSE;
			emailp->port=25;
			if(port)
			{	if(atoi(port)>0)
					emailp->port=atoi(port);
			}			

			if(*p2)
			{	val=p2;
				while(*val && myisspace(*val))	/* now parse the remaining text */
					val++;
				if(val)
				{	p2=val;
					while(*p2 && !myisspace(*p2))
						p2++;

					if(*p2)
					{	*p2++ =0;
						safecopy(emailp->recipient,val);	/* save recipient */

						val=p2;
						while(*val && myisspace(*val))	/* has a sender name been specified? */
							val++;
						if(val)
						{	p2=val;
							while(*p2 && !myisspace(*p2))
								p2++;
							*p2=0;
							safecopy(emailp->sender,val);	/* save sender */
						}
					}
					else
					{	*p2=0;
						safecopy(emailp->recipient,val);	/* save recipient */
					}
				}
			}
			if(!emailp->recipient[0])
			{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] EMAIL defined without recipient!",file,line);
				logmessage(1,msg,"email",0);
				free(emailp);
				plugindatalist->data=NULL;
			}
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid EMAIL server '%s' ignored.",file,line,val);
			logmessage(1,msg,"email",0);
		}
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Empty EMAIL parameter.",file,line);
		logmessage(1,msg,"email",0);
	}
}


/* This routine sends the email only on block events, not unblock
 */
void EmailSendBlockOnly(BLOCKINFO *bd,void *data,unsigned long qp)
{ 	if(bd->block)
		EmailSend(bd,data,qp);
}

/* This routine sends the email
 */
void EmailSend(BLOCKINFO *bd,void *data,unsigned long qp)
{   EMAILDATA *emailp;
	struct sockaddr_in thissocketaddr,emailsocketaddr;
	unsigned long ll;
	char emailmsg[4000],serverat[STRBUFSIZE+2],edate[42],msg[STRBUFSIZE+2],msg2[STRBUFSIZE+2],host[STRBUFSIZE+2];
	struct tm *timep;
	signed int timediff,gth;
	struct protoent *protoe;
	time_t	notetime;
#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif
#endif

	if(!data)
		return;
	emailp=(EMAILDATA *)data;

#ifdef FWSAMDEBUG
	printf("Debug: [email][%lx] Plugin Sending Mail...\n",(unsigned long)threadid);
#endif

	notetime=bd->blocktime;
	if(!bd->block)
		notetime+=bd->duration;
	timep=gmtime((time_t *)&(notetime));
	gth=timep->tm_hour;
	timep=localtime((time_t *)&(notetime));
	strftime(edate,40,"%a, %d %b %Y %H:%M:%S",timep);
	timediff=timep->tm_hour-gth;
	if(timediff>12)
		timediff-=24;
	else if(timediff<-12)
		timediff+=24;
	
	snprintf(serverat,sizeof(serverat)-1,"mail server at %s",inettoa(emailp->ip.s_addr));
		
	if(!emailp->mailsocket)
	{	emailsocketaddr.sin_port=htons(emailp->port); 
		emailsocketaddr.sin_addr.s_addr=emailp->ip.s_addr;
		emailsocketaddr.sin_family=AF_INET;
		thissocketaddr.sin_port=htons(0); /* get a dynamic port  */
		thissocketaddr.sin_addr.s_addr=0;
		thissocketaddr.sin_family=AF_INET;
		/* create socket */
		emailp->mailsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
		if(emailp->mailsocket==INVALID_SOCKET)
		{	snprintf(emailmsg,sizeof(emailmsg)-1,"Error: [email] Couldn't create socket!");
			logmessage(1,emailmsg,"email",emailp->ip.s_addr);
			emailp->mailsocket=0;
			return;
		}
		/* bind it */
		if(bind(emailp->mailsocket,(struct sockaddr *)&(thissocketaddr),sizeof(struct sockaddr)))
		{	snprintf(emailmsg,sizeof(emailmsg)-1,"Error: [email] Couldn't bind socket!");
			logmessage(1,emailmsg,"email",emailp->ip.s_addr);
			emailp->mailsocket=0;
			return;
		}
		/* and connect to mail server */
		if(connect(emailp->mailsocket,(struct sockaddr *)&emailsocketaddr,sizeof(struct sockaddr))) 
		{	snprintf(emailmsg,sizeof(emailmsg)-1,"Error: [email] Could not connect to %s! Will try later.",serverat);
			logmessage(1,emailmsg,"email",emailp->ip.s_addr);
			closesocket(emailp->mailsocket);
			emailp->mailsocket=0;
		}
	}

	if(emailp->mailsocket)
	{	do
		{
#ifdef FWSAMDEBUG
			printf("Debug: [email][%lx] Connected to %s.\n",(unsigned long)threadid,serverat);
#endif
			ll=1;
			ioctlsocket(emailp->mailsocket,FIONBIO,&ll);	/* set non blocking  */
			
			ll=FALSE;
			
			if(!emailp->loggedin)
			{	
				if(!sendreceive(emailp->mailsocket,EMAILNETWAIT,"email",emailp->ip,"","220","waiting for banner on ",serverat))
				{	ll=TRUE;
					continue;
				}
				snprintf(emailmsg,sizeof(emailmsg)-1,"HELO %s\r\n",myhostname);	/* send helo */
				if(!sendreceive(emailp->mailsocket,EMAILNETWAIT,"email",emailp->ip,emailmsg,"250","after HELO on ",serverat))
				{	ll=TRUE;
					continue;
				}
				emailp->loggedin=TRUE;
			}
			snprintf(emailmsg,sizeof(emailmsg)-1,"RSET\r\n");	/* send reset */
			if(!sendreceive(emailp->mailsocket,EMAILNETWAIT,"email",emailp->ip,emailmsg,"250","after RSET on ",serverat))
			{	ll=TRUE;
				continue;
			}
			if(emailp->sender[0])
				snprintf(emailmsg,sizeof(emailmsg)-1,"MAIL FROM:<%s>\r\n",emailp->sender);	/* send mail from */
			else
				snprintf(emailmsg,sizeof(emailmsg)-1,"MAIL FROM:<SnortSam@%s>\r\n",myhostname);	/* send mail from */
			if(!sendreceive(emailp->mailsocket,EMAILNETWAIT,"email",emailp->ip,emailmsg,"250","after MAIL FROM on ",serverat))
			{	ll=TRUE;
				continue;
			}
			snprintf(emailmsg,sizeof(emailmsg)-1,"RCPT TO:<%s>\r\n",emailp->recipient);	/* send rcpt to */
			if(!sendreceive(emailp->mailsocket,EMAILNETWAIT,"email",emailp->ip,emailmsg,"250","after RCPT TO on ",serverat))
			{	ll=TRUE;
				continue;
			}
			snprintf(emailmsg,sizeof(emailmsg)-1,"DATA\r\n");	/* send reset */
			if(!sendreceive(emailp->mailsocket,EMAILNETWAIT,"email",emailp->ip,emailmsg,"354","after DATA on ",serverat))
			{	ll=TRUE;
				continue;
			}

			if(disablereverselookups)
				snprintf(host,sizeof(host)-1,"%s",inettoa(bd->blockip));
			else
				snprintf(host,sizeof(host)-1,"%s (%s)",inettoa(bd->blockip),gethstname(bd->blockip));
				
			if(bd->block)
			{	switch(bd->mode&FWSAM_HOW)
				{	case FWSAM_HOW_THIS:
						protoe=getprotobynumber(bd->proto);
						snprintf(msg,sizeof(msg)-1, "Blocking host %s in connection %s->%s:%d (%s) for %lu seconds.",
							host,bd->mode&FWSAM_WHO_SRC?inettoa(bd->blockip):inettoa(bd->peerip),bd->mode&FWSAM_WHO_SRC?inettoa(bd->peerip):inettoa(bd->blockip),bd->port,protoe->p_name,(unsigned long)bd->duration);
					break;
					case FWSAM_HOW_IN:
						snprintf(msg,sizeof(msg)-1,	"Blocking host %s inbound for %lu seconds.",host,(unsigned long)bd->duration);
					break;
					case FWSAM_HOW_OUT:
						snprintf(msg,sizeof(msg)-1, "Blocking host %s outbound for %lu seconds.",host,(unsigned long)bd->duration);
					break;
					case FWSAM_HOW_INOUT:
						snprintf(msg,sizeof(msg)-1, "Blocking host %s completely for %lu seconds.",host,(unsigned long)bd->duration);
					break;
					default:
						snprintf(msg,sizeof(msg)-1, "Blocking host %s in a weird way for %lu seconds. (Let me know if you see this message!)",host,(unsigned long)bd->duration);
					break;
				}
				snprintf(msg2,sizeof(msg2)-1,"This block was triggered by signature ID: %lu",bd->sig_id);
				snprintf(emailmsg,sizeof(emailmsg)-1,"From: %s%s\r\nTo: %s\r\nSubject: Blocked IP Address %s\r\nDate: %s %+.2i00\r\n\r\n%s\r\n\r\n%s\r\n\r\n.\r\n",
									emailp->sender[0]?emailp->sender:"SnortSam@",emailp->sender[0]?"":myhostname,emailp->recipient,
									inettoa(bd->blockip),edate,timediff,msg,msg2);	/* send message */
			}
			else
			{	switch(bd->mode&FWSAM_HOW)
				{	case FWSAM_HOW_THIS:
						protoe=getprotobynumber(bd->proto);
						snprintf(msg,sizeof(msg)-1, "Removing %lu sec block for host %s in connection %s->%s:%d (%s).",
							(unsigned long)bd->duration,host,bd->mode&FWSAM_WHO_SRC?inettoa(bd->blockip):inettoa(bd->peerip),bd->mode&FWSAM_WHO_SRC?inettoa(bd->peerip):inettoa(bd->blockip),bd->port,protoe->p_name);
					break;
					case FWSAM_HOW_IN:
						snprintf(msg,sizeof(msg)-1, "Removing %lu sec inbound block for host %s.",(unsigned long)bd->duration,host);
					break;
					case FWSAM_HOW_OUT:
						snprintf(msg,sizeof(msg)-1, "Removing %lu sec outbound block for host %s.",(unsigned long)bd->duration,host);
					break;
					case FWSAM_HOW_INOUT:
						snprintf(msg,sizeof(msg)-1, "Removing %lu sec complete block for host %s.",(unsigned long)bd->duration,host);
					break;
					default:
						snprintf(msg,sizeof(msg)-1, "Removing weird %lu sec block for host %s.",(unsigned long)bd->duration,host);
					break;
				}
				snprintf(msg2,sizeof(msg2)-1,"The block was originally triggered by signature ID: %lu",bd->sig_id);
				snprintf(emailmsg,sizeof(emailmsg)-1,"From: %s%s\r\nTo: %s\r\nSubject: Unblocked IP Address %s\r\nDate: %s %+.2i00\r\n\r\n%s\r\n\r\n%s\r\n\r\n.\r\n",
									emailp->sender[0]?emailp->sender:"SnortSam@",emailp->sender[0]?"":myhostname,emailp->recipient,
									inettoa(bd->blockip),edate,timediff,msg,msg2);	/* send message */
			}
			if(!sendreceive(emailp->mailsocket,EMAILNETWAIT,"email",emailp->ip,emailmsg,"250","after message on ",serverat))
			{	ll=TRUE;
				continue;
			}

			if(!moreinqueue(qp))
			{	snprintf(emailmsg,sizeof(emailmsg)-1,"QUIT\r\n");	/* send reset */
				sendreceive(emailp->mailsocket,EMAILNETWAIT,"email",emailp->ip,emailmsg,"","after QUIT on ",serverat);
				ll=TRUE;
			}
		}while(FALSE);

		if(ll)
		{	closesocket(emailp->mailsocket);
			emailp->mailsocket=0;
			emailp->loggedin=FALSE;
		}
	}

#ifdef FWSAMDEBUG
	printf("Debug: [email][%lx] Email has been sent. Now waiting 10 secs...\n",(unsigned long)threadid);
	waitms(10000);
	printf("Debug: Done waiting... ending thread %lx.\n",(unsigned long)threadid);
#endif
}

#endif /* __SSP_EMAIL_C__ */






