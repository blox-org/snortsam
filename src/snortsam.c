/* $Id: snortsam.c,v 2.70 2011/02/20 18:26:17 fknobbe Exp $
 *
 *
 * Copyright (c) 2001-2009 Frank Knobbe <frank@knobbe.us>
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
 * SnortSam 
 * 
 * Purpose:  
 *
 * This is the remote module that listens for snort alerts generated with the 
 * Alert_FWsam plug-in. This module provides secure gateway functionality between 
 * the snort alerts and various firewalls. It listens to the snort alerts, and can
 * invoke a block on following firewalls:
 *  - Checkpoint Firewall-1 (by sending an OPSEC packet to port 18183, 
 *    either via the OPSEC API, or using a self-assembled packet, or by execution
 *    of the fw.exe through command line.
 *  - Cisco PIX (by telnetting into the PIX and issuing the SHUN command)
 *  - Cisco Routers (by telnetting ino the router and modifying the ACL)
 *  - Cisco Routers (by telnetting ino the router and adding a null-route)
 *  - Netscreen firewalls (by telnetting in the Netscreen and adding IP's to a group
 *    which is denied access in the policy)
 *  - BSD's IPfilter - ipf (by calling ipf to add drop rules for IP's)
 *  - BSD's IPFirewall2 - ipfw2 (by calling ipfw2 to add IP's into tables for drop)
 *  - OpenBSD's Packet Filter - pf (by using ioctl to to add drop rules for IP's)
 *  - IPchains - ipchain (by using do_setsockopt to add drop rules for IP's)
 *  - WatchGuard Firebox firewalls (by calling fbidsmate)
 *  - IPtables - iptables (by calling the iptables executable)
 *  - EBtables - ebtables (by calling the ebtables executable)
 *  - 8signs firewall (by calling the dwf executable)
 *  - MS ISA firewall/proxy (by calling API functions)
 *  - CHX-I firewall (by calling the fltcon executable)
 *
 * SnortSam also performs checks against a white-list of never-to-be-blocked IP addresses,
 * can override block durations (for example for known proxies), and can detect attack conditions
 * where too many blocks are received within a defined interval. If an attack is detected
 * it will unblock the last x blocks and wait for the attack to end.
 *
 * Arguments:
 *   
 * conf.file  (configuration file with lotsastuffinit)
 *
 * The communication over the network is encrypted using TwoFish.
 * (Implementation ripped from CryptCat by Farm9 with permission.)
 *
 * Comments:
 *
 *
 *
 *  
 */


#ifndef		__SNORTSAM_C__
#define		__SNORTSAM_C__


#define SNORTSAM_REV			"$Revision: 2.70 $"




#include "snortsam.h"
#include "plugins.h"


/* global vars */

unsigned long netmask[2][33]={{0,0x00000080, 0x000000c0, 0x000000e0, 0x000000f0, 0x000000f8, 0x000000fc, 0x000000fe,0x000000ff,
								 0x000080ff, 0x0000c0ff, 0x0000e0ff, 0x0000f0ff, 0x0000f8ff, 0x0000fcff, 0x0000feff,0x0000ffff,
								 0x0080ffff, 0x00c0ffff, 0x00e0ffff, 0x00f0ffff, 0x00f8ffff, 0x00fcffff, 0x00feffff,0x00ffffff,
								 0x80ffffff, 0xc0ffffff, 0xe0ffffff, 0xf0ffffff, 0xf8ffffff, 0xfcffffff, 0xfeffffff,0xffffffff},
							  {0,0x80000000, 0xc0000000, 0xe0000000, 0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000,0xff000000,
								 0xff800000, 0xffc00000, 0xffe00000, 0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000,0xffff0000,
								 0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00,0xffffff00,
								 0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe,0xffffffff}};

const unsigned long plugincount=sizeof(Plugins)/sizeof(PLUGINREGISTRY);

unsigned short mylistenport=FWSAM_DEFAULTPORT;
unsigned int loglevel=2,screenlevel=2,keepblockhistory=FALSE,holdsnort=FALSE,disableseqnocheck=FALSE;
unsigned int avoidstatefile=FALSE,savestatefile=FALSE,fwsamipflip=FALSE,daemonized=FALSE,wantdaemon=FALSE;
unsigned int disablereverselookups=FALSE,disablepersistentconnections=TRUE;
unsigned int dontusethreads=FALSE,usedontunblock=FALSE,useonlyblock=FALSE,useonlyunblock=FALSE;

char logfile[FILEBUFSIZE+2]="",statefile[FILEBUFSIZE+2]="",defaultkey[TwoFish_KEY_LENGTH+2]="";
char msg[STRBUFSIZE+2]="",myhostname[STRBUFSIZE+2]="";
time_t keyinterval=14400; /* in seconds: 4 hour default */
time_t rbsleeptime=900,rbmeterinterval=30; /* in seconds */
unsigned long rbhosts=0,rbmeterhosts=0,mybindip=0;
unsigned long skiphosts=10,currentskiphost=0,netmaskbigendian=0;
time_t skipinterval=10;
volatile int preparetodie=FALSE,signal_usr1=FALSE,signal_usr2=FALSE;

#ifndef WIN32
pthread_mutex_t inettoa_mutex,gethstname_mutex,loginprogress_mutex;
#endif

DONTBLOCKLIST *firstdontblock=NULL;
ONLYBLOCKLIST *firstonlyblock=NULL;
OVERRIDELIST *firstoverride=NULL;
LIMITLIST *firstlimit=NULL;
SIDFILTERLIST *firstsidfilter=NULL;
ACCEPTLIST *firstaccept=NULL;
SENSORLIST *firstsensor=NULL;
BLOCKINFO *skiphostsfield=NULL;
BLOCKHISTORY *firstblockhistory=NULL;
SOCKET mysock=0,callersock=0;
DATALIST FirstPluginData[sizeof(Plugins)/sizeof(PLUGINREGISTRY)];
THREADTABLE *threadtable;

BLOCKQUEUE BlockQueue[BLOCKQUEUESIZE];
unsigned long BQ_writepointer=0;

unsigned long PluginStatus[sizeof(Plugins)/sizeof(PLUGINREGISTRY)];
unsigned long PluginIndex[sizeof(Plugins)/sizeof(PLUGINREGISTRY)];
unsigned long PluginsActive=0,maxpluginthreads=0;



/* Don't know where I found this. It just lists the Winsock error message. 
*/
void showerror(void)
{
#ifdef WIN32				
	switch (WSAGetLastError())
	{	case WSAEINTR          : puts("INTR          "); break;
		case WSAEBADF          : puts("BADF          "); break;
		case WSAEACCES         : puts("ACCES         "); break;
		case WSAEFAULT         : puts("FAULT         "); break;
		case WSAEINVAL         : puts("INVAL         "); break;
		case WSAEMFILE         : puts("MFILE         "); break;
		case WSAEWOULDBLOCK    : puts("WOULDBLOCK    "); break;
		case WSAEINPROGRESS    : puts("INPROGRESS    "); break;
		case WSAEALREADY       : puts("ALREADY       "); break;
		case WSAENOTSOCK       : puts("NOTSOCK       "); break;
		case WSAEDESTADDRREQ   : puts("DESTADDRREQ   "); break;
		case WSAEMSGSIZE       : puts("MSGSIZE       "); break;
		case WSAEPROTOTYPE     : puts("PROTOTYPE     "); break;
		case WSAENOPROTOOPT    : puts("NOPROTOOPT    "); break;
		case WSAEPROTONOSUPPORT: puts("PROTONOSUPPORT"); break;
		case WSAESOCKTNOSUPPORT: puts("SOCKTNOSUPPORT"); break;
		case WSAEOPNOTSUPP     : puts("OPNOTSUPP     "); break;
		case WSAEPFNOSUPPORT   : puts("PFNOSUPPORT   "); break;
		case WSAEAFNOSUPPORT   : puts("AFNOSUPPORT   "); break;
		case WSAEADDRINUSE     : puts("ADDRINUSE     "); break;
		case WSAEADDRNOTAVAIL  : puts("ADDRNOTAVAIL  "); break;
		case WSAENETDOWN       : puts("NETDOWN       "); break;
		case WSAENETUNREACH    : puts("NETUNREACH    "); break;
		case WSAENETRESET      : puts("NETRESET      "); break;
		case WSAECONNABORTED   : puts("CONNABORTED   "); break;
		case WSAECONNRESET     : puts("CONNRESET     "); break;
		case WSAENOBUFS        : puts("NOBUFS        "); break;
		case WSAEISCONN        : puts("ISCONN        "); break;
		case WSAENOTCONN       : puts("NOTCONN       "); break;
		case WSAESHUTDOWN      : puts("SHUTDOWN      "); break;
		case WSAETOOMANYREFS   : puts("TOOMANYREFS   "); break;
		case WSAETIMEDOUT      : puts("TIMEDOUT      "); break;
		case WSAECONNREFUSED   : puts("connection refused"); break;
		case WSAELOOP          : puts("LOOP          "); break;
		case WSAENAMETOOLONG   : puts("NAMETOOLONG   "); break;
		case WSAEHOSTDOWN      : puts("HOSTDOWN      "); break;
		case WSAEHOSTUNREACH   : puts("HOSTUNREACH   "); break;
		case WSAENOTEMPTY      : puts("NOTEMPTY      "); break;
		case WSAEPROCLIM       : puts("PROCLIM       "); break;
		case WSAEUSERS         : puts("USERS         "); break;
		case WSAEDQUOT         : puts("DQUOT         "); break;
		case WSAESTALE         : puts("STALE         "); break;
		case WSAEREMOTE        : puts("REMOTE        "); break;
		case WSAEDISCON        : puts("DISCON        "); break;
		case WSASYSNOTREADY    : puts("SYSNOTREADY    "); break;
		case WSAVERNOTSUPPORTED: puts("VERNOTSUPPORTED"); break;
		case WSANOTINITIALISED : puts("NOTINITIALISED "); break;
		case WSAHOST_NOT_FOUND : puts("HOST_NOT_FOUND "); break;
		case WSATRY_AGAIN      : puts("TRY_AGAIN      "); break;
		case WSANO_RECOVERY    : puts("NO_RECOVERY    "); break;
		case WSANO_DATA        : puts("NO_DATA        "); break;
		default : puts("unknown socket error"); break;
	}
#endif
}

/*	This function (together with the define in snortsam.h) attempts
 *	to prevent buffer overflows by checking the destination buffer size.
*/
void _safecp(char *dst,unsigned long max,char *src)		
{	if(dst && src && max)
	{	while(--max>0 && *src)
			*dst++ = *src++;
		*dst=0;
	}
}

/* This function allocates memory and exists gracefully if not
 * enough memory is available
*/
void *safemalloc(unsigned long size,char *func,char *what)
{	void *buffer;

	buffer=malloc(size);
	if(!buffer)
	{	snprintf(msg,sizeof(msg)-1,"Error: Out of Memory in function '%s', allocating '%s'.",func,what);
		logmessage(1,msg,"snortsam",0);
		getout(1);
	}
	return buffer;
}

#ifdef _MYLIBCSTUFF
/*	These cause linker problem with the OPSEC link config in VC++.
 *	Had to use my own. Leave until linker problem is figured out.
 *	(libc.lib vs. msvcrt.lib when compiling with OPSEC APIs)
*/
char mytolower(char c)
{	if(c>='A' && c<='Z')
		c+=('a'-'A');
	return c;
}

int myisspace(unsigned char c)
{	if(c==0x20 || (c>=0x09 && c<=0x0D) || c==0xff)
		return TRUE;
	else
		return FALSE;
}

int myisdigit(char c)
{	if(c>='0' && c<='9')
		return TRUE;
	else
		return FALSE;
}
#endif


void waitms(unsigned int dur)
{
#ifdef WIN32
	Sleep(dur);
#else
	usleep(dur*1000);
#endif
}

/* This routine waits for certain text on the given socket, 
 * and returns TRUE if that text was received, or FALSE in case of a timeout
*/
int waitfor(SOCKET sock,char *text,unsigned long timeout)
{	char buf[52],smallbuf[4],search[52],*p;
	time_t starttime;
	unsigned int x,y;

	
	starttime=time(NULL);
	strncpy(search,text,50);
	search[50]=0;
	p=search;
	while(*p)
	{	*p=mytolower(*p);
		p++;
	}
	x=50-strlen(search);
	memset(buf,0,52);

	while(((unsigned long)time(NULL))-(unsigned long)starttime<=timeout) /* if we're still within time */
	{	while(recv(sock,smallbuf,1,0)==1)		/* read one byte from queue */
		{	buf[49]=mytolower(*smallbuf);
			y=x;
			p=search;
			while(*p==buf[y++] && *p)
				p++;

			if(!*p)
				return TRUE;				/* found a match */
		
			memcpy(buf,buf+1,49);				/* shift the ring buffer */
		}
		waitms(10);								/* just a 10ms breather to give the IP stack some time to catch up */
	}
	return FALSE;
}

/*	This routine sends out text to a socket and waits for response.
*/
int sendreceive(SOCKET socket,unsigned int timeout,char *plugin,struct in_addr ip,char *sendmsg,char *response,char *errmsg1,char *errmsg2)
{	int len;
#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif
#endif
	
    if(*sendmsg)
	{
		len=strlen(sendmsg);
#ifdef FWSAMDEBUG
		printf("Debug: [%s][%lx] Sending %i bytes to %s: %s\n",plugin,(unsigned long)threadid,len,inettoa(ip.s_addr),sendmsg);      /* send  */
#endif
		if(send(socket,sendmsg,len,0)!=len) /* weird...could not send */
		{	snprintf(msg, sizeof(msg)-1,"Error: [%s] Could not send %s%s!",plugin,errmsg1,errmsg2);
			logmessage(1,msg,plugin,ip.s_addr);
			return FALSE;
		}
	}
	if(*response)
	{
#ifdef FWSAMDEBUG
		printf("Debug: [%s][%lx] Waiting from %s for: %s\n",plugin,(unsigned long)threadid,inettoa(ip.s_addr),response);
#endif
		if(!waitfor(socket,response,timeout))                            /* wait for prompt */
		{	snprintf(msg, sizeof(msg)-1,"Error: [%s] Did not receive a response %s%s!",plugin,errmsg1,errmsg2);
			logmessage(1,msg,plugin,ip.s_addr);
			return FALSE;
		}
	}
	return TRUE;
}

/* This function checks if there are any plugin threads running at the moment.
*/
int threadsrunning(void)
{	unsigned long i=0;

	while(i<maxpluginthreads)
		if(threadtable[i++].threadid)
			return TRUE;
	return FALSE;
}

void clearhistory()
{	BLOCKHISTORY *bhp,*fbhp;

	bhp=firstblockhistory;
	while(bhp)
	{	fbhp=bhp;
		bhp=bhp->next;
		free(fbhp);
	}
	firstblockhistory=NULL;
}

/* clean exit function. Free's all allocated buffers.
*/
void getout(int ret)		
{	DONTBLOCKLIST *dbl;
	ONLYBLOCKLIST *obl;
	ACCEPTLIST *al;
	OVERRIDELIST *orl;
	LIMITLIST *ll;
	SIDFILTERLIST *sfl;
	DATALIST *dlp,*tdlp;
	SENSORLIST *sensor,*nextsensor;
	unsigned long i,threads;


	if(preparetodie)
		return;
		
	preparetodie=TRUE;	/*	Set prepare-to-die flag so that any other routines
							(Main network-wait routine and queue handler) don't run in case
							getout is called by a Signal. */
	signal(SIGTERM,SIG_IGN);
	signal(SIGINT,SIG_IGN);
	signal(SIGQUIT,SIG_IGN);
	signal(SIGUSR1,SIG_IGN);
	signal(SIGUSR2,SIG_IGN);
	signal(SIGHUP,SIG_IGN);
	
	printf("\n");

	if(ret<100)
	{	savehistory();	/* Flush whole blocked-chain to file */
		waitms(1000);
		if(callersock)
			closesocket(callersock);
		if(mysock)
			closesocket(mysock);
	
		if(!dontusethreads)
		{	if(threadsrunning())
			{	printf("\nWaiting up to 10 secs for plugin threads to finish...");
				i=1;
				while(threadsrunning() && i<=10)
				{	printf("%lu...",i++);
					waitms(1000);
				}				
				printf("\n");
				for(i=0,threads=FALSE;i<maxpluginthreads;i++)
				{	if(threadtable[i].threadid)
					{	threads=TRUE;
#ifdef WIN32
#ifdef FWSAMDEBUG
						printf("Debug: Canceling thread id %lx\n",threadtable[i].winthreadid);
#endif
						TerminateThread(threadtable[i].threadid,0);
#else
#ifdef FWSAMDEBUG
						printf("Debug: Canceling thread id %lx\n",(unsigned long)threadtable[i].threadid);
#endif
						pthread_cancel(threadtable[i].threadid);
#endif
					}
				}
				if(threads)
					waitms(2000); /* wait to give threads time to finish */
			}
		}

		for(i=0;i<PluginsActive;i++)		/* Call plugin exit routines */
		{	if(Plugins[PluginIndex[i]].PluginExit)
			{	printf("Terminating plugin '%s'.\n",Plugins[PluginIndex[i]].PluginHandle);
				Plugins[PluginIndex[i]].PluginExit(&(FirstPluginData[PluginIndex[i]]));
			}
		}
		clearhistory();
		while(firstdontblock)				/* free all lists */
		{	dbl=firstdontblock->next;
			free(firstdontblock);
			firstdontblock=dbl;
		}
		while(firstonlyblock)
		{	obl=firstonlyblock->next;
			free(firstonlyblock);
			firstonlyblock=obl;
		}
		while(firstaccept)
		{	al=firstaccept->next;
			free(firstaccept);
			firstaccept=al;
		}
		while(firstoverride)
		{	orl=firstoverride->next;
			free(firstoverride);
			firstoverride=orl;
		}
		while(firstlimit)
		{	ll=firstlimit->next;
			free(firstlimit);
			firstlimit=ll;
		}
		while(firstsidfilter)
		{	sfl=firstsidfilter->next;
			free(firstsidfilter->sidarray);
			free(firstsidfilter);
			firstsidfilter=sfl;
		}
		
		sensor=firstsensor;			/* start at the beginning */
		while(sensor)
		{	nextsensor=sensor->next;
			TwoFishDestroy(sensor->snortfish);	/* if this is the one, free the TwoFish structure */
			if(sensor->rbfield)				/* and all other allocated buffers */
				free(sensor->rbfield);
			if(sensor->rbmeterfield)
				free(sensor->rbmeterfield);
			if(sensor->persistentsocket && sensor->snortsocket) /* close any remaining open sockets */
				closesocket(sensor->snortsocket);
			free(sensor);					/* free sensor element */
			sensor=nextsensor;
		}

		if(skiphostsfield)
			free(skiphostsfield);
		if(threadtable)
			free(threadtable);
		for(i=0;i<plugincount;i++)			/* Free data lists of plugins if used/allocated... */
		{	dlp=&(FirstPluginData[i]);				/* ...and free the list itself. */
			if(dlp)
			{	if(dlp->data)
					free(dlp->data);
				dlp=dlp->next;
				while(dlp)
				{	tdlp=dlp->next;
					if(dlp->data)
						free(dlp->data);
					free(dlp);
					dlp=tdlp;
				}
			}
		}
#ifdef WIN32
		WSACleanup();
#endif
	}
	printf("Exiting SnortSam...\n\n");
	exit(ret);
}

/* This does nothing else than inet_ntoa, but it keeps 256 results in a static string
 * unlike inet_ntoa which keeps only one. This is used for (s)printf's were two IP
 * addresses are printed (this has been increased from four while multithreading the app).
*/
char *inettoa(unsigned long ip)
{	struct in_addr ips;
	static char addr[256][20];
	static unsigned char toggle;

#ifndef WIN32
	pthread_mutex_lock(&inettoa_mutex);  /* Since we have static vars, a thread */
#endif
	ips.s_addr=ip;                       /* interrupt could change a var, so we */
	toggle=(toggle+1)&255;               /* use a mutex to lock other threads. */
	safecopy(addr[toggle],inet_ntoa(ips));
#ifndef WIN32
	pthread_mutex_unlock(&inettoa_mutex);
#endif

	return addr[toggle];
}

/* Logs data to log file.
*/
void logmessage(unsigned int level,char *logmsg,char *module,unsigned long ip)	/* logs messages to log file */
{	struct tm *tp;							/* level: 0=off, 1=sparse, 2=normal, 3=verbose */
	FILE *fp;
	time_t ttime;
/*  FILE *con; 

	if(level==1)				 Retrofitted by request to log errors to stderr and the rest to stdout 
		con=stderr;					*** Crashes under Windows. Need to check this out
	else
		con=stdout;
*/

	if(!daemonized)
	{	if(level<=screenlevel)
		{	
#ifndef WIN32
			pthread_mutex_lock(&loginprogress_mutex);
#endif
			printf("%s\n", logmsg);
#ifndef WIN32
			pthread_mutex_unlock(&loginprogress_mutex);   
#endif
		}
	}

	if(level<=loglevel && *logfile)	/* The log level is only checked for logging to files (and other logs later) */
	{	
#ifndef WIN32
		pthread_mutex_lock(&loginprogress_mutex);
#endif
		fp=fopen(logfile,"a+t");
		if(fp)
		{	time(&ttime);
			tp=localtime(&ttime);
			fprintf(fp,"%04i/%02i/%02i, %02i:%02i:%02i, %s, %i, %s, %s\n",tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec,ip?inettoa(ip):"-",level,module,logmsg);
			fclose(fp);
		}
		else
			printf("Error: Could not create log file!\n");
#ifndef WIN32
		pthread_mutex_unlock(&loginprogress_mutex);   
#endif
	}
}

/* removes spaces from a string 
*/	
void remspace(char *str)    
{	char *p;

	p=str;
	while(*p)
	{	if(myisspace(*p))		/* normalize spaces (tabs into space, etc) */
			*p=' ';
		p++;
	}
	while((p=strrchr(str,' ')))	/* remove spaces */
		strcpy(p,p+1);
}

/* parses duration arguments and returns seconds 
*/
unsigned long parseduration(char *p)  
{	unsigned long dur=0,tdu;
	char *tok,c1,c2;

	remspace(p);				/* remove spaces from value */
	while(*p)
	{	tok=p;
		while(*p && myisdigit(*p))
			p++;
		if(*p)
		{	c1=mytolower(*p);
			*p=0;
			p++;
			if(*p && !myisdigit(*p))
			{	c2=mytolower(*p++);
				while(*p && !myisdigit(*p))
					p++;
			}
			else
				c2=0;
			tdu=atol(tok);
			switch(c1)
			{	case 'm':	if(c2=='o')				/* for month... */
								tdu*=(60*60*24*30);	/* ...use 30 days */
							else
								tdu*=60;			/* minutes */
				case 's':	break;					/* seconds */
				case 'h':	tdu*=(60*60);			/* hours */
							break;
				case 'd':	tdu*=(60*60*24);		/* days */
							break;
				case 'w':	tdu*=(60*60*24*7);		/* week */
							break;
				case 'y':	tdu*=(60*60*24*365);	/* year */
							break;
			}
			dur+=tdu;
		}
		else
			dur+=atol(tok);
	}

	return dur;
}

/* Returns *ONE* IP address as a long
*/
unsigned long getip(char *ipstr)  
{	struct hostent *hoste;
	unsigned long ip;

	if((hoste=gethostbyname(ipstr)))
	{	ip=*(unsigned long *)hoste->h_addr;
#ifdef FWSAMDEBUG
		printf("Debug: getip()\nhostent: [0]=%0x, [1]=%0x, [2]=%0x, [3]=%0x\nhostent: %lx\n",
			*(((unsigned char *)hoste->h_addr)),	*(((unsigned char *)hoste->h_addr)+1),
			*(((unsigned char *)hoste->h_addr)+2),	*(((unsigned char *)hoste->h_addr)+3),ip);
#endif
	}
	else if((ip=inet_addr(ipstr))==INADDR_NONE)
		ip=0;

	return ip;
}

/* returns a pointer to a hostname
*/
char *gethstname(unsigned long ip)  
{	static unsigned char toggle;
	struct hostent *hoste;
	static char hostname[256][256];

#ifndef WIN32
	pthread_mutex_lock(&gethstname_mutex); /* Since we have static vars, a thread */
#endif
	toggle=(toggle+1)&255;				  /* interrupt could change a var, so we */
										  /* use a mutex to lock other threads. */
	if((hoste=gethostbyaddr((const char *)&ip,4,AF_INET)))
		strncpy(hostname[toggle],hoste->h_name,255);
	else
		strncpy(hostname[toggle],inettoa(ip),255);
	hostname[toggle][255]=0;
#ifndef WIN32
	pthread_mutex_unlock(&gethstname_mutex);
#endif
	
	return hostname[toggle];
}

/* This function adds an IP address and mask to the DONTBLOCK list
*/
void adddontblock(unsigned long ip, unsigned long mask, int block, char *func, char *what)
{	DONTBLOCKLIST *dbl;
	static DONTBLOCKLIST *lastdontblock=NULL;
	
	dbl=safemalloc(sizeof(DONTBLOCKLIST),func,what);
	dbl->ip.s_addr=ip&mask;
	dbl->mask=mask;
	dbl->next=NULL;
	dbl->block=block;
	if(!firstdontblock)			/* if first one, set first-pointer */
		firstdontblock=dbl;
	else
		lastdontblock->next=dbl;
	lastdontblock=dbl;
	if(!block)
		usedontunblock=TRUE; /* Special flag since it may not be used */
}

/* This function adds an IP address and mask to the ONLYBLOCK list
*/
void addonlyblock(unsigned long ip, unsigned long mask, int block, char *func, char *what)
{	ONLYBLOCKLIST *obl;
	static ONLYBLOCKLIST *lastonlyblock=NULL;
	
	obl=safemalloc(sizeof(ONLYBLOCKLIST),func,what);
	obl->ip.s_addr=ip&mask;
	obl->mask=mask;
	obl->next=NULL;
	obl->block=block;
	if(!firstonlyblock)			/* if first one, set first-pointer */
		firstonlyblock=obl;
	else
		lastonlyblock->next=obl;
	lastonlyblock=obl;
	if(block)
		useonlyblock=TRUE; /* Special flag since it may not be used */
	else
		useonlyunblock=TRUE;
}

/* This function adds an IP address and mask to the OVERRIDE list
*/
void addoverride(unsigned long ip, unsigned long mask, unsigned long dur, char *func, char *what)
{	OVERRIDELIST *orl;
	static OVERRIDELIST *lastoverride=NULL;
	
	orl=safemalloc(sizeof(OVERRIDELIST),func,what);
	orl->ip.s_addr=ip&mask;
	orl->mask=mask;
	orl->newduration=dur;
	orl->next=NULL;
	if(!firstoverride)		/* if first one, set first-pointer */
		firstoverride=orl;
	else
		lastoverride->next=orl;
	lastoverride=orl;
}

/* parses the config file and sets parameters and options 
*/
void parseline(char *arg,bool first,char *file,unsigned long line)  
{	char *val,*val2,*val3;
	unsigned int i,block;
	unsigned long l,mask=0;
	struct in_addr ipip;
	struct hostent *hoste;
	ACCEPTLIST *al;
	LIMITLIST *ll;
	SIDFILTERLIST *sfl;
	DATALIST *datalistp,*newdatalistp;
	static LIMITLIST *lastlimit=NULL;
	static ACCEPTLIST *lastaccept=NULL;
	static SIDFILTERLIST *lastsidfilter=NULL;


	val=arg;					/* the first string is the argument. */
	while(!myisspace(*val) && *val)		
		val++;
	if(*val)
	{	*val++ =0;
		while(myisspace(*val) && *val)		/* the second string is the value  */
			val++;
	}
	if(!stricmp(arg,"defaultkey") 
		|| !stricmp(arg,"password")  
		|| !stricmp(arg,"defaultpassword"))		/* default key (accept password as well) */
	{	if(*defaultkey)
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] DEFAULTKEY already defined. Ignoring '%s'.",file,line,val);
			logmessage(3,msg,"snortsam",0);
		}
		else
		{	remspace(val);				/* remove spaces from value */
			safecopy(defaultkey,val);
		}
	}
	else if(!stricmp(arg,"bindip"))		/* Bind to one address/interface only */
	{	remspace(val);				/* remove spaces from value */
		mybindip=getip(val);
	}
	else if(!stricmp(arg,"port"))				/* get the port SnortSam supposed to listen on */
	{	remspace(val);				/* remove spaces from value */
		i=atoi(val);
		if(i>0)
			mylistenport=(unsigned short)i;
	}
	else if(!stricmp(arg,"holdsnort"))	/* keep Snort/Barnyard on hold while blocking */
	{	holdsnort=TRUE;
	}
	else if(!stricmp(arg,"daemon") 
	     || !stricmp(arg,"daemonize"))	  /* Option to daemonize Snortsam */
	{	wantdaemon=TRUE;
	}
	else if(!stricmp(arg,"fwsamipflip"))	/* Performs an endian flip on IP addresses for fwsam */
	{	fwsamipflip=TRUE;
	}
	else if(!stricmp(arg,"avoidstatefile"))	/* don't keep a state file unless plugins need it */
	{	avoidstatefile=TRUE;
	}
	else if(!stricmp(arg,"dontusethreads") 
	     || !stricmp(arg,"neverusethreads") 
	     || !stricmp(arg,"nothreads"))	/* don't use thread functions (turn it into a single threaded progam) */
	{	dontusethreads=TRUE;
	}
	else if(!stricmp(arg,"usethreads") 
	     || !stricmp(arg,"forcethreads"))	/* force use of thread functions (mainly for Linux) */
	{	dontusethreads=FALSE;
	}
	else if(!stricmp(arg,"disableseqnocheck"))	/* don't check sequence numbers */
	{	disableseqnocheck=TRUE;
	}
	else if(!stricmp(arg,"disablepersistenttcp") 
	     || !stricmp(arg,"disablepersistenttcpconnections") 
	     || !stricmp(arg,"disablepersistentconnections")) 	/* don't use persistens tcp connections */
	{	disablepersistentconnections=TRUE;
	}
	else if(!stricmp(arg,"enablepersistenttcp") 
	     || !stricmp(arg,"enablepersistenttcpconnections") 
	     || !stricmp(arg,"enablepersistentconnections")) 	/* force use persistens tcp connections */
	{	disablepersistentconnections=FALSE;
	}
	else if(!stricmp(arg,"disablereverselookups") 
	     || !stricmp(arg,"disablereverselookup"))	/* don't reverse resolve IP to host names on log output or email (currently onyl email) */
	{	disablereverselookups=TRUE;
	}
	else if(!stricmp(arg,"loglevel"))			/* get the logging level (none/sparse/normal/verbose) */
	{	remspace(val);				/* remove spaces from value */
		loglevel=atol(val);
	}
	else if(!stricmp(arg,"screenlevel"))		/* get the screen output level (none/sparse/normal/verbose) */
	{	remspace(val);				/* remove spaces from value */
		screenlevel=atol(val);
	}
	else if(!stricmp(arg,"logfile"))			/* get the name of the log file */
	{	if(*logfile)
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] LOGFILE already defined. Ignoring '%s'.",file,line,val);
			logmessage(1,msg,"snortsam",0);
		}
		else
		{	remspace(val);				/* remove spaces from value */
			safecopy(logfile,val);
		}
	}
	else if(!stricmp(arg,"statefile"))		/* get the name of the state file */
	{	if(*statefile)
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] STATEFILE already defined. Ignoring '%s'.",file,line,val);
			logmessage(1,msg,"snortsam",0);
		}
		else
		{	remspace(val);				/* remove spaces from value */
			safecopy(statefile,val);
		}
	}
	else if(!stricmp(arg,"skiphosts"))			/* get the 'skip repetitive host' value */
	{	remspace(val);				/* remove spaces from value */
		skiphosts=atol(val);
	}
	else if(!stricmp(arg,"skipinterval"))		/* get time interval for repetitive skips */
		skipinterval=(time_t)parseduration(val);
	else if(!stricmp(arg,"rollbackhosts"))		/* get amount of rollback hosts */
	{	remspace(val);				/* remove spaces from value */
		rbhosts=atol(val);
	}
	else if(!stricmp(arg,"rollbacksleeptime"))	/* get the additional sleeptime after rollback */
		rbsleeptime=(time_t)parseduration(val);
	else if (!stricmp(arg,"rollbackthreshold"))	/* get the rollback threshold */
	{	remspace(val);				/* remove spaces from value */
		val2=strchr(val,'/');				/* val is hosts, val2 is time interval */
		if(val2)
		{	*val2++ =0;
			rbmeterinterval=(time_t)parseduration(val2);
		}
		rbmeterhosts=atol(val);
	}
	else if((block= !stricmp(arg,"dontblock")) || !stricmp(arg,"dontunblock"))		/* add hosts/nets that never get blocked/unblocked */
	{	remspace(val);						/* remove spaces from value */
		val2=strchr(val,'/');				/* val is host, val2 is /netmask */
		mask=0xffffffff;
		if(val2)
		{	*val2++ =0;
			mask=getnetmask(val2);
		}
		ipip.s_addr=getip(val);
		if(ipip.s_addr)						/* if valid entry */
		{	if(val2)						/* If we had a netmask */
			{
#ifdef FWSAMDEBUG
		printf("Debug: Dont%sAdd: Host %s, IP %s\n",block?"Block":"Unblock",val,inettoa(ipip.s_addr));
		printf("Debug: Dont%sAdd: Mask %s, IP %s\n",block?"Block":"Unblock",val2,inettoa(mask));
		
#endif
				adddontblock(ipip.s_addr,mask,block,"parseline",block?"dontblock-list":"dontunblock-list"); /* add just one IP */
			}
			else                            /* if we had a hostname */
			{	if(hoste=gethostbyname(val))
				{	i=0;
					while(hoste->h_addr_list[i]) /* we iterate through the IP's for that hostname */
					{	
#ifdef FWSAMDEBUG
		printf("Debug: Dont%sAdd: Host %s, IP %s\n",block?"Block":"Unblock",val,inettoa(*((unsigned long *)hoste->h_addr_list[i])));
		
#endif
						adddontblock(*((unsigned long *)hoste->h_addr_list[i++]),mask,block,"parseline",block?"dontblock-list":"dontunblock-list");
					}
				}
			}
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid or unresolvable host '%s'.",file,line,val);
			logmessage(1,msg,"snortsam",0);
		}
	}
	else if((block= !stricmp(arg,"onlyblock")) || !stricmp(arg,"onlyunblock"))		/* add hosts/nets that never get blocked/unblocked */
	{	remspace(val);						/* remove spaces from value */
		val2=strchr(val,'/');				/* val is host, val2 is /netmask */
		mask=0xffffffff;
		if(val2)
		{	*val2++ =0;
			mask=getnetmask(val2);
		}
		ipip.s_addr=getip(val);
		if(ipip.s_addr)						/* if valid entry */
		{	if(val2)						/* If we had a netmask */
			{
#ifdef FWSAMDEBUG
		printf("Debug: Only%sAdd: Host %s, IP %s\n",block?"Block":"Unblock",val,inettoa(ipip.s_addr));
		printf("Debug: Only%sAdd: Mask %s, IP %s\n",block?"Block":"Unblock",val2,inettoa(mask));
		
#endif
				addonlyblock(ipip.s_addr,mask,block,"parseline",block?"onlyblock-list":"onlyunblock-list"); /* add just one IP */
			}
			else                            /* if we had a hostname */
			{	if(hoste=gethostbyname(val))
				{	i=0;
					while(hoste->h_addr_list[i]) /* we iterate through the IP's for that hostname */
					{	
#ifdef FWSAMDEBUG
		printf("Debug: Only%sAdd: Host %s, IP %s\n",block?"Block":"Unblock",val,inettoa(*((unsigned long *)hoste->h_addr_list[i])));
		
#endif
						addonlyblock(*((unsigned long *)hoste->h_addr_list[i++]),mask,block,"parseline",block?"onlyblock-list":"onlyunblock-list");
					}
				}
			}
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid or unresolvable host '%s'.",file,line,val);
			logmessage(1,msg,"snortsam",0);
		}
	}
	else if(!stricmp(arg,"override"))			/* add hosts/nets for time override */
	{	remspace(val);				/* remove spaces from value */
		val2=strchr(val,'/');
		if(!val2)
		{	mask=0xffffffff;
			val2=val;
		}
		else
			*val2++ =0;
		val3=strchr(val2,',');
		if(!val3)
			l=300;				/* default override time 5 minutes */
		else
		{	*val3++ =0;
			l=parseduration(val3);
		}
		ipip.s_addr=getip(val);
		if(ipip.s_addr)
		{	if(!mask)
			{	mask=getnetmask(val2); /* If we had a netmask */
#ifdef FWSAMDEBUG
		printf("Debug: OverrideAdd: Host %s, IP %s, Duration %lu\n",val,inettoa(ipip.s_addr),l);
		
#endif
				addoverride(ipip.s_addr,mask,l,"parseline","override-list"); /* add just one IP */
			}
			else                            /* if we had a hostname */
			{	if(hoste=gethostbyname(val))
				{	i=0;
					while(hoste->h_addr_list[i]) /* we iterate through the IP's for that hostname */
					{	
#ifdef FWSAMDEBUG
		printf("Debug: OverrideAdd: Host %s, IP %s, Duration: %lu\n",val,inettoa(*((unsigned long *)hoste->h_addr_list[i])),l);
		
#endif
						addoverride(*((unsigned long *)hoste->h_addr_list[i++]),mask,l,"parseline","override-list");

					}
				}
			}
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid or unresolvable host '%s'.",file,line,val);
			logmessage(1,msg,"snortsam",0);
		}
	}
	else if(!stricmp(arg,"upperlimit") || !stricmp(arg,"limit") 
	     || !stricmp(arg,"lowerlimit") || !stricmp(arg,"atleast"))			/* add hosts/nets for time limit */
	{	remspace(val);				/* remove spaces from value */
		val2=strchr(val,'/');
		if(!val2)
		{	mask=0xffffffff;
			val2=val;
		}
		else
			*val2++ =0;
		val3=strchr(val2,',');
		if(!val3)
			l=60*60*24*7;			/* default limit time 1 week */
		else
		{	*val3++ =0;
			l=parseduration(val3);
		}
		if(!mask)
			mask=getnetmask(val2);
		ipip.s_addr=getip(val);
		if(ipip.s_addr)
		{	ll=safemalloc(sizeof(LIMITLIST),"parseline","limit-list");
			ll->ip.s_addr=ipip.s_addr&mask;
			ll->mask=mask;
			ll->limit=l;
			ll->upper=(!stricmp(arg,"upperlimit") || !stricmp(arg,"limit"));
			ll->next=NULL;
			if(!firstlimit)
				firstlimit=ll;
			else
				lastlimit->next=ll;
			lastlimit=ll;
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid or unresolvable host '%s'.",file,line,val);
			logmessage(1,msg,"snortsam",0);
		}
	}
	else if(!stricmp(arg,"accept"))				/* add hosts/nets for authorized sensors */
	{	remspace(val);				/* remove spaces from value */
		val2=strchr(val,'/');
		if(!val2)				/* val is host, val2 is netmask */
		{	mask=0xffffffff;
			val2=val;
		}
		else
			*val2++ =0;
		val3=strchr(val2,',');		/* val3 is the initial key for those hosts */
		if(val3)
			*val3++ =0;
		if(!mask)
			mask=getnetmask(val2);
		ipip.s_addr=getip(val);
		if(ipip.s_addr)
		{	al=safemalloc(sizeof(ACCEPTLIST),"parseline","accept-list");
			al->ip.s_addr=ipip.s_addr&mask;
			al->mask=mask;
			if(val3)
				safecopy(al->initialkey,val3);
			else
				al->initialkey[0]=0;
			al->next=NULL;
			if(!firstaccept)
				firstaccept=al;
			else
				lastaccept->next=al;
			lastaccept=al;
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid or unresolvable host '%s'.",file,line,val);
			logmessage(1,msg,"snortsam",0);
		}
	}
	else if(!stricmp(arg,"denysidfrom") || !stricmp(arg,"allowsidfrom")
	     || !stricmp(arg,"denysidsfrom") || !stricmp(arg,"allowsidsfrom"))		/* populates SID filter arrays */
	{	remspace(val);				/* remove spaces from value */
		val2=strchr(val,'/');
		if(!val2)				/* val is host, val2 is netmask */
		{	mask=0xffffffff;
			val2=val;
		}
		else
			*val2++ =0;
		val3=strchr(val2,':');		/* val3 points to the first SID */
		if(val3)
		{	*val3++=0;
			while(*val3 && !myisdigit(*val3))
				val3++;
			if(*val3)
			{	if(!mask)
					mask=getnetmask(val2);
				i=1;						/* Always assume at least one SID is given */
				val2=val3;
				while(*val2)
				{	if(!myisdigit(*val2))
						i++;				/* Count SIDs (well, just commas or delimiters anyway) */
					val2++;
				}
				ipip.s_addr=getip(val);
				if(ipip.s_addr)
				{	sfl=safemalloc(sizeof(SIDFILTERLIST),"parseline","sid-filter-list");
					sfl->ip.s_addr=ipip.s_addr&mask;
					sfl->mask=mask;

					/* Set allowed/denied flag and malloc SID array */
					sfl->typedenied=!stricmp(arg,"denysidfrom") || !stricmp(arg,"denysidsfrom");
					sfl->sidarray=safemalloc(sizeof(unsigned long)*i,"parseline","sidarray");
					sfl->sidcount=0;
					
					val2=val3;
					while(*val3)
					{	while(*val2 && myisdigit(*val2)) /* Walk all numbers in line */
							val2++;
						if(*val2)	 		/* if comma, skip commas */
						{	*val2++=0;
							while(*val2 && !myisdigit(*val2))
								val2++;
						}
						sfl->sidarray[sfl->sidcount++]=atol(val3);
						val3=val2;		/* val2 either 0 or next sid */
					}
					
					sfl->next=NULL;
					if(!firstsidfilter)
						firstsidfilter=sfl;
					else
						lastsidfilter->next=sfl;
					lastsidfilter=sfl;
				}
				else
				{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid or unresolvable host '%s'.",file,line,val);
					logmessage(1,msg,"snortsam",0);
				}
			}
			else
			{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Syntax error. Invalid SID specified. Ignoring line.",file,line);
				logmessage(1,msg,"snortsam",0);
			}
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Syntax error. No ':' specified. Ignoring line.",file,line);
			logmessage(1,msg,"snortsam",0);
		}
	}
	else if(!stricmp(arg,"keyinterval"))		/* get the key renewal interval */
	{	remspace(val);				/* remove spaces from value */
		l=parseduration(val);
		if(l<300)						/* 5 minute minimum, because I said so */
			l=300;
		keyinterval=l;
	}
	else if(!stricmp(arg,"include"))			/* are we including another cfg file? */
	{	remspace(val);				/* remove spaces from value */
		if(first)
			parsefile(val,FALSE,file,line);				/* then parse that file */
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Only one level of inclusion allowed, ignoring file '%s'.",file,line,val);
			logmessage(1,msg,"snortsam",0);
		}
	}
	else
	{	for(i=0;i<plugincount;i++)		/* check if the argument is a plugin handle */
		{	if(!stricmp(arg,Plugins[i].PluginHandle))
			{	if(PluginStatus[i]==INACTIVE)	/* if plugin not active yet... */
				{	printf("Linking plugin '%s'...\n",Plugins[i].PluginHandle);
					PluginStatus[i]=ACTIVE;		/* ...mark plugin as active... */
					if(Plugins[i].PluginInit)
					{	printf("Initializing plugin '%s'...\n",Plugins[i].PluginHandle);
						if(!Plugins[i].PluginInit(&(FirstPluginData[i])))	/* ...and initialize it */
						{	PluginStatus[i]=DISABLED;				/* if init returns 0 (plugin failed), disable it */
							printf("Plugin '%s' failed to initialize. Disabling plugin...\n",Plugins[i].PluginHandle);
						}
					}
					if(PluginStatus[i]==ACTIVE)			/* if it's still active... */
						PluginIndex[PluginsActive++]=i;	/* ...add it to the index of active plugins */
				}
				if(PluginStatus[i]==ACTIVE && Plugins[i].PluginConfigParse) /* if we have a parse routine... */
				{	datalistp=&(FirstPluginData[i]);
					while(datalistp->data)		/* ... find next available datalist element and...*/
						datalistp=datalistp->next;
					Plugins[i].PluginConfigParse(val,file,line,datalistp);/* ...pass value to plugin parse routine */
					datalistp->readpointer=0;
					datalistp->busy=FALSE;
					if(datalistp->data!=NULL)	/* if parse routine allocated element...*/
					{	newdatalistp=safemalloc(sizeof(DATALIST),"parseline","newdatalistp"); /* allocate a new one for the next parse and ...*/
						newdatalistp->data=newdatalistp->next=NULL;
						datalistp->next=newdatalistp;		/* ...add it to the list */
					}
				}
				i=10000;
			}
		}
		if(i<10000)
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Unknown parameter '%s' in config file ignored.",file,line,arg);
			logmessage(1,msg,"snortsam",0);
		}
	}
}

/* sorts the authorized sensor list,
 * priority to single host (for individual keys)
*/
void sortacceptlist(void)					
{	ACCEPTLIST **thisp,**nextp,*tp,*np;		
	int again=TRUE;

	if(firstaccept)
	{	if(firstaccept->next)	/* Sort */
		{	while(again)		/* First by IP */
			{	thisp=&firstaccept;
				nextp=&(firstaccept->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->ip.s_addr>(*nextp)->ip.s_addr)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			again=TRUE;
        	while(again)		/* Then by mask */
			{	thisp=&firstaccept;
				nextp=&(firstaccept->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->mask<(*nextp)->mask)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			/* Remove duplicates */
			tp=firstaccept;
			np=firstaccept->next;
			while(np)
			{	if(tp->mask==np->mask && tp->ip.s_addr==np->ip.s_addr)
				{	tp->next=np->next;
					free(np);
					np=tp->next;
				}
				else
				{	np=np->next;
				    tp=tp->next;
				}
			}
		}
	}
}				

/* sort the whitelist,
 * priority to network
*/
void sortdontblocklist(void)				
{	DONTBLOCKLIST **thisp,**nextp,*tp,*np;	
	int again=TRUE;

	if(firstdontblock)
	{	if(firstdontblock->next)  	/* Sort */
		{	while(again)			/* First by IP */
			{	thisp=&firstdontblock;
				nextp=&(firstdontblock->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->ip.s_addr>(*nextp)->ip.s_addr)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			again=TRUE;
			while(again)			/* Then by mask */
			{	thisp=&firstdontblock;
				nextp=&(firstdontblock->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->mask>(*nextp)->mask)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			/* Remove duplicates */
			tp=firstdontblock;
			np=firstdontblock->next;
			while(np)
			{	if(tp->mask==np->mask && tp->ip.s_addr==np->ip.s_addr && tp->block==np->block)
				{	tp->next=np->next;
					free(np);
					np=tp->next;
				}
				else
				{	np=np->next;
				    tp=tp->next;
				}
			}
		}
	}
}				

/* sort the whitelist,
 * priority to network
*/
void sortonlyblocklist(void)				
{	ONLYBLOCKLIST **thisp,**nextp,*tp,*np;	
	int again=TRUE;

	if(firstonlyblock)
	{	if(firstonlyblock->next)  	/* Sort */
		{	while(again)			/* First by IP */
			{	thisp=&firstonlyblock;
				nextp=&(firstonlyblock->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->ip.s_addr>(*nextp)->ip.s_addr)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			again=TRUE;
			while(again)			/* Then by mask */
			{	thisp=&firstonlyblock;
				nextp=&(firstonlyblock->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->mask>(*nextp)->mask)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			/* Remove duplicates */
			tp=firstonlyblock;
			np=firstonlyblock->next;
			while(np)
			{	if(tp->mask==np->mask && tp->ip.s_addr==np->ip.s_addr && tp->block==np->block)
				{	tp->next=np->next;
					free(np);
					np=tp->next;
				}
				else
				{	np=np->next;
				    tp=tp->next;
				}
			}
		}
	}
}				

/* sort the override list
 * priority to single host
*/
void sortoverridelist(void)					
{	OVERRIDELIST **thisp,**nextp,*tp,*np;		
	int again=TRUE;

	if(firstoverride)
	{	if(firstoverride->next)  	/* Sort */
		{	while(again)			/* First by IP */
			{	thisp=&firstoverride;
				nextp=&(firstoverride->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->ip.s_addr>(*nextp)->ip.s_addr)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			again=TRUE;
			while(again)			/* Then my mask */
			{	thisp=&firstoverride;
				nextp=&(firstoverride->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->mask<(*nextp)->mask)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			/* Remove duplicates */
			tp=firstoverride;
			np=firstoverride->next;
			while(np)
			{	if(tp->mask==np->mask && tp->ip.s_addr==np->ip.s_addr && tp->newduration==np->newduration)
				{	tp->next=np->next;
					free(np);
					np=tp->next;
				}
				else
				{	np=np->next;
				    tp=tp->next;
				}
			}
		}
	}
}				

/* sort the limit list
 * priority to single host
*/
void sortlimitlist(void)					
{	LIMITLIST **thisp,**nextp,*tp,*np;		
	int again=TRUE;

	if(firstlimit)
	{	if(firstlimit->next)
		{	while(again)		/* First by IP */
			{	thisp=&firstlimit;
				nextp=&(firstlimit->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->ip.s_addr>(*nextp)->ip.s_addr)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			again=TRUE;
			while(again)		/* Then by mask */
			{	thisp=&firstlimit;
				nextp=&(firstlimit->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->mask<(*nextp)->mask)
					{	again=TRUE;
						tp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						tp->next=(*thisp);
						*thisp=tp;
						thisp=&(tp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
			/* Remove duplicates */
			tp=firstlimit;
			np=firstlimit->next;
			while(np)
			{	if(tp->mask==np->mask && tp->ip.s_addr==np->ip.s_addr && tp->limit==np->limit && tp->upper==np->upper)
				{	tp->next=np->next;
					free(np);
					np=tp->next;
				}
				else
				{	np=np->next;
				    tp=tp->next;
				}
			}
		}
	}
}				

/* sort the SID filter list
 * priority to network
*/
void sortsidfilterlist(void)					
{	SIDFILTERLIST **thisp,**nextp,*temp;		
	int again=TRUE;

	if(firstsidfilter)
	{	if(firstsidfilter->next)
		{	while(again)
			{	thisp=&firstsidfilter;
				nextp=&(firstsidfilter->next);
				again=FALSE;
				while(*nextp)
				{	if((*thisp)->mask<(*nextp)->mask)
					{	again=TRUE;
						temp=(*thisp)->next;
						(*thisp)->next=(*nextp)->next;
						temp->next=(*thisp);
						*thisp=temp;
						thisp=&(temp->next);
					}
					else
						thisp=nextp;
					nextp=&((*thisp)->next);
				}
			}
		}
	}
}				

/* finds and returns pointer to the host structure
*/
ACCEPTLIST *allowedhost(unsigned long addr)	
{	ACCEPTLIST *ap;

	ap=firstaccept;
	while(ap)
	{	if((addr&ap->mask)==ap->ip.s_addr)
			return ap;
		ap=ap->next;
	}
	return NULL;
}

/* checks if a host is in the whitelist
*/
int dontblockhost(unsigned long addr,int block)		
{	DONTBLOCKLIST *dbp;

	dbp=firstdontblock;
	while(dbp)
	{	if((addr&dbp->mask)==dbp->ip.s_addr && dbp->block==block)
			return TRUE;
		dbp=dbp->next;
	}
	return FALSE;
}

/* checks if a host is in the only-block list
*/
int onlyblockhost(unsigned long addr,int block)		
{	ONLYBLOCKLIST *obp;

	obp=firstonlyblock;
	while(obp)
	{	if((addr&obp->mask)==obp->ip.s_addr && obp->block==block)
			return TRUE;
		obp=obp->next;
	}
	return FALSE;
}

/* finds and returns override duration for a host to be blocked
*/
unsigned long override_duration_on_host(unsigned long addr,unsigned long duration)
{	OVERRIDELIST *op;						

	op=firstoverride;
	while(op)
	{	if((addr&op->mask)==op->ip.s_addr)
			return op->newduration;
		op=op->next;
	}
	return duration;
}

/* finds and returns a limit based on reporting sensor
*/
unsigned long limit_duration_on_sensor(unsigned long addr,unsigned long duration)
{	LIMITLIST *lp;						

	lp=firstlimit;
	while(lp)
	{	if((addr&lp->mask)==lp->ip.s_addr)
		{	 if((lp->upper && ((duration > lp->limit) || (duration==0))) 
		     ||(!lp->upper && (duration < lp->limit)))
				return lp->limit;
		}
		lp=lp->next;
	}
	return duration;
}

/* This checks if a given SID is allowed from a reporting sensor. It checks
 * allowed and denied arrays of specified SIDs.
*/
int sid_denied_from_sensor(unsigned long addr, unsigned long sid)
{	SIDFILTERLIST *sfp;
	int denied=FALSE;
	unsigned long i;
	
	/* First we check if we have the SID in a denied list. If so, it takes...
	   ...precendence over an allowed list, and we quickly return. */
	sfp=firstsidfilter;
	while(sfp)
	{	if((addr&sfp->mask)==sfp->ip.s_addr && sfp->typedenied)
		{	for(i=0;i< sfp->sidcount;i++)
				if(sfp->sidarray[i]==sid)
					return TRUE;
		}
		sfp=sfp->next;
	}
	
	/* Next we check if we have a SID in a allowed list. If so, ...
	   ...we set a default denied flag and override it if the SID is listed/ */
	sfp=firstsidfilter;
	while(sfp)
	{	if((addr&sfp->mask)==sfp->ip.s_addr && !sfp->typedenied)
		{	denied=TRUE;
			for(i=0;i< sfp->sidcount;i++)
				if(sfp->sidarray[i]==sid)
					return FALSE; /* If SID allowed, we return that */
		}
		sfp=sfp->next;
	}

	return denied;
}

/* This just sorts the plugin index and moves the multi-thread capable plugins
 * to the top, then single-threadable, and lastly inline plugins.
*/
void sortpluginindex(void)
{	unsigned long i,again,top,max;

	if(PluginsActive>=2)
	{	max=PluginsActive-1;
		for(again=TRUE,top=0;top<max && again;top++)
		{	for(again=FALSE,i=top+1;i<=max;i++)
			{	if(Plugins[PluginIndex[i]].PluginThreading>Plugins[PluginIndex[top]].PluginThreading)
				{	again=PluginIndex[i];
					PluginIndex[i]=PluginIndex[top];
					PluginIndex[top]=again;
					again=TRUE;
				}
			}
		}
	}
}


/* this function finds and returns the pointer to a snort sensor
 * if the sensor does not exist, it will be added to the chain 
*/
SENSORLIST *getsnorty(unsigned long addr,ACCEPTLIST *ap)
{	SENSORLIST *sens,**pointer;

	pointer=&firstsensor;				/* start at the beginning */
	while((sens=*pointer))		/* grab a sensor */
	{	if(sens->snortip.s_addr==addr)	/* is it the IP address we're looking for? */
			return sens;				/* if so, return sensor */
		pointer=&(sens->next);			/* otherwise check next one */
	}
	sens=safemalloc(sizeof(SENSORLIST),"getsnorty","sensor");	/* if sensor is not in the list, create a new one */

	snprintf(msg,sizeof(msg)-1,"Adding sensor %s to list.",inettoa(addr));
	logmessage(3,msg,"snortsam",addr);

	sens->snortip.s_addr=addr;			/* set the IP address of the sensor */
	sens->snortsocket=0;
	sens->toberemoved=FALSE;
	sens->persistentsocket=FALSE;
	sens->packetversion=FWSAM_PACKETVERSION;

	safecopy(sens->currentkey,ap->initialkey);	/* set the key to the initial key as defined in accept list */
	sens->snortfish=TwoFishInit(sens->currentkey); /* create a TwoFish for the sensor */
	do
		sens->myseqno=(unsigned short)rand();		/* the seqno this host will use */
	while(sens->myseqno<20 || sens->myseqno>65500);
	sens->lastcontact=sens->lastkeytime=time(NULL); /* reset the last contact/key time */
	sens->actrb=sens->actrbmeter=sens->sleepstart=0; /* reset the threshold settings */
	if(rbhosts)										 /* if we're keeping track of blocks */
	{	sens->rbfield=safemalloc(sizeof(BLOCKINFO)*rbhosts,"getsnorty","roll-back field"); /* alloc and initialize the field for rollback */
		memset(sens->rbfield,0,sizeof(BLOCKINFO)*rbhosts);
	}
	else
		sens->rbfield=NULL;
	if(rbmeterhosts)							/* if we're checking thresholds */
	{	sens->rbmeterfield=safemalloc(sizeof(unsigned long)*rbmeterhosts,"getsnorty","roll-back meter field"); /* alloc and init the meterfield */
		memset(sens->rbmeterfield,0,sizeof(unsigned long)*rbmeterhosts);
	}
	else
		sens->rbmeterfield=NULL;
	sens->next=NULL;
	*pointer=sens;

	return sens;
}


/* generate new encryption key 
*/
void newkey(SENSORLIST *snortbox,FWsamPacket *packet)
{	unsigned char newkey[TwoFish_KEY_LENGTH+2];			
	int i;

	newkey[0]=packet->snortseqno[0];					/* based on sensors sequence number... */
	newkey[1]=packet->snortseqno[1];				
	newkey[2]=packet->fwseqno[0];						/* ...our sequence number... */
	newkey[3]=packet->fwseqno[1];
	newkey[4]=packet->protocol[0];					/* ...and a random number */
	newkey[5]=packet->protocol[1];

	strncpy(newkey+6,snortbox->currentkey,TwoFish_KEY_LENGTH-6); /* append old key */
	newkey[TwoFish_KEY_LENGTH]=0;

	newkey[0]^=snortbox->snortkeymod[0];			/* xor new key with key modifiers */
	newkey[1]^=snortbox->snortkeymod[1];
	newkey[2]^=snortbox->snortkeymod[2];
	newkey[3]^=snortbox->snortkeymod[3];
	newkey[4]^=snortbox->mykeymod[0];
	newkey[5]^=snortbox->mykeymod[1];
	newkey[6]^=snortbox->mykeymod[2];
	newkey[7]^=snortbox->mykeymod[3];

	for(i=0;i<=7;i++)					/* change 0's to 1' since it's handled as a string */
		if(newkey[i]==0)
			newkey[i]++;

	safecopy(snortbox->currentkey,newkey);		/* update key string */
	TwoFishDestroy(snortbox->snortfish);
	snortbox->snortfish=TwoFishInit(newkey);	/* generate new TwoFish */
	snortbox->lastkeytime=time(NULL);			/* update last key gen time */
}

/* this function encrypts the packet and sends it to the specified sensor  
*/
int sendpacket(SENSORLIST *snortbox,char *packet,unsigned long packetsize)
{	char *encbuf;
	int len;

	encbuf=TwoFishAlloc(packetsize,FALSE,FALSE,snortbox->snortfish); /* get some buffer space for encryption */
	len=TwoFishEncrypt(packet,&encbuf,packetsize,FALSE,snortbox->snortfish); /* encrypt the packet */

	if(send(snortbox->snortsocket,encbuf,len,0)!=len) /* weird...could not send */
	{	snprintf(msg,sizeof(msg)-1,"Error: Could not send to snort box %s.",inettoa(snortbox->snortip.s_addr));
		logmessage(1,msg,"snortsam",snortbox->snortip.s_addr);
		return FALSE;
	}
	TwoFishFree(snortbox->snortfish); /* free the encryption buffer */
	return TRUE;
}

/* this function will go through the rollback history
 * and cancels the last <rbhosts> blocks
*/
void rollback(SENSORLIST *sensor)
{	unsigned long rb;
	struct protoent *protoe;

	if(rbhosts>0)							/* if we keep track */
	{	snprintf(msg,sizeof(msg)-1,"Rolling back last %lu blocks.",rbhosts);
		logmessage(3,msg,"snortsam",sensor->snortip.s_addr);
		sensor->actrb=0;					/* start at the beginning of the list... */
		for(rb=0;rb<rbhosts;rb++)			/* ...and go through them all */
		{	if(sensor->rbfield[rb].blockip)
			{	switch(sensor->rbfield[rb].mode&FWSAM_HOW)
				{	case FWSAM_HOW_THIS:
						protoe=getprotobynumber(sensor->rbfield[rb].proto);
						snprintf(msg,sizeof(msg)-1,"Rolling back %lu sec block for host %s in connection %s->%s:%d (%s).",(unsigned long)sensor->rbfield[rb].duration,inettoa(sensor->rbfield[rb].blockip),sensor->rbfield[rb].mode&FWSAM_WHO_SRC?inettoa(sensor->rbfield[rb].blockip):inettoa(sensor->rbfield[rb].peerip),sensor->rbfield[rb].mode&FWSAM_WHO_SRC?inettoa(sensor->rbfield[rb].peerip):inettoa(sensor->rbfield[rb].blockip),sensor->rbfield[rb].port,protoe->p_name);
					break;
					case FWSAM_HOW_IN:
						snprintf(msg,sizeof(msg)-1,"Rolling back %lu sec inbound block for host %s.",(unsigned long)sensor->rbfield[rb].duration,inettoa(sensor->rbfield[rb].blockip));
					break;
					case FWSAM_HOW_OUT:
						snprintf(msg,sizeof(msg)-1,"Rolling back %lu sec outbound block for host %s.",(unsigned long)sensor->rbfield[rb].duration,inettoa(sensor->rbfield[rb].blockip));
					break;
					case FWSAM_HOW_INOUT:
						snprintf(msg,sizeof(msg)-1,"Rolling back %lu sec complete block for host %s.",(unsigned long)sensor->rbfield[rb].duration,inettoa(sensor->rbfield[rb].blockip));
					break;
					default:
						snprintf(msg,sizeof(msg)-1,"Rolling back weird %lu sec block for host %s.",(unsigned long)sensor->rbfield[rb].duration,inettoa(sensor->rbfield[rb].blockip));
					break;
				}
				logmessage(2,msg,"snortsam",sensor->snortip.s_addr);

				addrequesttoqueue(FALSE,&(sensor->rbfield[rb]),TRUE,FALSE,FALSE,sensor->snortip.s_addr);  /* add unblock request to queue */
				
			}
		}
		memset(sensor->rbfield,0,sizeof(BLOCKINFO)*rbhosts);
	}
}

/* inhistory checks if an identical block is already active. 
 * It only checks for the peerip if the blocking mode is SERVICE.
*/
BLOCKHISTORY *inhistory(BLOCKINFO *bd)
{	BLOCKHISTORY *bhp;


	bhp=firstblockhistory;
	while(bhp)
	{	if(bhp->blockinfo.blockip == bd->blockip)					
		{	if((bhp->blockinfo.mode&FWSAM_HOW)!=FWSAM_HOW_THIS &&		/* If previous and current block are not of type service,*/
			   (bd->mode&FWSAM_HOW)!=FWSAM_HOW_THIS)					/* we just extend the old block */
				return bhp;		
			else if((bhp->blockinfo.mode&FWSAM_HOW)!=FWSAM_HOW_THIS &&	/* If previous block was not service, but current block is, */
					(bd->mode&FWSAM_HOW)==FWSAM_HOW_THIS)				/* we still extend the old block. This has to be done to prevent an unshun */
				return bhp;											/* of an IP which would also prematurely remove the service shun. */
								
			else if((bhp->blockinfo.mode&FWSAM_HOW)==FWSAM_HOW_THIS &&	/* If previous and current block are both services, we compare the  */
					(bd->mode&FWSAM_HOW)==FWSAM_HOW_THIS &&				/* details and only if it's the same service, we extend the block. */
					bhp->blockinfo.peerip==bd->peerip &&			
					bhp->blockinfo.proto==bd->proto &&				
					bhp->blockinfo.port==bd->port)
					return bhp;
		}															/* If previous block was a service, but current block is not, */
		bhp=bhp->next;													/* we create a new block.  TEST THIS, SERVICE UNSHUN MAY ERASE IP SHUN! */
	}
	return NULL;
}

/* isrepetitive checks for repetitive blocking requests. It uses an array of <skiphosts>
 * and checks if identical block have already been performed within the last <skipinterval> secs.
 * It only checks for the peerip if the blocking mode is SERVICE.
*/
int isrepetitive(BLOCKINFO *bd)
{	unsigned long i;
	int hit;
	time_t now;

#ifdef FWSAMDEBUG
/*	printf("Debug: SkipHosts: %lu, SkipInterval: %lu\n",skiphosts,(unsigned long)skipinterval);
*/
#endif

	now=time(NULL);
	for(hit=FALSE,i=0;i<skiphosts && !hit;i++)
	{	
#ifdef FWSAMDEBUG
/*		printf("Debug: Skip Field [%04lx]: IP: %s, Duration: %lu, LastBlockTime: %lu, Now: %lu\n",i,inettoa(skiphostsfield[i].blockip),(unsigned long)skiphostsfield[i].duration,(unsigned long)skiphostsfield[i].blocktime,(unsigned long)bd->blocktime);
*/
#endif
		if(skiphostsfield[i].block==bd->block)	/* Look only for same type blocks/unblocks */
		{	if(	skiphostsfield[i].blockip==bd->blockip &&			/* Check for identical block parameters */
				skiphostsfield[i].mode==bd->mode &&				
				(((bd->mode&FWSAM_HOW)==FWSAM_HOW_THIS)?
				 (	skiphostsfield[i].peerip==bd->peerip &&	
					skiphostsfield[i].port==bd->port &&	
					skiphostsfield[i].proto==bd->proto 
				 ):TRUE) &&  
				 (bd->block?(   skiphostsfield[i].duration==bd->duration &&
				 				/* and if we're looking for blocks, check if the duration falls within the time interval */
				 				bd->blocktime-skiphostsfield[i].blocktime<=((bd->duration>skipinterval)?skipinterval:bd->duration)
				 			):	/* if we're looking for unblocks, check if the last block timestamp is in within the interval time */
				 			(	now-skiphostsfield[i].blocktime<skipinterval
				 			)
				 )
			   )
			{	hit=TRUE;
			}
		}
	}
	return hit;
}

/* Here we add a blockinfo struct into the history list, sorted by expiration
 * time. The block request with the earlier expiration time is at the front.
 * That way the expiration handler can run more efficient.
 * Function is also used to move a blockinfo farther down the chain.
*/
void addtohistory(BLOCKHISTORY *this, int remove)
{	BLOCKHISTORY **pp;
 	time_t exp;

	exp=this->blockinfo.blocktime+this->blockinfo.duration;
	pp=&firstblockhistory;

	if(remove)
	{	while(*pp!=this)
			pp=&((*pp)->next);	/* Find it */
		*pp=this->next;			/* remove it */
	}
	while(*pp)
	{	if((*pp)->blockinfo.blocktime+(*pp)->blockinfo.duration>exp)
		{	this->next=*pp;
			*pp=this;
			return;
		}
		pp=&((*pp)->next);
	}
	*pp=this;
	this->next=NULL;
}

/* This routine saves the list of current blocks into a state file.
 * It is read during startup to populate the block history so that
 * SnortSam can unblock IP's that don't expire automatically (i.e. Cisco's SHUN)
*/
void savehistory()
{	FILE *fp;
	int exists=FALSE;
	char hversion[]=FWSAMHISTORYVERSION,backup[FILEBUFSIZE+8];
	BLOCKHISTORY *bhp;
	
	if(!avoidstatefile || keepblockhistory)
	{	if((fp=fopen(statefile,"rb")))
		{	exists=TRUE;
			fclose(fp);
		}
		if(exists)
		{	snprintf(backup,sizeof(backup)-1,"%s.bak",statefile);
			rename(statefile,backup);
		}
		fp=fopen(statefile,"w+b");
		if(!fp)
		{	printf("Error: Could not create state file!\n");
			return;
		}
		fwrite(hversion,6,1,fp); 	/* version is 6 chars long, see def in header */
		bhp=firstblockhistory;
		while(bhp)
		{	fwrite(&(bhp->blockinfo),sizeof(BLOCKINFO),1,fp);
			bhp=bhp->next;
		}
		fclose(fp);
		if(exists)
			unlink(backup);
	}
}

/* This routine handles the blocking request. It checks the whitelist and notes the block
 * in the unblock/rollback history. It grabs the new duration, if it is to be overridden,
 * and if all is well, it will call the block plugins.
*/
void block(SENSORLIST *snortbox,unsigned long bsip,unsigned short bsport,
		   unsigned long bdip,unsigned short bdport,
		   unsigned short bproto,time_t bduration,unsigned char bmode,
		   time_t btime,unsigned long bsig_id)
{	unsigned long peerip,blockip;
	unsigned short blockport;
	time_t t;
	int block=FALSE,extend=FALSE;
	BLOCKHISTORY *bhp;
	struct protoent *protoe;
	BLOCKINFO blockdata;

	if((bmode&FWSAM_WHO)==FWSAM_WHO_DST) /* check who we are blocking and get the IP address */
	{	blockip=bdip;
		blockport=bdport;	/* the blocked port for 'service/connection' type blocks should always be the port of the peer. */
		peerip=bsip;		/* Change it here if you want to change the behaviour (i.e. always peer port) */
	}
	else
	{	blockip=bsip;
		blockport=bdport;
		peerip=bdip;
	}
	
	/* checks here */
	if(blockip==0 || blockip==0xFFFFFFFFUL)		/* check if the IP address is valid */
	{	snprintf(msg,sizeof(msg)-1,"Ignoring block for invalid address %s.",inettoa(blockip));
		logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
		return;
	}
	if(useonlyblock)
	{	if(!onlyblockhost(blockip,TRUE))		/* check if the IP address is on the only-block list */
		{	snprintf(msg,sizeof(msg)-1,"Ignoring block for host %s.",inettoa(blockip));
			logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
			return;
		}
	}
	if(dontblockhost(blockip,TRUE))		/* check if the IP address is white-listed */
	{	snprintf(msg,sizeof(msg)-1,"Ignoring block for white-listed host %s.",inettoa(blockip));
		logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
		return;
	}
	
	blockdata.blockip=blockip;
	if((bmode&FWSAM_HOW)==FWSAM_HOW_THIS)
	{	blockdata.port=blockport;
		blockdata.peerip=peerip;
		blockdata.proto=bproto;
	}
	else
		blockdata.peerip=blockdata.proto=blockdata.port=0;
	blockdata.mode=bmode;
	blockdata.blocktime=btime;
	blockdata.sig_id=bsig_id;
	blockdata.block=TRUE;

	/* check for and get a blocktime limit out of the limit list based on the sensor*/
	blockdata.duration=limit_duration_on_sensor(snortbox->snortip.s_addr,bduration);	

	/* check for and get new duration out of override list for the host to be blocked */
	blockdata.duration=override_duration_on_host(blockip,blockdata.duration);	

	if(isrepetitive(&blockdata))
	{	snprintf(msg,sizeof(msg)-1,"Skipping repetitive block for host %s.",inettoa(blockip));
		logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
	}
	else
	{	/* note all info to check against at the next block request to avoid duplicate blocks */
		if(skiphosts>0)	
		{	memcpy(&skiphostsfield[currentskiphost],&blockdata,sizeof(BLOCKINFO));
			if(++currentskiphost>=skiphosts)   /* advance the skip pointer (in a ring) */
				currentskiphost=0;
		}
	
		if(rbmeterhosts)					/* now we check if we use thresholds */
		{	t=snortbox->actrbmeter;			/* we'll get current meter pointer */
			snortbox->rbmeterfield[t]=btime; /* and note the time of this request */
			if(++snortbox->actrbmeter>=rbmeterhosts) /* advance pointer */
				snortbox->actrbmeter=0;
			/* now we check if this request and the first request are within the same interval period */
			if(snortbox->rbmeterfield[t]-snortbox->rbmeterfield[snortbox->actrbmeter]<rbmeterinterval)
			{	snprintf(msg,sizeof(msg)-1,"Blocking threshold exceeded.");
				logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
				
				rollback(snortbox); /* if so, we unblock the last blocks */

				snprintf(msg,sizeof(msg)-1,"Ignoring blocks for sensor %s until blocks fall below threshold.",inettoa(snortbox->snortip.s_addr));
				logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
				snortbox->sleepstart=btime; /* send set the additional sleep time */
			}
			else /* if this blocking request is below threshold, we'll check if we can accept new blocks... */
			{	if((t=btime-snortbox->sleepstart)<rbsleeptime) /* ...or if we still have to wait a bit. */
				{	snprintf(msg,sizeof(msg)-1,"Ignoring blocks from %s for %lu more seconds (rollbacksleeptime).",inettoa(snortbox->snortip.s_addr),(unsigned long)rbsleeptime-t);
					logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
				}
				else /* if everything pans out, we'll block the IP */
					block=TRUE;
			}
		}
		else /* if we don't use thresholds, we just block */
			block=TRUE;

		if(block)
		{	if(rbhosts)			/* note the block in the rollback history */
			{	memcpy(&snortbox->rbfield[snortbox->actrb],&blockdata,sizeof(BLOCKINFO));/* (snort sensor dependend) */
				if(++snortbox->actrb>=rbhosts)	/* advance the rollback pointer (in a ring) */
					snortbox->actrb=0;
			}

			if((!avoidstatefile || keepblockhistory) && blockdata.duration)					/* If snortsam needs to time out blocks itself...*/
			{	bhp=inhistory(&blockdata);		/* ..check if an old block exist. */
				if(bhp)						/* if so, check if it is covered by an older, longer block */
				{	if(bhp->blockinfo.blocktime+bhp->blockinfo.duration >= blockdata.blocktime+blockdata.duration) /* If so, do nothing */
					{
#ifdef FWSAMDEBUG
						printf("Debug: New block would expire before old block. Skipping this request.\n");
#endif
						snprintf(msg,sizeof(msg)-1,"%lu second block for host %s is still covered by an older block of %lu seconds. Skipping this request!",(unsigned long)blockdata.duration,inettoa(blockdata.blockip),(unsigned long)bhp->blockinfo.duration);
						logmessage(2,msg,"snortsam",snortbox->snortip.s_addr);
						return ;
					}

					extend=TRUE;
#ifdef FWSAMDEBUG
					printf("Debug: Extending old block timeout for %s by %lu seconds.\n",inettoa(blockdata.blockip),(unsigned long)(blockdata.blocktime+blockdata.duration)-(bhp->blockinfo.blocktime+bhp->blockinfo.duration));
#endif

					bhp->blockinfo.duration=blockdata.duration;	/* otherwise, we extend the time-out. */
					bhp->blockinfo.blocktime=blockdata.blocktime;
					addtohistory(bhp,TRUE);
					savestatefile=TRUE;	/* flush whole chain to file */
				}
				else								/* if no old block exists, we create a new entry... */
				{	bhp=safemalloc(sizeof(BLOCKHISTORY),"block","bhp");
					memcpy(&(bhp->blockinfo),&blockdata,sizeof(BLOCKINFO)); /* ...and note the block */
					addtohistory(bhp,FALSE);
					savestatefile=TRUE; /* flush whole chain to file */
				}
			}
			switch(blockdata.mode&FWSAM_HOW)
			{	case FWSAM_HOW_THIS:
					protoe=getprotobynumber(blockdata.proto);
					snprintf(msg,sizeof(msg)-1,"%s host %s in connection %s->%s:%d (%s) for %lu seconds (Sig_ID: %lu).",extend?"Extending block for":"Blocking",inettoa(blockdata.blockip),blockdata.mode&FWSAM_WHO_SRC?inettoa(blockdata.blockip):inettoa(blockdata.peerip),blockdata.mode&FWSAM_WHO_SRC?inettoa(blockdata.peerip):inettoa(blockdata.blockip),blockdata.port,protoe->p_name,(unsigned long)blockdata.duration,blockdata.sig_id);
				break;
				case FWSAM_HOW_IN:
					snprintf(msg,sizeof(msg)-1,"%s host %s inbound for %lu seconds (Sig_ID: %lu).",extend?"Extending block for":"Blocking",inettoa(blockdata.blockip),(unsigned long)blockdata.duration,blockdata.sig_id);
				break;
				case FWSAM_HOW_OUT:
					snprintf(msg,sizeof(msg)-1,"%s host %s outbound for %lu seconds (Sig_ID: %lu).",extend?"Extending block for":"Blocking",inettoa(blockdata.blockip),(unsigned long)blockdata.duration,blockdata.sig_id);
				break;
				case FWSAM_HOW_INOUT:
					snprintf(msg,sizeof(msg)-1,"%s host %s completely for %lu seconds (Sig_ID: %lu).",extend?"Extending block for":"Blocking",inettoa(blockdata.blockip),(unsigned long)blockdata.duration,blockdata.sig_id);
				break;
				default:
					snprintf(msg,sizeof(msg)-1,"%s host %s in a weird way for %lu seconds (Sig_ID: %lu). (Let me know if you see this message!) ",extend?"Extending block for":"Blocking",inettoa(blockdata.blockip),(unsigned long)blockdata.duration,blockdata.sig_id);
				break;
			}

			if(blockdata.duration!=bduration)
			{	snprintf(msg+strlen(msg)-1,sizeof(msg)-1-strlen(msg)," (override from %lu seconds)",(unsigned long)bduration);
			}
			logmessage(2,msg,"snortsam",snortbox->snortip.s_addr);
			
			addrequesttoqueue(TRUE,&blockdata,FALSE,extend,signal_usr1,snortbox->snortip.s_addr);	/* add block request to queue */
		}
	}
}

/* parse a config file
*/
void parsefile(char *cfgfile,bool first,char *callingfile,unsigned long callingline)
{	FILE *fp;
	char buf[STRBUFSIZE+2],*p;
	unsigned long line=0;

	fp=fopen(cfgfile,"rt");				/* open config file */
	if(!fp)
	{	if(first)
		{	printf("Error: Config file '%s' not found or inaccessible!\n",cfgfile);
			getout(100);
		}
		else
			printf("Error: [%s: %lu] Config file '%s' not found or inaccessible!\n",callingfile,callingline,cfgfile);
	}
	else
	{	printf("Parsing config file %s...\n",cfgfile);
		while(fgets(buf,sizeof(buf)-1,fp))
		{	buf[sizeof(buf)-1]=0;
			line++;
			p=buf;
		    while(myisspace(*p))
				p++;
			if(p>buf);
				safecopy(buf,p);			
			if(*buf)
			{	p=buf+strlen(buf)-1;	/* remove leading and trailing spaces */
				while(myisspace(*p))
					*p-- =0;
			}
			p=buf;
			if(*p=='#' || *p==';')
				*p=0;
			else
				p++;
			while(*p)					/* remove inline comments (except escaped #'s and ;'s) */
			{	if(*p=='#' || *p==';')
				{	if(*(p-1)=='\\')
						strcpy(p-1,p);
					else
						*p=0;
				}
				else
					p++;
			}
			if(*buf)
				parseline(buf,first,cfgfile,line);		/* parse the line */
		}
		fclose(fp);
	}
}

/* This routine forces an unblock of the IP listed in the BLOCKINFO struct.
 * It's called by a state file content check against white list on startup,
 * and when Snortsam receives a manual unblock request from external tools.
*/
void unblock(BLOCKINFO *bhp,char *comment,unsigned long reqip,int force)
{	char msg[STRBUFSIZE+2],durmsg[STRBUFSIZE+2]="";
	struct protoent *protoe;
	

	if(bhp->blockip==0 || bhp->blockip==0xFFFFFFFFUL)		/* check if the IP address is valid */
	{	snprintf(msg,sizeof(msg)-1,"Ignoring unblock for invalid address %s.",inettoa(bhp->blockip));
		logmessage(3,msg,"snortsam",reqip);
		return;
	}

	bhp->block=FALSE;
	if(force)
	{	if(isrepetitive(bhp))
		{	if(reqip)
				snprintf(durmsg,sizeof(durmsg)-1," from address %s",inettoa(reqip));
			snprintf(msg,sizeof(msg)-1,"Skipping repetitive unblock request%s for host %s.",durmsg,inettoa(bhp->blockip));
			logmessage(3,msg,"snortsam",reqip);
			return;
		}
		if(useonlyunblock)
		{	if(!onlyblockhost(bhp->blockip,FALSE))		/* check if the IP address is white-listed */
			{	snprintf(msg,sizeof(msg)-1,"Ignoring unblock for host %s.",inettoa(bhp->blockip));
				logmessage(3,msg,"snortsam",reqip);
				return;
			}
		}
		if(usedontunblock)
		{	if(dontblockhost(bhp->blockip,FALSE))		/* check if the IP address is white-listed */
			{	snprintf(msg,sizeof(msg)-1,"Ignoring unblock for white-listed host %s.",inettoa(bhp->blockip));
				logmessage(3,msg,"snortsam",reqip);
				return;
			}
		}
	}
	if(bhp->duration>0)
		snprintf(durmsg,STRBUFSIZE," %lu sec",(unsigned long)bhp->duration);
	else
		*durmsg=0;
		
	switch(bhp->mode&FWSAM_HOW)
	{	case FWSAM_HOW_THIS:
			protoe=getprotobynumber(bhp->proto);
			snprintf(msg,sizeof(msg)-1,"Removing%s block %s host %s in connection %s->%s:%d (%s).",durmsg,comment,inettoa(bhp->blockip),bhp->mode&FWSAM_WHO_SRC?inettoa(bhp->blockip):inettoa(bhp->peerip),bhp->mode&FWSAM_WHO_SRC?inettoa(bhp->peerip):inettoa(bhp->blockip),bhp->port,protoe->p_name);
		break;
		case FWSAM_HOW_IN:
			snprintf(msg,sizeof(msg)-1,"Removing%s inbound block %s host %s.",durmsg,comment,inettoa(bhp->blockip));
		break;
		case FWSAM_HOW_OUT:
			snprintf(msg,sizeof(msg)-1,"Removing%s outbound block %s host %s.",durmsg,comment,inettoa(bhp->blockip));
		break;
		case FWSAM_HOW_INOUT:
			snprintf(msg,sizeof(msg)-1,"Removing%s complete block %s host %s.",durmsg,comment,inettoa(bhp->blockip));
		break;
		default:
			snprintf(msg,sizeof(msg)-1,"Removing weird%s block %s host %s.",durmsg,comment,inettoa(bhp->blockip));
		break;
	}
	logmessage(2,msg,"snortsam",reqip);
	
	bhp->blocktime=time(NULL);

	/* note all info to check against at the next block request to avoid duplicate blocks */
	if(force)
	{	if(skiphosts>0)	
		{	memcpy(&skiphostsfield[currentskiphost],bhp,sizeof(BLOCKINFO));
			if(++currentskiphost>=skiphosts)   /* advance the skip pointer (in a ring) */
				currentskiphost=0;
		}
	}
	addrequesttoqueue(FALSE,bhp,force,FALSE,FALSE,reqip);  /* ...add unblock request for it to queue */
}

/* This function loads the history file into memory.
 * Optionally, it will invoke blocks for all currently listed IP again.
*/
void reloadhistory(int reblock)
{	int i=0,changefilename=FALSE;
	FILE *fp;
	char buf[STRBUFSIZE+2],histversion=-1;
	BLOCKHISTORY *bhp;
	OLDBLOCKINFO *obi=NULL;
	time_t now;
	struct protoent *protoe;
	unsigned long diff;
	
	if(keepblockhistory || !avoidstatefile)			/* If SnortSam needs to keep track of blocks... */
	{	clearhistory();
	
		printf("Checking for existing state file \"%s\".\n",statefile);
		fp=fopen(statefile,"rb");		/* We check if a state file is present (check new location first) */
		if(!fp && stricmp(statefile,FWSAMHISTORYFILE))
		{	printf("Not found, trying \"%s\".\n",FWSAMHISTORYFILE);
			fp=fopen(FWSAMHISTORYFILE,"rb");		/* perhaps under the default name? */
			if(fp)
				changefilename=TRUE;
		}
		if(!fp)
			printf("Not found.\n");
		else
		{	printf("Found. Reading state file.\n");
			bhp=NULL;
			do
			{	if(!bhp)
					bhp=safemalloc(sizeof(BLOCKHISTORY),"main","blockhistory");	/* Alloc a struct for block history */
					
				if(histversion== -1)		/* If we don't know yet what version the file is... */
				{	fread(buf,6,1,fp);		/* ...read first 6 bytes and check. */
					buf[6]=0;
					if(!strncmp(buf,FWSAMHISTORYVERSION,4)) /* If it has a header... */
						histversion=atoi(buf+4);			/* ...note the version. */
					else
					{	histversion=0;						/* If it doesn't, it's old-style */
						obi=safemalloc(sizeof(OLDBLOCKINFO),"main","oldblockinfo (obi)"); /* get a struct for conversion */
						rewind(fp);							/* Since the old version didn't have a header, rewind file. */
					}
				}
				switch(histversion)
				{	case 0:		i=fread(obi,sizeof(OLDBLOCKINFO),1,fp);
								if(i==1)
								{	bhp->blockinfo.blockip=obi->blockip;
									bhp->blockinfo.peerip=obi->peerip;
									bhp->blockinfo.duration=obi->duration;
									bhp->blockinfo.blocktime=obi->blocktime;
									bhp->blockinfo.port=obi->port;
									bhp->blockinfo.proto=obi->proto;
									bhp->blockinfo.mode=obi->mode;
									bhp->blockinfo.block=obi->block;
									bhp->blockinfo.sig_id=0;
								}
								break;
					case 1:		i=fread(&(bhp->blockinfo),sizeof(BLOCKINFO),1,fp);
								break;
				}
				if(i==1) /* Read in one history element */
				{	if(useonlyblock && !onlyblockhost(bhp->blockinfo.blockip,TRUE))
					{	snprintf(msg,sizeof(msg)-1,"Ignoring entry for host %s in state file.",inettoa(bhp->blockinfo.blockip));
						logmessage(3,msg,"snortsam",0);
					}
					else
					{	if(dontblockhost(bhp->blockinfo.blockip,TRUE))						/* If the blocked host is on the whitelist... */
						{	if(useonlyunblock && !onlyblockhost(bhp->blockinfo.blockip,TRUE)) /* ...and we're allowed to unblockit... */
							{	snprintf(msg,sizeof(msg)-1,"Keeping entry for non-unblockable host %s in state file.",inettoa(bhp->blockinfo.blockip));
								logmessage(3,msg,"snortsam",0);
							}
							else
							{	if(!reblock)
									unblock(&(bhp->blockinfo),"for white-listed",0,TRUE);		/* ...add unblock request for it to queue */
								else
								{	snprintf(msg,sizeof(msg)-1,"Ignoring entry for white-listed host %s in state file.",inettoa(bhp->blockinfo.blockip));
									logmessage(3,msg,"snortsam",0);
								}
							}
						}
						else
						{	if(reblock)  /* If we should re-instate blocks */
							{	now=time(NULL);
								if(bhp->blockinfo.blocktime+bhp->blockinfo.duration<now && bhp->blockinfo.duration>0) /* Check if the block is already expired */
								{	snprintf(msg,sizeof(msg)-1,"Did NOT reinstate block for host %s (by Sig_ID: %lu) because block duration of %lu seconds has alread expired.",inettoa(bhp->blockinfo.blockip),bhp->blockinfo.sig_id,(unsigned long)bhp->blockinfo.duration);
									logmessage(3,msg,"snortsam",0);
								}
								else  /* If not, we subtract the already passed duration, and block for the remaining time */
								{	if(bhp->blockinfo.duration)
									{	diff=now - bhp->blockinfo.blocktime;
										if(diff>0)
										{	if(diff < bhp->blockinfo.duration)
												bhp->blockinfo.duration-=diff;
											else
												bhp->blockinfo.duration=1;
										}
										else
											bhp->blockinfo.duration=1;
									
										switch(bhp->blockinfo.mode&FWSAM_HOW)
										{	case FWSAM_HOW_THIS:
												protoe=getprotobynumber(bhp->blockinfo.proto);
												snprintf(msg,sizeof(msg)-1,"Reinstating block for host %s in connection %s->%s:%d (%s) for the remaining %lu seconds (Sig_ID: %lu).",inettoa(bhp->blockinfo.blockip),bhp->blockinfo.mode&FWSAM_WHO_SRC?inettoa(bhp->blockinfo.blockip):inettoa(bhp->blockinfo.peerip),bhp->blockinfo.mode&FWSAM_WHO_SRC?inettoa(bhp->blockinfo.peerip):inettoa(bhp->blockinfo.blockip),bhp->blockinfo.port,protoe->p_name,(unsigned long)bhp->blockinfo.duration,bhp->blockinfo.sig_id); 
											break;
											case FWSAM_HOW_IN:
												snprintf(msg,sizeof(msg)-1,"Reinstating block for host %s inbound for the remaining %lu seconds (Sig_ID: %lu).",inettoa(bhp->blockinfo.blockip),(unsigned long)bhp->blockinfo.duration,bhp->blockinfo.sig_id);
											break;
											case FWSAM_HOW_OUT:
												snprintf(msg,sizeof(msg)-1,"Reinstating block for host %s outbound for the remaining %lu seconds (Sig_ID: %lu).",inettoa(bhp->blockinfo.blockip),(unsigned long)bhp->blockinfo.duration,bhp->blockinfo.sig_id);
											break;
											case FWSAM_HOW_INOUT:
												snprintf(msg,sizeof(msg)-1,"Reinstating block for host %s completely for the remaining %lu seconds (Sig_ID: %lu).",inettoa(bhp->blockinfo.blockip),(unsigned long)bhp->blockinfo.duration,bhp->blockinfo.sig_id);
											break;
											default:
												snprintf(msg,sizeof(msg)-1,"Reinstating block for host %s in a weird way for the remaining %lu seconds (Sig_ID: %lu). (Let me know if you see this message!) ",inettoa(bhp->blockinfo.blockip),(unsigned long)bhp->blockinfo.duration,bhp->blockinfo.sig_id);
											break;
										}
									}
									else
									{	switch(bhp->blockinfo.mode&FWSAM_HOW)
										{	case FWSAM_HOW_THIS:
												protoe=getprotobynumber(bhp->blockinfo.proto);
												snprintf(msg,sizeof(msg)-1,"Reinstating permanent block for host %s in connection %s->%s:%d (%s) (Sig_ID: %lu).",inettoa(bhp->blockinfo.blockip),bhp->blockinfo.mode&FWSAM_WHO_SRC?inettoa(bhp->blockinfo.blockip):inettoa(bhp->blockinfo.peerip),bhp->blockinfo.mode&FWSAM_WHO_SRC?inettoa(bhp->blockinfo.peerip):inettoa(bhp->blockinfo.blockip),bhp->blockinfo.port,protoe->p_name,bhp->blockinfo.sig_id); 
											break;
											case FWSAM_HOW_IN:
												snprintf(msg,sizeof(msg)-1,"Reinstating permanent block for host %s inbound (Sig_ID: %lu).",inettoa(bhp->blockinfo.blockip),bhp->blockinfo.sig_id);
											break;
											case FWSAM_HOW_OUT:
												snprintf(msg,sizeof(msg)-1,"Reinstating permanent block for host %s outbound (Sig_ID: %lu).",inettoa(bhp->blockinfo.blockip),bhp->blockinfo.sig_id);
											break;
											case FWSAM_HOW_INOUT:
												snprintf(msg,sizeof(msg)-1,"Reinstating permanent block for host %s completely (Sig_ID: %lu).",inettoa(bhp->blockinfo.blockip),bhp->blockinfo.sig_id);
											break;
											default:
												snprintf(msg,sizeof(msg)-1,"Reinstating permanent block for host %s in a weird way (Sig_ID: %lu). (Let me know if you see this message!) ",inettoa(bhp->blockinfo.blockip),bhp->blockinfo.sig_id);
											break;
										}
									}

									logmessage(2,msg,"snortsam",0);
									bhp->blockinfo.blocktime=now;
									addrequesttoqueue(TRUE,&(bhp->blockinfo),FALSE,FALSE,signal_usr1,0);	/* add block request to queue */
									queuehandler();		/* And process queueitems added (required to avoid overflowing the queue) */
									waitms(200);		/* Had to throttle reload'n'block loop. Some firewalls didn't keep up */
									addtohistory(bhp,FALSE);
									bhp=NULL;
								}
							}
							else
							{	addtohistory(bhp,FALSE);
								bhp=NULL;
							}
						}
					}
				}
				else
				{	fclose(fp);		/* if there is no more data, close file. */
					if(bhp)
						free(bhp);		/* give back extra struct */
					if(obi)
						free(obi);
					fp=NULL;
				}
			}while(fp);
			
			if(changefilename)
			{	savehistory();
				unlink(FWSAMHISTORYFILE);
			}
		}
	}
}

int processincomingrequest(SENSORLIST *snortbox,char *buf,unsigned long packetsize,ACCEPTLIST *acceptp)
{	int decrypterror,i,ret=TRUE,makenewkeys=FALSE;
	char *decp,bmode,orgstatus=0,packstat;
	FWsamPacket packet;
	unsigned short bproto,bsport,bdport;
	unsigned long bduration,bsip,bdip,len,bsig_id;
	BLOCKINFO blocki;
	BLOCKHISTORY *bhp,*bhpbefore,*bhptemp,*oldblock;
	time_t mytime;
						
	decrypterror=FALSE;
	decp=(char *)&packet;
	/* try to decrypt the packet using current key */
	len=TwoFishDecrypt(buf,&decp,packetsize,FALSE,snortbox->snortfish);
	if(len!=sizeof(FWsamPacket) && len!=sizeof(Old13FWsamPacket)) /* invalid decryption */
	{	safecopy(snortbox->currentkey,acceptp->initialkey); /* try intial key */
		TwoFishDestroy(snortbox->snortfish);
		snortbox->snortfish=TwoFishInit(snortbox->currentkey); /* get a new TwoFish */
		len=TwoFishDecrypt(buf,&decp,packetsize,FALSE,snortbox->snortfish); /* and try again */
		decrypterror=TRUE;
		logmessage(3,"Had to use initial key!","snortsam",snortbox->snortip.s_addr);
	}
	if(len==sizeof(FWsamPacket) || len==sizeof(Old13FWsamPacket)) /* if we decrypted a packet */
	{	packetsize=len;
#ifdef FWSAMDEBUG
		printf("Debug: Received Packet: %s\n",packet.status==FWSAM_STATUS_CHECKIN?"CHECKIN":
											  packet.status==FWSAM_STATUS_CHECKOUT?"CHECKOUT":
											  packet.status==FWSAM_STATUS_BLOCK?"BLOCK":
											  packet.status==FWSAM_STATUS_UNBLOCK?"UNBLOCK":"**UNKNOWN**");
		printf("Debug: Snort SeqNo:  %x\n",packet.snortseqno[0]|(packet.snortseqno[1]<<8));
		printf("Debug: Mgmt SeqNo :  %x\n",packet.fwseqno[0]|(packet.fwseqno[1]<<8));
		printf("Debug: Status     :  %i\n",packet.status);
		printf("Debug: Version    :  %i\n",packet.version);
#endif
		if(packet.version==FWSAM_PACKETVERSION || packet.version==FWSAM_PACKETVERSION_PERSISTENT_CONN || packet.version==13)	/* snort sensor speaks our language */
		{	mytime=time(NULL);
			snortbox->packetversion=packet.version;
			if(disablepersistentconnections && packet.version==FWSAM_PACKETVERSION_PERSISTENT_CONN)
				snortbox->packetversion=packet.version=FWSAM_PACKETVERSION;
			if(packet.version==FWSAM_PACKETVERSION_PERSISTENT_CONN)
				snortbox->persistentsocket=TRUE;
			else
				snortbox->persistentsocket=FALSE;

			if(packet.status==FWSAM_STATUS_CHECKIN)  /* if sensor checks in */
			{	snortbox->snortseqno=((unsigned short)packet.snortseqno[0]) | (((unsigned short)packet.snortseqno[1])<<8); /* get snort box seqno */
				snortbox->lastcontact=mytime;			/* get lastcontact time (not used yet) */
				memcpy(snortbox->snortkeymod,packet.duration,4); /* get sensors key modifier */
				snortbox->mykeymod[0]=(unsigned char)rand();
				snortbox->mykeymod[1]=(unsigned char)rand();
				snortbox->mykeymod[2]=(unsigned char)rand();
				snortbox->mykeymod[3]=(unsigned char)rand();
				memcpy(packet.duration,snortbox->mykeymod,4); /* our key modifer */
				packet.fwseqno[0]=(unsigned char)snortbox->myseqno;	/* our sequence number */
				packet.fwseqno[1]=(unsigned char)(snortbox->myseqno>>8);
				packet.status=FWSAM_STATUS_NEWKEY;		/* and ask sensor to generate new keys */
				packet.protocol[0]=(unsigned char)rand();			/* (give him a rand on the way) */
				packet.protocol[1]=(unsigned char)rand();
				sendpacket(snortbox,(char *) &packet,packetsize);			/* and send the packet */

				newkey(snortbox,&packet);				/* finally generate new key ourselves */
			}
			else if(packet.status==FWSAM_STATUS_CHECKOUT) /* if sensor checks out */
			{	snortbox->snortseqno=((unsigned short)packet.snortseqno[0]) | (((unsigned short)packet.snortseqno[1])<<8); /* get snort box seqno */
				snortbox->myseqno+=snortbox->snortseqno;  /* prepare status packet */
				packet.status=FWSAM_STATUS_OK;			  /* let him know we'll miss him */
				packet.fwseqno[0]=(unsigned char)snortbox->myseqno;	/* our sequence number */
				packet.fwseqno[1]=(unsigned char)(snortbox->myseqno>>8);
				sendpacket(snortbox,(char *) &packet,packetsize);			  /* and off it goes */
				closesocket(snortbox->snortsocket);
				snortbox->toberemoved=TRUE;				/* Mark sensor for removal from list. */
				ret=FALSE;
			}
			else if(packet.status==FWSAM_STATUS_BLOCK || packet.status==FWSAM_STATUS_UNBLOCK)	/* if we received a blocking request */
			{	if((( (packet.fwseqno[0]|(packet.fwseqno[1]<<8)) ==snortbox->myseqno) && ( (packet.snortseqno[0]|(packet.snortseqno[1]<<8)) ==((snortbox->snortseqno+snortbox->myseqno)&0xffff) )) || disableseqnocheck)
				{	packstat=packet.status;
#ifdef FWSAMDEBUG
					printf("Debug: %s request received...\n",packet.status==FWSAM_STATUS_BLOCK?"Blocking":"Unblocking");
#endif
					bmode=packet.fwmode;			/* save parameters from packet */
					if(packet.endiancheck==1)		/* Check if peer has the same endianess */
					{	bsip=packet.srcip[0]|			
							(packet.srcip[1]<<8)|
							(packet.srcip[2]<<16)|
							(packet.srcip[3]<<24);
						bdip=packet.dstip[0] |
							(packet.dstip[1]<<8)|
							(packet.dstip[2]<<16)|
							(packet.dstip[3]<<24);
					}
					else							/* If not, then we need to read the IP address in reverse order */
					{	bsip=packet.srcip[3]|		/* Other values (port, protocol, duration) are not affected */
							(packet.srcip[2]<<8)|
							(packet.srcip[1]<<16)|
							(packet.srcip[0]<<24);
						bdip=packet.dstip[3] |
							(packet.dstip[2]<<8)|
							(packet.dstip[1]<<16)|
							(packet.dstip[0]<<24);
#ifdef FWSAMDEBUG
					printf("Debug: Peer is a different endian, switching IP octets.\n");
#endif
					}
					bsport=packet.srcport[0] |(packet.srcport[1]<<8);
					bdport=packet.dstport[0] |(packet.dstport[1]<<8);
					bproto=packet.protocol[0]|(packet.protocol[1]<<8);
					bduration=packet.duration[0] |
							 (packet.duration[1]<<8)|
							 (packet.duration[2]<<16)|
							 (packet.duration[3]<<24);

					if(packet.version==FWSAM_PACKETVERSION || packet.version==FWSAM_PACKETVERSION_PERSISTENT_CONN)		 
					{	bsig_id=packet.sig_id[0] |
					 		   (packet.sig_id[1]<<8)|
					   		   (packet.sig_id[2]<<16)|
					   		   (packet.sig_id[3]<<24);
#ifdef FWSAMDEBUG
						printf("Debug: Block triggered by Signature ID: %lu\n",bsig_id);
#endif
					}
					else
					{	bsig_id=0;
#ifdef FWSAMDEBUG
						printf("Debug: No Signature ID available. Sensor not updated to packet version %u.\n",FWSAM_PACKETVERSION);
#endif
					}
															
					snortbox->snortseqno=packet.snortseqno[0] | (packet.snortseqno[1]<<8); /* get snort box seqno */
					snortbox->myseqno+=snortbox->snortseqno; /* increase seq no */
					i=FALSE;

					if(decrypterror)		/* if we had to use the initial key to decrypt */
					{	snortbox->mykeymod[0]=rand();
						snortbox->mykeymod[1]=rand();
						snortbox->mykeymod[2]=rand();
						snortbox->mykeymod[3]=rand();
						memcpy(packet.duration,snortbox->mykeymod,4); /* our key modifer */
						packet.status=FWSAM_STATUS_RESYNC;		/* and ask the sensor to re-sync with us */
						makenewkeys=TRUE;
					}
					else if(mytime-snortbox->lastkeytime>keyinterval) /* if key life time has expired */
					{	packet.status=FWSAM_STATUS_NEWKEY;		/* we'll tell sensor to generate new ones */
						makenewkeys=TRUE;
					}
					else
						packet.status=FWSAM_STATUS_OK;

					if(holdsnort)								/* if we put Snort on hold, save the status... */
					{	orgstatus=packet.status;
						packet.status=FWSAM_STATUS_HOLD;		/* ...and send hold status. */
					}

					snortbox->lastcontact=mytime;
					packet.fwseqno[0]=(unsigned char)snortbox->myseqno;	/* our sequence number */
					packet.fwseqno[1]=(unsigned char)(snortbox->myseqno>>8);
					packet.protocol[0]=(unsigned char)rand();			/* populate the rest of the packet and */
					packet.protocol[1]=(unsigned char)rand();
					sendpacket(snortbox,(char *) &packet,packetsize);		/* send it on its way */

					if(sid_denied_from_sensor(snortbox->snortip.s_addr,bsig_id))
					{	snprintf(msg,sizeof(msg)-1,"SID %lu not permitted from sensor %s.",bsig_id,inettoa(snortbox->snortip.s_addr));
						logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
					}
					else
					{
						if(packstat==FWSAM_STATUS_BLOCK)
						{	/* call block, which performs checks */
							block(snortbox,bsip,bsport,bdip,bdport,bproto,bduration,bmode,mytime,bsig_id);
						}
						else
						{	
							if((bmode&FWSAM_WHO)==FWSAM_WHO_DST) /* check who we are blocking and get the IP address */
							{	blocki.blockip=bdip;
								blocki.port=bdport;	/* the blocked port for 'service/connection' type blocks should always be the port of the peer. */
								blocki.peerip=bsip;			/* Change it here if you want to change the behaviour (i.e. always peer port) */
							}
							else
							{	blocki.blockip=bsip;
								blocki.port=bdport;
								blocki.peerip=bdip;
							}
							
							if((bmode&FWSAM_HOW)==FWSAM_HOW_THIS)
								blocki.proto=bproto;
							else
								blocki.peerip=blocki.proto=blocki.port=0;
							
							oldblock=inhistory(&blocki);
							if(oldblock)
							{	unblock(&(oldblock->blockinfo),"manually on existing block for",snortbox->snortip.s_addr,TRUE);	/* add unblock equest to queue with previous block data */ 											
								if(!avoidstatefile || keepblockhistory)	/* Remove old block from history now that we manually unblocked it */
								{	bhp=firstblockhistory;
									i=FALSE;
									bhpbefore=NULL;
									while(bhp && !i)
									{	if(bhp == oldblock) /* we check if we have a match for this block */
										{	if(bhpbefore)
												bhpbefore->next=bhp->next;		/* take element out of the chain */
											else
												firstblockhistory=bhp->next;
											bhptemp=bhp;
											bhp=bhp->next;						/* advance pointers */
											free(bhptemp);
											i=TRUE;					/* Yes, we unblocked something */
										}
										else
										{	bhpbefore=bhp;
											bhp=bhp->next;
										}
									}
									savestatefile=TRUE;	/* flush whole chain to file */
								}
							}
							else	/* If we haven't previously blocked this host (or don't know about it)
									   then we force an unblock. This may or may not return an error on the
									   firewall, but hey, you manually requested it, so it's not Snortsams fault :) */
							{	blocki.mode=bmode;
								blocki.blocktime=mytime;
								blocki.sig_id=bsig_id;

								/* check for and get a blocktime limit out of the limit list based on the sensor*/
								blocki.duration=limit_duration_on_sensor(snortbox->snortip.s_addr,bduration);	

								/* check for and get new duration out of override list for the host to be blocked */
								blocki.duration=override_duration_on_host(blocki.blockip,blocki.duration);	

								unblock(&blocki,"manually for",snortbox->snortip.s_addr,TRUE);	/* add unblock equest to queue */
							}
						}
					}
					
					if(holdsnort)	/* if we keep Snort on hold, send packet after block.  */
					{	packet.status=orgstatus;
						sendpacket(snortbox,(char *) &packet,packetsize);		/* send original status packet */
					}
					
					if(makenewkeys)
						newkey(snortbox,&packet);		/* we'll generate new keys ourselves */
				}
				else /* Following error should never be seen, unless someone is spoofing (successfully encrypted) packets */
				{	snprintf(msg,sizeof(msg)-1,"Error: Packet out of sequence from %s, trying to re-sync.",inettoa(snortbox->snortip.s_addr));
					logmessage(1,msg,"snortsam",snortbox->snortip.s_addr);
					snortbox->mykeymod[0]=(unsigned char)rand(); /* regenerate key modifier */
					snortbox->mykeymod[1]=(unsigned char)rand();
					snortbox->mykeymod[2]=(unsigned char)rand();
					snortbox->mykeymod[3]=(unsigned char)rand();
					memcpy(packet.duration,snortbox->mykeymod,4); /* our key modifer */
					packet.status=FWSAM_STATUS_RESYNC;		/* and ask the sensor to re-sync with us (or send STATUS_ERROR?) */
					snortbox->lastcontact=mytime;
					do
						snortbox->myseqno=(unsigned char)rand();		/* the seqno this host will use */
					while(snortbox->myseqno<20 || snortbox->myseqno>65500);
					packet.fwseqno[0]=(unsigned char)snortbox->myseqno;	/* our sequence number */
					packet.fwseqno[1]=(unsigned char)(snortbox->myseqno>>8);
					packet.protocol[0]=(unsigned char)rand();			/* populate the rest of the packet and */
					packet.protocol[1]=(unsigned char)rand();
					sendpacket(snortbox,(char *) &packet,packetsize);		/* send it on its way */
				}
			}
			else 
			{	snprintf(msg,sizeof(msg)-1,"Error: Unknown packet status from %s.",inettoa(snortbox->snortip.s_addr));
				logmessage(1,msg,"snortsam",snortbox->snortip.s_addr);
			}
		}
		else 
		{	snprintf(msg,sizeof(msg)-1,"Error: Protocol version error! Ignoring snort station %s.",inettoa(snortbox->snortip.s_addr));
			logmessage(1,msg,"snortsam",snortbox->snortip.s_addr);
			packet.status=FWSAM_STATUS_ERROR;

/*			packet.version=FWSAM_PACKETVERSION; 
			sendpacket(snortbox,(char *) &packet,sizeof(FWsamPacket));
*/
			sendpacket(snortbox,(char *) &packet,packetsize);
			closesocket(snortbox->snortsocket);
			snortbox->toberemoved=TRUE;				/* Mark sensor for removal from list */
			ret=FALSE;
		}
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Snort station %s using wrong password, trying to re-sync.",inettoa(snortbox->snortip.s_addr));
		logmessage(1,msg,"snortsam",snortbox->snortip.s_addr);
		packet.status=FWSAM_STATUS_ERROR;
		if(packetsize==sizeof(Old13FWsamPacket)+TwoFish_BLOCK_SIZE)
		{	packet.version=13;
			sendpacket(snortbox,(char *) &packet,sizeof(Old13FWsamPacket));
		}	
		else
		{	packet.version=snortbox->packetversion;
			sendpacket(snortbox,(char *) &packet,sizeof(FWsamPacket));
		}
		if(disablepersistentconnections)
		{	closesocket(snortbox->snortsocket);
			snortbox->snortsocket=0;
		}
		ret=FALSE;
	}
	return ret;
}

/* our main loop...
*/
int main(int argc,char *argv[])
{	int i;
	struct sockaddr_in sockaddr;
	struct in_addr callerip;
	struct hostent *hoste;
	struct linger lingr;
	char buf[STRBUFSIZE+2];
	unsigned long ll;
	int packetsize;
	SENSORLIST *snortbox,**snortboxpointer;
	ACCEPTLIST *acceptp;
#ifdef FWSAMDEBUG
	DONTBLOCKLIST *debugdbp;
	ONLYBLOCKLIST *debugobp;
#endif
	BLOCKHISTORY *bhp,**bhpp;
	time_t nowtime,lastsavetime=0,lastcheck=0;
	DATALIST *datap;
#ifdef WIN32
	struct WSAData wsad;
#else
	sigset_t set;
 	sigemptyset(&set);
	sigprocmask(SIG_SETMASK, &set, NULL);
#endif 
	

#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    /* Do some sanity checking, because some people seem to forget to
     * put spaces between their parameters
     */
    if( argc > 1 &&
        ( _stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_INSTALL_CMDLINE_PARAM))==0   ||
          _stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_UNINSTALL_CMDLINE_PARAM))==0 ||
          _stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_SHOW_CMDLINE_PARAM))==0       ) )
    {
        printf("You must have a space after the '%s' command-line parameter\n",
               SERVICE_CMDLINE_PARAM);
        exit(0);
    }

    /* If the first parameter is "/SERVICE", then start Snort as a Win32 service */
    if( argc>1 && _stricmp(argv[1],SERVICE_CMDLINE_PARAM)==0)
    {
        return SnortSamServiceMain(argc, argv);
    }

#endif /* WIN32 && ENABLE_WIN32_SERVICE */

#ifndef WIN32
	pthread_mutex_init(&inettoa_mutex, NULL);
	pthread_mutex_init(&gethstname_mutex, NULL);
	pthread_mutex_init(&loginprogress_mutex, NULL);
#endif

	signal(SIGTERM,getout);
	signal(SIGINT,getout);
	signal(SIGQUIT,getout);
	signal(SIGUSR1,sig_usr1_flagger);
	signal(SIGUSR2,sig_usr2_flagger);
/*	signal(SIGHUP,reloadconfigorsomething); */

/*	setbuf(stdout,NULL); Strange... This seems to crash NT with OPSEC libraries (not without OPSEC...odd) 		
	setbuf(stderr,NULL); 

	setvbuf(stdout, NULL, 0,0);   Disable buffering on stdout/stderr  -- crashes too. Need to check stderr stuff under Windows
	setvbuf(stderr, NULL, 0,0);
*/
	safecopy(buf,SNORTSAM_REV+11);
	buf[strlen(SNORTSAM_REV+11)-2]=0;
	printf("\nSnortSam, v %s.\nCopyright (c) 2001-2009 Frank Knobbe <frank@knobbe.us>. All rights reserved.\n\n",buf);
	
	TwoFish_srand=FALSE;			/* Since we need to rand() before any TwoFish call, */
									/* there is no need for TwoFish to initialze rand as well. */
	srand(time(NULL));				/* Intialize the random number generator. */

#ifdef WIN32
	if(WSAStartup(MAKEWORD(1,1),&wsad))				/* intialize winsock */
	{	puts("\nCould not initialize Winsock!");
		exit(1);
	}
	if(LOBYTE(wsad.wVersion)!=1 || HIBYTE(wsad.wVersion)!=1)
	{	puts("\nThis Winsock version is not supported!");
	    exit(1);
	}
#endif

	hoste=gethostbyname("127.0.0.1");		/* Accquire host entity for localhost */
	if(hoste) 
	{	ll=*(unsigned long *)hoste->h_addr;
		if((ll&255) ==1)					/* Check the byte order for IP addresses and ...*/
		{	netmaskbigendian=1;				/* set the netmask endian flag accordingly. */
#ifdef FWSAMDEBUG
			printf("Debug: System appears to be big endian.\n\n");
#endif
		}
#ifdef FWSAMDEBUG
		else
			printf("Debug: System appears to be little endian.\n\n");
#endif
	}
	gethostname(myhostname,sizeof(myhostname)-1);

	for(ll=0;ll<plugincount;ll++)
	{	printf("Plugin '%s': v %s, by %s\n",Plugins[ll].PluginHandle,Plugins[ll].PluginVersion,Plugins[ll].PluginAuthor);
		PluginStatus[ll]=INACTIVE;  		/* Initializing plugin vars... */
		FirstPluginData[ll].data=FirstPluginData[ll].next=NULL;
	}
	printf("\n");

	if(argc>1)
		safecopy(buf,argv[1]);	 /* get the argument of SnortSam (the config file) */
	else
		safecopy(buf,FWSAMCONFIGFILE);  /* if not specified, default to snortsam.cfg or /etc/snortsam.conf */

	parsefile(buf,TRUE,"",0);		 /* parse the config file */

	sortacceptlist();						/* sort the lists */
	sortoverridelist();
	sortdontblocklist();
	sortonlyblocklist();
	sortlimitlist();
	sortsidfilterlist();
	sortpluginindex();		/* We're sorting the plugins to execute multi-threaded plugins first */
	
	if(!*statefile)
		safecopy(statefile,FWSAMHISTORYFILE);
		
#ifdef FWSAMDEBUG
	if(!avoidstatefile)
		printf("Debug: Starting to keep track of blocks regardless of plugins used in file %s.\n",statefile);
#endif

	for(ll=0;ll<PluginsActive;ll++)		/* Go through list of plugins...*/	
	{	if(Plugins[PluginIndex[ll]].PluginNeedsExpiration)	/* Check if we need to remember blocks for expiration */
		{	keepblockhistory=TRUE;
#ifdef FWSAMDEBUG
			if(avoidstatefile)
				printf("Debug: Starting to keep track of blocks for plugin '%s' (and maybe others).\n",Plugins[PluginIndex[ll]].PluginHandle);
#endif
		}		

/* place to initialize other variables for active plugins */
		
		maxpluginthreads++;			/* If a plugin can not multithread or doesn't use multiple devices, */
									/* we make room for one thread. */
		if(Plugins[PluginIndex[ll]].PluginThreading==TH_MULTI)
		{	datap=&(FirstPluginData[PluginIndex[ll]]);		/* Walk the chain of devices and count possible threads. */
			while(datap->data)
			{	maxpluginthreads++;
				datap=datap->next;
			}
		}
	}
	ll=sizeof(THREADTABLE)*maxpluginthreads;
	threadtable=safemalloc(ll,"main","threadtable");			/* Allocate memory for the table */
	memset(threadtable,0,ll);				/* Set threadtable field to 0 */

	acceptp=firstaccept;
	while(acceptp)			/* use the defaultkey if no key set in the accept line */
	{	if(!acceptp->initialkey[0])
			safecopy(acceptp->initialkey,defaultkey);
		acceptp=acceptp->next;
	}

	if(skiphosts>0 && skipinterval>0)
	{	skiphostsfield=safemalloc(ll=(sizeof(BLOCKINFO)*skiphosts),"main","skiphosts"); /* Allocate a field of blockinfo's for skip checking */
		memset(skiphostsfield,0,ll);
	}

	reloadhistory(FALSE);	/* Load block history file into memory */
			
#ifdef FWSAMDEBUG
	printf("Debug: Accepting connections from:\n");
	acceptp=firstaccept;
	while(acceptp)
	{	printf("Debug: IP: %s, Mask: %s, Pass: %s\n",inettoa(acceptp->ip.s_addr),inettoa(acceptp->mask),acceptp->initialkey);
		acceptp=acceptp->next;
	}
	
	printf("Debug: Dontblock list:\n");
	debugdbp=firstdontblock;
	while(debugdbp)
	{	printf("Debug: IP: %s, Mask: %s (%s)\n",inettoa(debugdbp->ip.s_addr),inettoa(debugdbp->mask),debugdbp->block?"block":"unblock");
		debugdbp=debugdbp->next;
	}

	printf("Debug: Onlyblock list:\n");
	debugobp=firstonlyblock;
	while(debugobp)
	{	printf("Debug: IP: %s, Mask: %s (%s)\n",inettoa(debugobp->ip.s_addr),inettoa(debugobp->mask),debugobp->block?"block":"unblock");
		debugobp=debugobp->next;
	}
#endif
	
	mysock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); /* create a socket for the agent */
	if(mysock==INVALID_SOCKET)
	{	snprintf(msg,sizeof(msg)-1,"Error: Funky socket error (socket).");
		logmessage(1,msg,"snortsam",0);
		showerror(); 
		getout(1); /* barf if socket creation fails. Need to clean this up later. */
	}
	         /* i= -1; */
	/* Setting socket option to reuse address */
	i= 1;
	if(setsockopt(mysock,SOL_SOCKET,SO_REUSEADDR,(const char *)&i,sizeof(i)))
	{	snprintf(msg,sizeof(msg)-1,"Error: Funky socket error (setsockopt REUSEADDR).");
		logmessage(1,msg,"snortsam",0);
		showerror(); 
		getout(1); 
	}

	/* Setting socket option to use keep-alives */
	i= 1;
	if(setsockopt(mysock,SOL_SOCKET,SO_KEEPALIVE,(const char *)&i,sizeof(i)))
	{	snprintf(msg,sizeof(msg)-1,"Error: Funky socket error (setsockopt KEEPALIVE).");
		logmessage(1,msg,"snortsam",0);
		showerror(); 
		getout(1); 
	}

	lingr.l_onoff=1;  	/* linger enabled */
	lingr.l_linger=1;	/* lingering for 1 second upon socket close */
	if(setsockopt(mysock,SOL_SOCKET,SO_LINGER,(const char *)&lingr,sizeof(lingr)))
	{	snprintf(msg,sizeof(msg)-1,"Error: Funky socket error (setsockopt LINGER).");
		logmessage(1,msg,"snortsam",0);
		showerror(); 
		getout(1); 
	}

	sockaddr.sin_port=htons(mylistenport);
	sockaddr.sin_addr.s_addr=mybindip;
	sockaddr.sin_family=AF_INET;
	if(bind(mysock,(struct sockaddr *)&(sockaddr),sizeof(struct sockaddr)))
	{	snprintf(msg,sizeof(msg)-1,"Error: Could not bind socket.");
		logmessage(1,msg,"snortsam",0);
		showerror(); 
		getout(1); /* barf if socket creation fails. Need to clean this up later. */
	}

	snprintf(msg,sizeof(msg)-1,"Starting to listen for Snort alerts.");
	logmessage(1,msg,"snortsam",0);

	ll=-1;
	ioctlsocket(mysock,FIONBIO,&ll);	/* make sure the socket is NOT blocking since SnortSam... */
										/* ...needs to do the timeout handling for manual unblocks. */
	if(listen(mysock,3)	)		  
	{	snprintf(msg,sizeof(msg)-1,"Error: Could not listen on socket.");
		logmessage(1,msg,"snortsam",0);
		showerror();
		getout(1); /* barf if listen fails. Need to clean this up later. */
	}

#ifndef WIN32
	if(wantdaemon)			   /* If "daemon" is set in config file... */
	{	if(daemon(1, 0) != -1)     /* ..try to daemonize thyself... */ 
			daemonized=TRUE;   /* ...and let us know. */
	}
#endif

	while(TRUE)
	{	do
			waitms(10);	/* Give CPU some time to breathe (and threads time to execute)... or hang if exit signals are being processed. */	
		while(preparetodie);


/* New Connection Receive Handler (backwards compatible) */

		i=sizeof(struct sockaddr);
		callersock=accept(mysock,(struct sockaddr *)&(sockaddr),&i);	/* Check if someone called (new connections) */

		if(callersock!=INVALID_SOCKET)					/* If so, start call handling */
		{	callerip.s_addr=sockaddr.sin_addr.s_addr;
			if(callerip.s_addr)
			{	ll=0;
				ioctlsocket(callersock,FIONBIO,&ll);	/* set to blocking  */
#ifdef FWSAMDEBUG
				printf("Debug: Connection from: %s.\n",inettoa(callerip.s_addr));
#endif
				if((acceptp=allowedhost(callerip.s_addr)))   /* Check if the caller is in accept list. */
				{	snprintf(msg,sizeof(msg)-1,"Accepted connection from %s.",inettoa(callerip.s_addr));
					logmessage(3,msg,"snortsam",callerip.s_addr);
					
					packetsize=recv(callersock,buf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,0);
					
					if(packetsize==sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE || packetsize==sizeof(Old13FWsamPacket)+TwoFish_BLOCK_SIZE)
					{	/* if we got a complete packet */
						snortbox=getsnorty(callerip.s_addr,acceptp); /* get the calling sensor structure (creates one if none in the list) */
/*						if(snortbox->snortsocket)
							closesocket(snortbox->snortsocket);
*/						snortbox->snortsocket=callersock;
						callersock=0;
						
						if(processincomingrequest(snortbox,buf,packetsize,acceptp))
						{	if(snortbox->persistentsocket)	/* If sensor uses persistent connections, we set to non blocking */
							{	ll=-1;
								ioctlsocket(snortbox->snortsocket,FIONBIO,&ll);	/* set to non-blocking  */
							}
							else
							{	closesocket(snortbox->snortsocket); /* Otherwise we just close this connection and wait for the next connection to arrive */
								snortbox->snortsocket=0;
							}
						}
					}
					else
					{	snprintf(msg,sizeof(msg)-1,"Error: Received incomplete packet from %s.",inettoa(callerip.s_addr));
						logmessage(1,msg,"snortsam",callerip.s_addr);
						closesocket(callersock);
					}
				}
				else
				{	snprintf(msg,sizeof(msg)-1,"Rejected connection from %s.",inettoa(callerip.s_addr));
					logmessage(3,msg,"snortsam",callerip.s_addr);
					closesocket(callersock);
				}
			}
			else
				closesocket(callersock);
		}
		
		
/* Established Connection Poll Handler */
		
		snortbox=firstsensor;	
		while(snortbox)		/* Cycle through list of checked-in sensors ... */
		{	if(snortbox->persistentsocket)	/* ...which supports persistent connections ...*/
			{	if(snortbox->snortsocket) 	/* ...and is connected ...*/
				{	packetsize=recv(snortbox->snortsocket,buf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,MSG_PEEK);
					if(packetsize==sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE)
					{	snprintf(msg,sizeof(msg)-1,"Received data on persistent connection from %s.",inettoa(snortbox->snortip.s_addr));
						logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
					
						packetsize=recv(snortbox->snortsocket,buf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,0);
					
						if(packetsize==sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE)
						{	/* if we got a complete packet */
							processincomingrequest(snortbox,buf,packetsize,allowedhost(snortbox->snortip.s_addr));
						}
						else
						{	snprintf(msg,sizeof(msg)-1,"Error: Received incomplete packet from %s even though we were told a complete packet is there. What the hell? Close this connection!",inettoa(snortbox->snortip.s_addr));
							logmessage(1,msg,"snortsam",snortbox->snortip.s_addr);
							closesocket(snortbox->snortsocket);
							snortbox->snortsocket=0;
							snortbox->persistentsocket=FALSE;
						}
					}
#ifdef WIN32
					else if(packetsize==SOCKET_ERROR || packetsize==0)
					{	if(errno==WSAECONNRESET || errno==WSAECONNABORTED || packetsize==0)
#else
					else if(packetsize==-1 || packetsize==0)
					{	if(errno==ECONNRESET || errno==EINTR || packetsize==0)
#endif
						{	snprintf(msg,sizeof(msg)-1,"Info: Persistent connection from %s got reset.",inettoa(snortbox->snortip.s_addr));
							logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
							closesocket(snortbox->snortsocket);
							snortbox->snortsocket=0;
							snortbox->persistentsocket=FALSE;
						}
					}
				}
			}
			snortbox=snortbox->next;
		}


/* Snort box removal handler */
	
		snortboxpointer=&firstsensor;			/* start at the beginning */
		while(snortbox=*snortboxpointer)
		{	if(snortbox->toberemoved)		/* Is it the one we're looking for? */
			{	*snortboxpointer=snortbox->next;
				TwoFishDestroy(snortbox->snortfish);	/* if this is the one, free the TwoFish structure */
				if(snortbox->rbfield)				/* and all other allocated buffers */
					free(snortbox->rbfield);
				if(snortbox->rbmeterfield)
					free(snortbox->rbmeterfield);

				snprintf(msg,sizeof(msg)-1,"Removing sensor %s from list.",inettoa(snortbox->snortip.s_addr));
				logmessage(3,msg,"snortsam",snortbox->snortip.s_addr);
				free(snortbox);
			}
			else
				snortboxpointer=&(snortbox->next); /* if not, check the next */
		}


/* Unblock Handler */
		
		nowtime=time(NULL);  /* What time is it? */
		
		if(nowtime!=lastcheck)    /* we only need to check the list once every second. Let's see if a second has passed */
		{	if(firstblockhistory!=NULL && (!avoidstatefile || keepblockhistory) && !preparetodie)	/* if we need to time-out blocks ourselves... */
			{	bhpp=&firstblockhistory;
				do
				{	if((*bhpp)->blockinfo.duration && (*bhpp)->blockinfo.blocktime+(*bhpp)->blockinfo.duration<=nowtime) /* ... we check if we have expired IP's in the list */
					{	bhp=*bhpp;
						unblock(&(bhp->blockinfo),"for",0,FALSE);  		/* ...add unblock request to queue */
						*bhpp=bhp->next;
						free(bhp);
						savestatefile=TRUE;
					}
					else
						bhpp=&((*bhpp)->next);
					if(*bhpp==NULL)
						break;
				}while((*bhpp)->blockinfo.blocktime+(*bhpp)->blockinfo.duration<=nowtime);	/* Are there are more? */
				lastcheck=nowtime;		/* Note last unblock time */
			}
		}


/* Signal Handler */

		if(signal_usr1)
		{	logmessage(2,"Received Signal USR1: Reloading State File and Reinstating Blocks","snortsam",0);
			reloadhistory(TRUE);
			signal_usr1=FALSE;
		}
		if(signal_usr2)
		{	logmessage(3,"Received Signal USR2: Reloading State File","snortsam",0);
			reloadhistory(FALSE);
			signal_usr2=FALSE;
		}


/* Queue Handler (Plugin Launcher) */

		queuehandler();


/* State File Handler */

		if(savestatefile && nowtime-lastsavetime>=5)
		{	savehistory();
			lastsavetime=nowtime;
			savestatefile=FALSE;
		}
	}
}

/* This funtion checks if more than one request is in the block queue.
*/
int moreinqueue(unsigned long rp)
{	if(!rp)
		return FALSE;
	rp--;	
	if(rp==BQ_writepointer)
		return FALSE;
	return ((rp>BQ_writepointer)?(BQ_writepointer+BLOCKQUEUESIZE-rp>1):(BQ_writepointer-rp>1));
}
			
/* Queue handler routine. This function picks a work item (block or unblock)
 * out of the queue and calls the output plugins in one or more of the three
 * threading ways (real multi-threading, per-device multi-threading, and inline
 * execution without threading).
*/
void queuehandler(void)
{	unsigned long ll,plugindex;
	DATALIST *datap;
	signed long threadtableentry;
#if !defined(WIN32)
 	pthread_attr_t attr;
#endif
 			
	for(ll=0;ll<PluginsActive && !preparetodie;ll++)		/* Go through list of plugins */
	{	plugindex=PluginIndex[ll];
		if(!dontusethreads && Plugins[plugindex].PluginThreading==TH_MULTI)   /* Can plugin multithread? */
		{	datap=&(FirstPluginData[plugindex]);		/* Walk their chain of devices */
			while(datap->data && !preparetodie)
			{	if(!datap->busy)			/* if the device is not busy...*/
				{	if(datap->readpointer!=BQ_writepointer)	/* ...and still has requests in the queue...*/
					{	if(	(!(BlockQueue[datap->readpointer].extension && BlockQueue[datap->readpointer].blockinfo.block && Plugins[plugindex].PluginNeedsExpiration) &&
							  (BlockQueue[datap->readpointer].blockinfo.block || Plugins[plugindex].PluginNeedsExpiration) &&
							  (!BlockQueue[datap->readpointer].reload || Plugins[plugindex].PluginDoesReblockOnSignal) )
							|| BlockQueue[datap->readpointer].forceunblock) /* ...and it needs to act on the request...*/
						{	threadtableentry=getfreethreadindex();		/* Find free threadtable entry */
							if(threadtableentry!= -1)
							{	
								BlockQueue[datap->readpointer].processing++;	/* ...mark that queue-slot to be processed...*/
								datap->busy=TRUE;							/* ...and mark the processing device as busy */
							
								threadtable[threadtableentry].plugin=plugindex;		/* Fill entry with plugin */
								threadtable[threadtableentry].datap=datap;				/* Fill entry with data pointer */
#ifdef WIN32
								threadtable[threadtableentry].threadid=CreateThread(NULL,0,(void *)multithreadhandler,(void *)&(threadtable[threadtableentry]),0,&(threadtable[threadtableentry].winthreadid));
#else 
								pthread_attr_init(&attr);
								pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
								pthread_create((pthread_t *)&(threadtable[threadtableentry].threadid),&attr,(void *)multithreadhandler,&(threadtable[threadtableentry]));	/* Then create a thread to process the slot */
								pthread_attr_destroy(&attr);
#endif
							}
						}
						else
						{	if(++datap->readpointer>=BLOCKQUEUESIZE)		/* Advance queue pointer in ring */
								datap->readpointer=0;
						}
					}
				}
				datap=datap->next;
			}
		}
		else		/* otherwise we use a single thread or inline execution */
		{	if(!FirstPluginData[plugindex].busy)			/* if the plugin is not busy...*/
			{	if(FirstPluginData[plugindex].readpointer!=BQ_writepointer)	/* ...and still has requests in the queue...*/
				{	if(	(!(BlockQueue[FirstPluginData[plugindex].readpointer].extension && BlockQueue[FirstPluginData[plugindex].readpointer].blockinfo.block && Plugins[plugindex].PluginNeedsExpiration) &&
						  (BlockQueue[FirstPluginData[plugindex].readpointer].blockinfo.block || Plugins[plugindex].PluginNeedsExpiration) &&
						  (!BlockQueue[FirstPluginData[plugindex].readpointer].reload || Plugins[plugindex].PluginDoesReblockOnSignal) )
						|| BlockQueue[FirstPluginData[plugindex].readpointer].forceunblock)
					{		/* ...mark that queue-slot to be processed...*/
						if(!dontusethreads && Plugins[plugindex].PluginThreading==TH_SINGLE) /* If we can launch the plugin in it's own thread */
						{	threadtableentry=getfreethreadindex();		/* Find free threadtable entry */
							if(threadtableentry!= -1)
							{	BlockQueue[FirstPluginData[plugindex].readpointer].processing++;
								FirstPluginData[plugindex].busy=TRUE;
								threadtable[threadtableentry].plugin=plugindex;	/* Fill entry with plugin */
								threadtable[threadtableentry].datap=&(FirstPluginData[plugindex]);	/* Fill entry with data pointer */
#ifdef WIN32
								threadtable[threadtableentry].threadid=CreateThread(NULL,0,(void *)singlethreadhandler,(void *)&(threadtable[threadtableentry]),0,&(threadtable[threadtableentry].winthreadid));
#else
								pthread_attr_init(&attr);
								pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
								pthread_create((pthread_t *)&(threadtable[threadtableentry].threadid),&attr,(void *)singlethreadhandler,&(threadtable[threadtableentry]));
								pthread_attr_destroy(&attr);
#endif
							}
						}
						else  /* If not threadable we execute the plugin inline */
						{	BlockQueue[FirstPluginData[plugindex].readpointer].processing++;
							FirstPluginData[plugindex].busy=TRUE;
							datap=&(FirstPluginData[plugindex]);
							while(datap && !preparetodie)
							{	Plugins[plugindex].PluginBlock(&(BlockQueue[FirstPluginData[plugindex].readpointer].blockinfo),datap->data,0);
								datap=datap->next;
								waitms(10);		/* just a breather for other threads */
							}
							BlockQueue[FirstPluginData[plugindex].readpointer].processing--;	/* Let queue know that we are done */
							if(++FirstPluginData[plugindex].readpointer>=BLOCKQUEUESIZE)		/* Advance queue pointer in ring */
								FirstPluginData[plugindex].readpointer=0;
							FirstPluginData[plugindex].busy=FALSE;						/* Mark device as available for more request */
						}
					}
					else
					{	if(++FirstPluginData[plugindex].readpointer>=BLOCKQUEUESIZE)		/* Advance queue pointer in ring */
							FirstPluginData[plugindex].readpointer=0;
					}
				}
			}	
		}
	}
}

/* 	This function adds a (un-)blocking request to the queue
*/
void addrequesttoqueue(short block,BLOCKINFO *bp,int forceunblock,int extend,int reload,unsigned long originator)
{	char msg[STRBUFSIZE+2];

	while(BlockQueue[BQ_writepointer].processing)	/* If the queue is filled up (write pointer slot still has a processing thread...*/
	{	snprintf(msg,sizeof(msg)-1,"Block-Process-Queue is filled up! Waiting 3 secs...");
		logmessage(1,msg,"snortsam",0);				/* ...then give an error and...*/ 
		waitms(QUEUE_RETRYTIME);					/* ...wait 3 seconds. */
	}
	bp->block=block;								/* set to block or unblock */	
	memcpy(&(BlockQueue[BQ_writepointer].blockinfo),bp,sizeof(BLOCKINFO)); /* copy info into queue */
	BlockQueue[BQ_writepointer].forceunblock=forceunblock;
	BlockQueue[BQ_writepointer].extension=extend;
	BlockQueue[BQ_writepointer].reload=reload;
	BlockQueue[BQ_writepointer].originator=originator;
	if(++BQ_writepointer>=BLOCKQUEUESIZE)			/* advance queue pointer in ring */
		BQ_writepointer=0;
}

/* 	This routine calls the blocking function of the plugin for the device
 *	and advances the devices read-queue pointer. Upon completion, it marks
 *	the device as available again for more requests.
*/	
void multithreadhandler(THREADTABLE *tablep)
{	
	/* Call the plugin block */
	Plugins[tablep->plugin].PluginBlock(&(BlockQueue[tablep->datap->readpointer].blockinfo),tablep->datap->data,tablep->datap->readpointer+1);
	BlockQueue[tablep->datap->readpointer].processing--;	/* Let queue know that we are done */
	if(++tablep->datap->readpointer>=BLOCKQUEUESIZE)		/* Advance queue pointer in ring */
		tablep->datap->readpointer=0;
	tablep->threadid=0;										/* Mark table entry as available */
	tablep->datap->busy=FALSE;								/* Mark device as available for more request */

#ifdef WIN32
	ExitThread(0);
#else
	pthread_exit(0);										/* End the thread */
#endif
}

/* 	This routine walks the device list of a plugin and calls the blocking function
 *	one-by-one sequentially (as opposed to simultaneously). Upon completion, it marks
 *	the whole plugin as available again for more requests.
*/	
void singlethreadhandler(THREADTABLE *tablep)   /*   crashes OPSEC */
{	DATALIST *plugindatalistp;

	/* Call the plugin block */
	plugindatalistp=tablep->datap;
	while(plugindatalistp && !preparetodie)
	{	if(plugindatalistp->data)
			Plugins[tablep->plugin].PluginBlock(&(BlockQueue[tablep->datap->readpointer].blockinfo),plugindatalistp->data,0);
		plugindatalistp=plugindatalistp->next;
		waitms(10);		/* just a breather for other threads */
	}
	BlockQueue[tablep->datap->readpointer].processing--;	/* Let queue know that we are done */
	if(++tablep->datap->readpointer>=BLOCKQUEUESIZE)		/* Advance queue pointer in ring */
		tablep->datap->readpointer=0;
	tablep->threadid=0;								/* Mark table entry as available */
	tablep->datap->busy=FALSE;						/* Mark device as available for more request */

#ifdef WIN32
	ExitThread(0);
#else
	pthread_exit(0);										/* End the thread */
#endif
}

/*	Function finds and returns an unused entry in the threadtable
*/
signed long getfreethreadindex(void)
{	unsigned long i=0;

	do
	{	if(!threadtable[i].threadid)
			return i;
	}while(++i<maxpluginthreads);
	return -1;
}

/* Signal USR1 flagger
 * Just sets the flag and returns
*/
void sig_usr1_flagger(int i)
{	signal_usr1=TRUE;
	return;
}

/* Signal USR2 flagger
 * Just sets the flag and returns
*/
void sig_usr2_flagger(int i)
{	signal_usr2=TRUE;
	return;
}

#undef	FWSAMDEBUG
#endif

