/* $Id: samtool.c,v 1.10 2009/11/27 01:39:39 fknobbe Exp $
 *
 * samtool.c
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
 * Purpose:
 *
 * This tool sends (un)blocking requests to a remote host running SnortSam
 * (the agent) which will (un)block the intruding IP address on a variety of
 * host and network firewalls.
 * The communication over the network is encrypted using two-fish.
 * (Implementation ripped from CryptCat by Farm9 with permission.)
 *
 *
 * Comments:
 * 
 *
 *
*/


#ifndef		__SAMTOOL_C__
#define		__SAMTOOL_C__

#include "snortsam.h"

#define SAMTOOL_REV                    "$Revision: 1.10 $"

#define NUM_HOSTS				255		/* We cache up to this many IPs for a name */
#define FWSAM_NETWAIT			1000		/* 100th of a second. 10 sec timeout for network connections */
#define FWSAM_NETHOLD			6000		/* 100th of a second. 60 sec timeout for holding */

/* Typedefs */

typedef struct _FWsamstation		/* structure of a mgmt station */
{	unsigned short 			myseqno;
	unsigned short 			stationseqno;
	unsigned char			mykeymod[4];
	unsigned char			fwkeymod[4];
	unsigned short			stationport;
	struct in_addr			stationip;
	struct sockaddr_in		localsocketaddr;
	struct sockaddr_in		stationsocketaddr;
	SOCKET					stationsocket;		/* the socket of that station */
	TWOFISH					*stationfish;
	char						initialkey[TwoFish_KEY_LENGTH+2];
	char						stationkey[TwoFish_KEY_LENGTH+2];
	time_t					lastcontact;
/*	time_t					sleepstart; */
	int						persistentsocket; /* Flag for permanent connection */
	unsigned char			packetversion;	/* The packet version the sensor uses. */
}	FWsamStation;

/* Globals */

unsigned long blockip[NUM_HOSTS +1],blockpeer[NUM_HOSTS +1],blockduration=0,blocksid=0;
unsigned short blockport=0,blockproto=0,blocklog=FWSAM_LOG_NONE,blockhow=FWSAM_HOW_INOUT,blockmode=FWSAM_STATUS_BLOCK,verbose=0,checkout=TRUE;


void waitms(unsigned int dur)
{
#ifdef WIN32
        Sleep(dur);
#else
        usleep(dur*1000);
#endif
}

/*      This function (together with the define in snortsam.h) attempts
 *      to prevent buffer overflows by checking the destination buffer size.
*/
void _safecp(char *dst,unsigned long max,char *src)
{	if(dst && src && max)
	{	while(--max>0 && *src)
			*dst++ = *src++;
		*dst=0;
	}
}

/*  Generates a new encryption key for TwoFish based on seq numbers and a random that
 *  the SnortSam agents send on checkin (in protocol)
*/
void FWsamNewStationKey(FWsamStation *station,FWsamPacket *packet)
{	unsigned char newkey[TwoFish_KEY_LENGTH+2];
	int i;

	newkey[0]=packet->snortseqno[0];		/* current snort seq # (which both know) */
	newkey[1]=packet->snortseqno[1];			
	newkey[2]=packet->fwseqno[0];			/* current SnortSam seq # (which both know) */
	newkey[3]=packet->fwseqno[1];
	newkey[4]=packet->protocol[0];		/* the random SnortSam chose */
	newkey[5]=packet->protocol[1];

	strncpy(newkey+6,station->stationkey,TwoFish_KEY_LENGTH-6); /* append old key */
	newkey[TwoFish_KEY_LENGTH]=0;

	newkey[0]^=station->mykeymod[0];		/* modify key with key modifiers which were */
	newkey[1]^=station->mykeymod[1];		/* exchanged during the check-in handshake. */
	newkey[2]^=station->mykeymod[2];
	newkey[3]^=station->mykeymod[3];
	newkey[4]^=station->fwkeymod[0];
	newkey[5]^=station->fwkeymod[1];
	newkey[6]^=station->fwkeymod[2];
	newkey[7]^=station->fwkeymod[3];

	for(i=0;i<=7;i++)
		if(newkey[i]==0)
			newkey[i]++;

	safecopy(station->stationkey,newkey);
	TwoFishDestroy(station->stationfish);
	station->stationfish=TwoFishInit(newkey);
}


/*  FWsamCheckOut will be called when samtool exists. It de-registeres this tool 
 *  from the list of sensor that the SnortSam agent keeps. 
*/
void FWsamCheckOut(FWsamStation *station)
{	FWsamPacket sampacket;
	int i,len;
	char *encbuf,*decbuf;


	if(!station->persistentsocket)
	{	station->stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
		if(station->stationsocket==INVALID_SOCKET)
		{	fprintf(stderr,"Error: [FWsamCheckOut] Invalid Socket error!\n");
			return;
		}
		if(bind(station->stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
		{	fprintf(stderr,"Error: [FWsamCheckOut] Can not bind socket!\n");
			return;
		}
		/* let's connect to the agent */
		i=!connect(station->stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr));
	}
	else
		i=TRUE;
	if(i)
	{	if(verbose>0)
			printf("Info: [FWsamCheckOut] Disconnecting from host %s.\n",inet_ntoa(station->stationip));
		/* now build the packet */
		station->myseqno+=station->stationseqno; /* increase my seqno */
		sampacket.endiancheck=1;
		sampacket.snortseqno[0]=(char)station->myseqno;
		sampacket.snortseqno[1]=(char)(station->myseqno>>8);
		sampacket.fwseqno[0]=(char)station->stationseqno; /* fill station seqno */
		sampacket.fwseqno[1]=(char)(station->stationseqno>>8);
		sampacket.status=FWSAM_STATUS_CHECKOUT;  /* checking out... */
		sampacket.version=station->packetversion;

		if(verbose>1)
		{	printf("Debug: [FWsamCheckOut] Sending CHECKOUT\n");
			printf("Debug: [FWsamCheckOut] Snort SeqNo:  %x\n",station->myseqno);
			printf("Debug: [FWsamCheckOut] Mgmt SeqNo :  %x\n",station->stationseqno);
			printf("Debug: [FWsamCheckOut] Status     :  %i\n",sampacket.status);
		}

		encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station->stationfish); /* get encryption buffer */
		len=TwoFishEncrypt((char *)&sampacket,(char **)&encbuf,sizeof(FWsamPacket),FALSE,station->stationfish); /* encrypt packet with current key */

		if(send(station->stationsocket,encbuf,len,0)==len)
		{	i=FWSAM_NETWAIT;
			ioctlsocket(station->stationsocket,FIONBIO,&i);	/* set non blocking and wait for  */
			while(i-- >1)
			{	waitms(10);					/* ...wait a maximum of 3 secs for response... */
				if(recv(station->stationsocket,encbuf,len,0)==len) /* ... for the status packet */
					i=0;
			}
			if(i) /* if we got the packet */
			{	decbuf=(char *)&sampacket;
				len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish);

				if(len!=sizeof(FWsamPacket)) /* invalid decryption */
				{	safecopy(station->stationkey,station->initialkey); /* try initial key */
					TwoFishDestroy(station->stationfish);			 /* toss this fish */
					station->stationfish=TwoFishInit(station->stationkey); /* re-initialze TwoFish with initial key */
					len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* and try to decrypt again */
					if(verbose>1)
						printf("Debug: [FWsamCheckOut] Had to use initial key!\n");
				}
				if(len==sizeof(FWsamPacket)) /* valid decryption */
				{	if(sampacket.version!=station->packetversion) /* but don't really care since we are on the way out */
						fprintf(stderr,"Error: [FWsamCheckOut] Protocol version error!\n");
				}
				else
					fprintf(stderr,"Error: [FWsamCheckOut] Password mismatch!\n");
			}
		}
		free(encbuf); /* release TwoFishAlloc'ed buffer */
	}
	else
		fprintf(stderr,"Error: [FWsamCheckOut] Could not connect to host %s for CheckOut. What the hell, we're quitting anyway! :)\n",inet_ntoa(station->stationip));

	closesocket(station->stationsocket);
	station->persistentsocket=FALSE;
}


/*  This routine registers this tool with SnortSam.
 *  It will also change the encryption key based on some variables.
*/
int FWsamCheckIn(FWsamStation *station)
{	int i,len,stationok=FALSE,again;
	FWsamPacket sampacket;
	char *encbuf,*decbuf;

	do
	{	again=FALSE;
		/* create a socket for the station */
		station->stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
		if(station->stationsocket==INVALID_SOCKET)
		{	fprintf(stderr,"Error: [FWsamCheckIn] Invalid Socket error!\n");
			return FALSE;
		}
		if(bind(station->stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
		{	fprintf(stderr,"Error: [FWsamCheckIn] Can not bind socket!\n");
			return FALSE;
		}

		/* let's connect to the agent */
		if(connect(station->stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr)))
		{	fprintf(stderr,"Error: [FWsamCheckIn] Could not connect to host %s.\n",inet_ntoa(station->stationip));
			return FALSE;
		}
		else
		{	if(verbose>0)
				printf("Info: [FWsamCheckIn] Connected to host %s.\n",inet_ntoa(station->stationip));
			/* now build the packet */
			sampacket.endiancheck=1;
			sampacket.snortseqno[0]=(char)station->myseqno; /* fill my sequence number number */
			sampacket.snortseqno[1]=(char)(station->myseqno>>8); /* fill my sequence number number */
			sampacket.status=FWSAM_STATUS_CHECKIN; /* let's check in */
			sampacket.version=station->packetversion; /* set the packet version */
			memcpy(sampacket.duration,station->mykeymod,4);  /* we'll send SnortSam our key modifier in the duration slot */
												   /* (the checkin packet is just the plain initial key) */
			if(verbose>1)
			{	printf("Debug: [FWsamCheckIn] Sending CHECKIN\n");
				printf("Debug: [FWsamCheckIn] Snort SeqNo:  %x\n",station->myseqno);
				printf("Debug: [FWsamCheckIn] Mode       :  %i\n",sampacket.status);
				printf("Debug: [FWsamCheckIn] Version    :  %i\n",sampacket.version);
			}

			encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station->stationfish); /* get buffer for encryption */
			len=TwoFishEncrypt((char *)&sampacket,(char **)&encbuf,sizeof(FWsamPacket),FALSE,station->stationfish); /* encrypt with initial key */
			if(send(station->stationsocket,encbuf,len,0)!=len) /* weird...could not send */
				fprintf(stderr,"Error: [FWsamCheckIn] Could not send to host %s.\n",inet_ntoa(station->stationip));
			else
			{	i=FWSAM_NETWAIT;
				ioctlsocket(station->stationsocket,FIONBIO,&i);	/* set non blocking and wait for  */
				while(i-- >1)
				{	waitms(10); /* wait a maximum of 3 secs for response */
					if(recv(station->stationsocket,encbuf,len,0)==len)
						i=0;
				}
				if(!i) /* time up? */
					fprintf(stderr,"Error: [FWsamCheckIn] Did not receive response from host %s.\n",inet_ntoa(station->stationip));
				else
				{	decbuf=(char *)&sampacket; /* got status packet */
					len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try to decrypt with initial key */
					if(len==sizeof(FWsamPacket)) /* valid decryption */
					{	if(verbose>1)
						{
							printf("Debug: [FWsamCheckIn] Received %s\n",sampacket.status==FWSAM_STATUS_OK?"OK":
																	   sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
																	   sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
																	   sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
							printf("Debug: [FWsamCheckIn] Snort SeqNo:  %x\n",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
							printf("Debug: [FWsamCheckIn] Mgmt SeqNo :  %x\n",sampacket.fwseqno[0]|(sampacket.fwseqno[1]<<8));
							printf("Debug: [FWsamCheckIn] Status     :  %i\n",sampacket.status);
							printf("Debug: [FWsamCheckIn] Version    :  %i\n",sampacket.version);
						}

						if(sampacket.version==FWSAM_PACKETVERSION_PERSISTENT_CONN || sampacket.version==FWSAM_PACKETVERSION) /* master speaks my language */
						{	if(sampacket.status==FWSAM_STATUS_OK || sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC) 
							{	station->stationseqno=sampacket.fwseqno[0]|(sampacket.fwseqno[1]<<8); /* get stations seqno */
								station->lastcontact=(unsigned long)time(NULL);
								stationok=TRUE;
								station->packetversion=sampacket.version;
								if(sampacket.version==FWSAM_PACKETVERSION)
									station->persistentsocket=FALSE;
								
								if(sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)	/* generate new keys */
								{	memcpy(station->fwkeymod,sampacket.duration,4); /* note the key modifier */
									FWsamNewStationKey(station,&sampacket); /* and generate new TwoFish keys (with key modifiers) */
									if(verbose>1)
										printf("Debug: [FWsamCheckIn] Generated new encryption key...\n");
								}
							}
							else if(sampacket.status==FWSAM_STATUS_ERROR && sampacket.version==FWSAM_PACKETVERSION) 
							{	if(station->persistentsocket)
								{	fprintf(stderr,"Info: [FWsamCheckIn] Host %s doesn't support packet version %i for persistent connections. Trying packet version %i.\n",inet_ntoa(station->stationip),FWSAM_PACKETVERSION_PERSISTENT_CONN,FWSAM_PACKETVERSION);
									station->persistentsocket=FALSE;
									station->packetversion=FWSAM_PACKETVERSION;
									again=TRUE;
								}
								else
									fprintf(stderr,"Error: [FWsamCheckIn] Protocol version mismatch! Ignoring host %s!\n",inet_ntoa(station->stationip));
							}
							else /* weird, got a strange status back */
								fprintf(stderr,"Error: [FWsamCheckIn] Funky handshake error! Ignoring host %s!\n",inet_ntoa(station->stationip));
						}
						else /* packet version does not match */
							fprintf(stderr,"Error: [FWsamCheckIn] Protocol version error! Ignoring host %s!\n",inet_ntoa(station->stationip));
					}
					else /* key does not match */
						fprintf(stderr,"Error: [FWsamCheckIn] Password mismatch! Ignoring host %s!\n",inet_ntoa(station->stationip));
				}
			}
			free(encbuf); /* release TwoFishAlloc'ed buffer */
		}
		if(!(stationok && station->persistentsocket))
			closesocket(station->stationsocket);
	}while(again);
	return stationok;
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

/* This does nothing else than inet_ntoa, but it keeps 256 results in a static string
 * unlike inet_ntoa which keeps only one. This is used for (s)printf's were two IP
 * addresses are printed (this has been increased from four while multithreading the app).
*/
char *inettoa(unsigned long ip)
{	struct in_addr ips;
	static char addr[20];

	ips.s_addr=ip;
	strncpy(addr,inet_ntoa(ips),19);
	addr[19]=0;
	return addr;
}

int FWsamBlock(char *arg)
{	char str[512],*p,*encbuf,*decbuf,*samport,*sampass,*samhost;
	int i,error=TRUE,len,ipidx=0,peeridx=0;
	FWsamPacket sampacket;
	struct hostent *hoste;
	unsigned long samip;
	FWsamStation station;

			

	safecopy(str,arg);
	samhost=str;
	samport=NULL;
	sampass=NULL;
	p=str;
	while(*p && *p!=':' && *p!='/') 
		p++;
	if(*p==':')
	{	*p++=0;
		if(*p)
			samport=p;
		while(*p && *p!='/')
			p++;
	}
	if(*p=='/')
	{	*p++=0;
		if(*p)
			sampass=p;
	}
	samip=0;
	if(inet_addr(samhost)==INADDR_NONE)
	{	hoste=gethostbyname(samhost);
		if(!hoste)
		{	fprintf(stderr,"Error: Unable to resolve host '%s', ignoring entry!\n",samhost);
			return 1;
		}
		else
			samip=*(unsigned long *)hoste->h_addr;
	}
	else
	{	samip=inet_addr(samhost);
		if(!samip)
		{	fprintf(stderr,"Error: Invalid host address '%s', ignoring entry!\n",samhost);
			return 1;
		}
	}
	station.stationip.s_addr=samip;
	if(samport!=NULL && atoi(samport)>0)
		station.stationport=atoi(samport);
	else
		station.stationport=FWSAM_DEFAULTPORT;
	if(sampass!=NULL)
	{	strncpy(station.stationkey,sampass,TwoFish_KEY_LENGTH);
		station.stationkey[TwoFish_KEY_LENGTH]=0;
	}
	else
		station.stationkey[0]=0;

	safecopy(station.initialkey,station.stationkey);
	station.stationfish=TwoFishInit(station.stationkey);

	station.localsocketaddr.sin_port=htons(0);
	station.localsocketaddr.sin_addr.s_addr=0;
	station.localsocketaddr.sin_family=AF_INET;
	station.stationsocketaddr.sin_port=htons(station.stationport);
	station.stationsocketaddr.sin_addr=station.stationip;
	station.stationsocketaddr.sin_family=AF_INET;

	do
		station.myseqno=rand();
	while(station.myseqno<20 || station.myseqno>65500);
	station.mykeymod[0]=rand();
	station.mykeymod[1]=rand();
	station.mykeymod[2]=rand();
	station.mykeymod[3]=rand();
	station.stationseqno=0;
	station.persistentsocket=TRUE;
	station.packetversion=FWSAM_PACKETVERSION_PERSISTENT_CONN;
	
	if(FWsamCheckIn(&station))
	{	error=FALSE;
	
		do
		{	ipidx=0;
			do
			{	if(!station.persistentsocket)
				{	/* create a socket for the station */
					station.stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
					if(station.stationsocket==INVALID_SOCKET)
					{	fprintf(stderr,"Error: [FWsamBlock] Invalid Socket error!\n");
						error=TRUE;
					}
					if(bind(station.stationsocket,(struct sockaddr *)&(station.localsocketaddr),sizeof(struct sockaddr)))
					{	fprintf(stderr,"Error: [FWsamBlock] Can not bind socket!\n");
						error=TRUE;
					}
				}
				else
					error=FALSE;
				if(!error)
				{	if(!station.persistentsocket)
					{	/* let's connect to the agent */
						if(connect(station.stationsocket,(struct sockaddr *)&station.stationsocketaddr,sizeof(struct sockaddr)))
						{	fprintf(stderr,"Error: [FWsamBlock] Could not send block to host %s.\n",inet_ntoa(station.stationip));
							closesocket(station.stationsocket);
							error=TRUE;
						}
					}
					
					if(!error)
					{	if(verbose>0)
							printf("Info: [FWsamBlock] Connected to host %s. %s IP %s.\n",inet_ntoa(station.stationip),blockmode==FWSAM_STATUS_BLOCK?"Blocking":"Unblocking",inettoa(blockip[ipidx]));

						/* now build the packet */
						station.myseqno+=station.stationseqno; /* increase my seqno by adding agent seq no */
						sampacket.endiancheck=1;						/* This is an endian indicator for Snortsam */
						sampacket.snortseqno[0]=(char)station.myseqno;
						sampacket.snortseqno[1]=(char)(station.myseqno>>8);
						sampacket.fwseqno[0]=(char)station.stationseqno;/* fill station seqno */
						sampacket.fwseqno[1]=(char)(station.stationseqno>>8);	
						sampacket.status=blockmode;			/* set block action */
						sampacket.version=station.packetversion;			/* set packet version */
						sampacket.duration[0]=(char)blockduration;		/* set duration */
						sampacket.duration[1]=(char)(blockduration>>8);
						sampacket.duration[2]=(char)(blockduration>>16);
						sampacket.duration[3]=(char)(blockduration>>24);
						sampacket.fwmode=blocklog|blockhow|FWSAM_WHO_SRC; /* set the mode */
						sampacket.dstip[0]=(char)blockpeer[peeridx]; /* destination IP */
						sampacket.dstip[1]=(char)(blockpeer[peeridx]>>8);
						sampacket.dstip[2]=(char)(blockpeer[peeridx]>>16);
						sampacket.dstip[3]=(char)(blockpeer[peeridx]>>24);
						sampacket.srcip[0]=(char)blockip[ipidx];	/* source IP */
						sampacket.srcip[1]=(char)(blockip[ipidx]>>8);
						sampacket.srcip[2]=(char)(blockip[ipidx]>>16);
						sampacket.srcip[3]=(char)(blockip[ipidx]>>24);
						sampacket.protocol[0]=(char)blockproto;	/* protocol */
						sampacket.protocol[1]=(char)(blockproto>>8);/* protocol */

						if(blockproto==6 || blockproto==17)
						{	sampacket.dstport[0]=(char)blockport;
							sampacket.dstport[1]=(char)(blockport>>8);
						} 
						else
							sampacket.dstport[0]=sampacket.dstport[1]=0;
						sampacket.srcport[0]=sampacket.srcport[1]=0;

						sampacket.sig_id[0]=(char)blocksid;		/* set signature ID */
						sampacket.sig_id[1]=(char)(blocksid>>8);
						sampacket.sig_id[2]=(char)(blocksid>>16);
						sampacket.sig_id[3]=(char)(blocksid>>24);

						if(verbose>1)
						{	printf("Debug: [FWsamBlock] Sending %s\n",blockmode==FWSAM_STATUS_BLOCK?"BLOCK":"UNBLOCK");
							printf("Debug: [FWsamBlock] Snort SeqNo:  %x\n",station.myseqno);
							printf("Debug: [FWsamBlock] Mgmt SeqNo :  %x\n",station.stationseqno);
							printf("Debug: [FWsamBlock] Status     :  %i\n",blockmode);
							printf("Debug: [FWsamBlock] Version    :  %i\n",station.packetversion);
							printf("Debug: [FWsamBlock] Mode       :  %i\n",blocklog|blockhow|FWSAM_WHO_SRC);
							printf("Debug: [FWsamBlock] Duration   :  %li\n",blockduration);
							printf("Debug: [FWsamBlock] Protocol   :  %i\n",blockproto);
							printf("Debug: [FWsamBlock] Src IP     :  %s\n",inettoa(blockip[ipidx]));
							printf("Debug: [FWsamBlock] Src Port   :  %i\n",0);
							printf("Debug: [FWsamBlock] Dest IP    :  %s\n",inettoa(blockpeer[peeridx]));
							printf("Debug: [FWsamBlock] Dest Port  :  %i\n",blockport);
							printf("Debug: [FWsamBlock] Sig_ID     :  %lu\n",blocksid);
						}

						encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station.stationfish); /* get the encryption buffer */
						len=TwoFishEncrypt((char *)&sampacket,(char **)&encbuf,sizeof(FWsamPacket),FALSE,station.stationfish); /* encrypt the packet with current key */

						if(send(station.stationsocket,encbuf,len,0)!=len) /* weird...could not send */
						{	fprintf(stderr,"Error: [FWsamBlock] Could not send to host %s.\n",inet_ntoa(station.stationip));
							closesocket(station.stationsocket);
							error=TRUE;
						}
						else
						{	i=FWSAM_NETWAIT;
							ioctlsocket(station.stationsocket,FIONBIO,&i);	/* set non blocking and wait for  */
							while(i-- >1)							/* the response packet	 */
							{	waitms(10); /* wait for response (default maximum 3 secs */
								if(recv(station.stationsocket,encbuf,len,0)==len)
									i=0; /* if we received packet we set the counter to 0. */
										 /* by the time we check with if, it's already dec'ed to -1 */
							}
							if(!i) /* id we timed out (i was one, then dec'ed)... */
							{	fprintf(stderr,"Error: [FWsamBlock] Did not receive response from host %s.\n",inet_ntoa(station.stationip));
								closesocket(station.stationsocket);
								error=TRUE;
							}
							else /* got a packet */
							{	decbuf=(char *)&sampacket; /* get the pointer to the packet struct */
								len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station.stationfish); /* try to decrypt the packet with current key */

								if(len!=sizeof(FWsamPacket)) /* invalid decryption */
								{	safecopy(station.stationkey,station.initialkey); /* try the intial key */
									TwoFishDestroy(station.stationfish);
									station.stationfish=TwoFishInit(station.stationkey); /* re-initialize the TwoFish with the intial key */
									len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station.stationfish); /* try again to decrypt */
									if(verbose>1)
										printf("Debug: [FWsamCheckOut] Had to use initial key!\n");
								}
								if(len==sizeof(FWsamPacket)) /* valid decryption */
								{	if(sampacket.version==station.packetversion)/* master speaks my language */
									{	if(sampacket.status==FWSAM_STATUS_OK || sampacket.status==FWSAM_STATUS_NEWKEY 
										|| sampacket.status==FWSAM_STATUS_RESYNC || sampacket.status==FWSAM_STATUS_HOLD) 
										{	station.stationseqno=sampacket.fwseqno[0] | (sampacket.fwseqno[1]<<8); /* get stations seqno */
											station.lastcontact=(unsigned long)time(NULL); /* set the last contact time (not used yet) */
											if(verbose>1)
											{
												printf("Debug: [FWsamBlock] Received %s\n",sampacket.status==FWSAM_STATUS_OK?"OK":
																						  sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
																					      sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
																					      sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
												printf("Debug: [FWsamBlock] Snort SeqNo:  %x\n",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
												printf("Debug: [FWsamBlock] Mgmt SeqNo :  %x\n",station.stationseqno);
												printf("Debug: [FWsamBlock] Status     :  %i\n",sampacket.status);
												printf("Debug: [FWsamBlock] Version    :  %i\n",sampacket.version);
											}

											if(sampacket.status==FWSAM_STATUS_HOLD)
											{	i=FWSAM_NETHOLD;			/* Stay on hold for a maximum of 60 secs (default) */
												while(i-- >1)							/* the response packet	 */
												{	waitms(10); /* wait for response  */
													if(recv(station.stationsocket,encbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,0)==sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE)
													  i=0; /* if we received packet we set the counter to 0. */
										 		}
												if(!i) /* id we timed out (i was one, then dec'ed)... */
												{	fprintf(stderr,"Error: [FWsamBlock] Did not receive response from host %s.\n",inet_ntoa(station.stationip));
													error=TRUE;
													sampacket.status=FWSAM_STATUS_ERROR;
												}
												else /* got a packet */
												{	decbuf=(char *)&sampacket; /* get the pointer to the packet struct */
													len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station.stationfish); /* try to decrypt the packet with current key */

													if(len!=sizeof(FWsamPacket)) /* invalid decryption */
													{	safecopy(station.stationkey,station.initialkey); /* try the intial key */
														TwoFishDestroy(station.stationfish);
														station.stationfish=TwoFishInit(station.stationkey); /* re-initialize the TwoFish with the intial key */
														len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station.stationfish); /* try again to decrypt */
														if(verbose>0)
															printf("Info: [FWsamBlock] Had to use initial key again!\n");
													}
													if(verbose>1)
													{	printf("Debug: [FWsamBlock] Received %s\n", sampacket.status==FWSAM_STATUS_OK?"OK":
																								   sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
																								   sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
																								   sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
														printf("Debug: [FWsamBlock] Snort SeqNo:  %x\n",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
														printf("Debug: [FWsamBlock] Mgmt SeqNo :  %x\n",station.stationseqno);
														printf("Debug: [FWsamBlock] Status     :  %i\n",sampacket.status);
														printf("Debug: [FWsamBlock] Version    :  %i\n",sampacket.version);
													}
													if(len!=sizeof(FWsamPacket)) /* invalid decryption */
													{	fprintf(stderr,"Error: [FWsamBlock] Password mismatch! Ignoring host %s.\n",inet_ntoa(station.stationip));
														error=TRUE;
														sampacket.status=FWSAM_STATUS_ERROR;
													}
													else if(sampacket.version!=station.packetversion) /* invalid protocol version */
													{	fprintf(stderr,"Error: [FWsamBlock] Protocol version error! Ignoring host %s.\n",inet_ntoa(station.stationip));
														error=TRUE;
														sampacket.status=FWSAM_STATUS_ERROR;
													}
													else if(sampacket.status!=FWSAM_STATUS_OK && sampacket.status!=FWSAM_STATUS_NEWKEY && sampacket.status!=FWSAM_STATUS_RESYNC) 
													{	fprintf(stderr,"Error: [FWsamBlock] Funky handshake error! Ignoring host %s.\n",inet_ntoa(station.stationip));
														error=TRUE;
														sampacket.status=FWSAM_STATUS_ERROR;
													}
												}
											}
											if(sampacket.status==FWSAM_STATUS_RESYNC)  /* if station want's to resync... */
											{	safecopy(station.stationkey,station.initialkey); /* ...we use the intial key... */
												memcpy(station.fwkeymod,sampacket.duration,4);	 /* and note the random key modifier */
											}
											if(sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)	
											{	
												FWsamNewStationKey(&station,&sampacket); /* generate new TwoFish keys */
												if(verbose>1)
													printf("Debug: [FWsamBlock] Generated new encryption key...\n");
											}
											if(!station.persistentsocket)
												closesocket(station.stationsocket);
										}
										else if(sampacket.status==FWSAM_STATUS_ERROR) /* if SnortSam reports an error on second try, */
										{	closesocket(station.stationsocket);				  /* something is messed up and ... */
											error=TRUE;
											fprintf(stderr,"Error: [FWsamBlock] Undetermined error right after CheckIn! Ignoring host %s.",inet_ntoa(station.stationip));
										}
										else /* an unknown status means trouble... */
										{	fprintf(stderr,"Error: [FWsamBlock] Funky handshake error! Ignoring host %s.",inet_ntoa(station.stationip));
											closesocket(station.stationsocket);
											error=TRUE;
										}
									}
									else   /* if the SnortSam agent uses a different packet version, we have no choice but to ignore it. */
									{	fprintf(stderr,"Error: [FWsamBlock] Protocol version error! Ignoring host %s.",inet_ntoa(station.stationip));
										closesocket(station.stationsocket);
										error=TRUE;
									}
								}
								else /* if the intial key failed to decrypt as well, the keys are not configured the same, and we ignore that SnortSam station. */
								{	fprintf(stderr,"Error: [FWsamBlock] Password mismatch! Ignoring host %s.",inet_ntoa(station.stationip));
									closesocket(station.stationsocket);
									error=TRUE;
								}
							}
						}
						free(encbuf); /* release of the TwoFishAlloc'ed encryption buffer */
					}
				}
				
				ipidx++;
			}while(!error && ipidx<NUM_HOSTS && blockip[ipidx]);
			peeridx++;
		}while(!error && peeridx<NUM_HOSTS && blockpeer[peeridx]);

		if(!error)
		{	if(checkout)
				FWsamCheckOut(&station);
			else
			{	closesocket(station.stationsocket);
				station.persistentsocket=FALSE;
			}
		}
	}
	TwoFishDestroy(station.stationfish);

	return error;
}

void exittool(int err)
{
#ifdef WIN32
	WSACleanup();
#endif
	exit(err);
}

void header(void)
{	char str[52];
	static int printed=FALSE;
	
	if(verbose && !printed)
	{	safecopy(str,SAMTOOL_REV+11);
	    str[strlen(SAMTOOL_REV+11)-2]=0;
		printf("\nsamtool -- A command line tool for SnortSam -- Version: %s\n\nCopyright (c) 2005-2008 Frank Knobbe <frank@knobbe.us>. All rights reserved.\n\n",str);
		printed=TRUE;
	}
}
	
int main(int argc, char **argv)
{	int curarg,i,retval=0;
	char *p,str[52];
	struct hostent *hoste;
	struct protoent *protoe;
#ifdef WIN32
	struct WSAData wsad;
#endif
	
	curarg=1;

#ifdef WIN32
	if(WSAStartup(MAKEWORD(1,1),&wsad))				/* intialize winsock */
	{	printf("\nCould not initialize Winsock!\n");
		exit(1);
	}
	if(LOBYTE(wsad.wVersion)!=1 || HIBYTE(wsad.wVersion)!=1)
	{	printf("\nThis Winsock version is not supported!\n");
	    exit(1);
	}
#endif
	
	while(curarg<argc)
	{	p=argv[curarg];
		if(*p=='-')
		{	while(*p=='-')
				p++;
			if(!strncmp(p,"b",1))
			{	blockmode=FWSAM_STATUS_BLOCK;
				curarg++;
			}
			else if(!strncmp(p,"u",1))
			{	blockmode=FWSAM_STATUS_UNBLOCK;
				curarg++;
			}
			else if(!strcmp(p,"v"))
			{	verbose=1;
				curarg++;
			}
			else if(!strcmp(p,"vv"))
			{	verbose=2;
				curarg++;
			}
			else if(!strcmp(p,"n"))
			{	checkout=FALSE;
				curarg++;
			}
			else if(!strcmp(p,"h"))
			{	verbose=TRUE;
				header();
				printf("\nParameters:    -b[lock]        Request a block of the specified IP address.\n\n"
			           "               -u[nblock]      Request the removal of a prior block.\n\n"
			           "               -i[p]           IP address (or host name) to be (un-)blocked.\n\n"
			           "               -du[ration]     Amount of seconds for the block. If you\n"
			           "                               enclose in quotes, you can use the usual time\n"
			           "                               abbreviations like sec and min.\n"
			           "                               (Default: 0   which means permanent block)\n\n"
			           "               -di[rection]    Can be:   in         Block inbound only.\n"
			           "                                         out        Block outbound only.\n"
			           "                                         full,both  Block in- and outbound.\n"
			           "                                         this,conn  Block specific connection.\n"
			           "                               (Default: full)\n\n"
			           "                               Note: Only some firewalls support connections or\n"
			           "                                     directional blocking.\n\n"
			           "               -log            Can be:   0      No logs on blocked packets.\n"
			           "                                         1-4    Log packets. (Most firewalls\n"
			           "                                                just log. Firewall-1 has 4 log\n"
			           "                                                options/levels.)\n"
			           "                               (Default: 0)\n\n"
			           "               -sid            Optional SID number to be passed for logging.\n"
			           "                               (Default: 0)\n\n"
			           "               -v[erbose]      Print additional information.\n\n"
			           "               -vv             Very verbose: Print Debug level output.\n\n"
			           "               -n              No disconnect: This tool will check-in into\n"
			           "                               Snortsam, block, and then check-out, thereby\n"
			           "                               removing any tables associated with this IP\n"
			           "                               address. By adding -n, this tool will not\n"
			           "                               check-out, thus preserving any tables (useful\n"
			           "                               when run from a Snort sensor).\n"
			           "                               Note: Causes harmless resync warnings.)\n\n"
			           "If the block type is \"CONNection\", the following options are required:\n\n"
			           "               -pe[er]         The peer IP address in that connecion.\n\n"
			           "               -pr[oto]        The IP protocol of the session (TCP, UDP, 6, 17)\n\n"
			           "               -po[rt]         Destination port of that session.\n\n\n"
			           "The rest of the command line are one or more Snortsam stations listed using the\n"
			           "same syntax as in the Snort configuration:  <host:port/password>\n\n\n"
			           "Examples:   samtool -block -ip 12.34.56.78 -dur 300  snortsam.domain.com\n"
			           "            samtool -unblock ip 10.10.1.4 myfw.corp.com/sampass\n"
			           "            samtool -b -ip 1.2.3.4 -dur \"10 min\" -dir conn -peer 10.2.0.4   \\ \n"
			           "                     -proto tcp -port 80 -log 1 -sid 1234  firewall:901/mypass\n"
			           "            samtool -b -ip mail.spam.com -dur 5days intfw.z.net ext.z.net\n\n");
				exittool(0);
			}
			else if(!strncmp(p,"i",1) || !strncmp(p,"a",1))
			{	if(++curarg <argc)
				{	if(inet_addr(argv[curarg])==INADDR_NONE)
					{	hoste=gethostbyname(argv[curarg]);
						if (!hoste) 
						{	fprintf(stderr,"Error: Unable to resolve block host '%s'!\n",argv[curarg]);
							exittool(11);
						}
						else
						{	i=0;
							do
							{	if(hoste->h_addr_list[i])
									blockip[i]=*((unsigned long *)hoste->h_addr_list[i]);
								else
									blockip[i]=0;
								i++;
							}while(i<NUM_HOSTS && blockip[i-1]);
						}
					} 
					else
					{	blockip[0]=inet_addr(argv[curarg]);
						blockip[1]=0;
						if(!blockip[0])
						{	fprintf(stderr,"Error: Invalid block address '%s'!\n",argv[curarg]);
							exittool(12);
						}
					}
					curarg++;
				}
				else
				{	fprintf(stderr,"Error: Block host not specified!\n");
					exittool(22);
				}
			}
			else if(!strncmp(p,"pe",2))
			{	if(++curarg <argc)
				{	if(inet_addr(argv[curarg])==INADDR_NONE)
					{	hoste=gethostbyname(argv[curarg]);
						if (!hoste) 
						{	fprintf(stderr,"Error: Unable to resolve peer host '%s'!\n",argv[curarg]);
							exittool(13);
						}
						else
						{	i=0;
							do
							{	if(hoste->h_addr_list[i])
									blockpeer[i]=*((unsigned long *)hoste->h_addr_list[i]);
								else
									blockpeer[i]=0;
								i++;
							}while(i<NUM_HOSTS && blockpeer[i-1]);
						}
					} 
					else
					{	blockpeer[0]=inet_addr(argv[curarg]);
						blockpeer[1]=0;
						if(!blockip[0])
						{	fprintf(stderr,"Error: Invalid peer address '%s'!\n",argv[curarg]);
							exittool(14);
						}
					}
					curarg++;
				}
				else
				{	fprintf(stderr,"Error: Peer IP not specified!\n");
					exittool(24);
				}
			}
			else if(!strncmp(p,"pr",2))
			{	if(++curarg <argc)
				{	if(atol(argv[curarg])>0)
						blockproto=atol(argv[curarg])&65535;
					else
					{	protoe=getprotobyname(argv[curarg]);
						if(!protoe)
						{	fprintf(stderr,"Error: Invalid protocol '%s'!\n",argv[curarg]);
							exittool(16);
						}
						blockproto=protoe->p_proto;
					}
					curarg++;
				}
				else
				{	fprintf(stderr,"Error: Protocol not specified!\n");
					exittool(26);
				}
			}
			else if(!strncmp(p,"po",2) || !strncmp(p,"dp",2) || !strncmp(p,"dst",3) || !strncmp(p,"dest",4))
			{	if(++curarg <argc)
				{	if(atol(argv[curarg])>0)
						blockport=atol(argv[curarg])&65535;
					else
					{	fprintf(stderr,"Error: Invalid port specified!\n");
						exittool(15);
					}
					curarg++;
				}
				else
				{	fprintf(stderr,"Error: Port not specified!\n");
					exittool(26);
				}
			}
			else if(!strncmp(p,"du",2))
			{	if(++curarg <argc)
				{	safecopy(str,argv[curarg]);
					blockduration=parseduration(str);
					curarg++;
				}
				else
				{	fprintf(stderr,"Error: Duration not specified!\n");
					exittool(27);
				}
			}
			else if(!strncmp(p,"sid",3) || !strncmp(p,"id",2))
			{	if(++curarg <argc)
				{	blocksid=atol(argv[curarg]);
					curarg++;
				}
				else
				{	fprintf(stderr,"Error: SID not specified!\n");
					exittool(28);
				}
			}
			else if(!strncmp(p,"di",2))
			{	if(++curarg <argc)
				{	if(!strcmp(argv[curarg],"in"))
						blockhow=FWSAM_HOW_IN;
					else if(!strcmp(argv[curarg],"out"))
						blockhow=FWSAM_HOW_OUT;
					else if(!strcmp(argv[curarg],"inout") || !strcmp(argv[curarg],"both") || !strcmp(argv[curarg],"full"))
						blockhow=FWSAM_HOW_INOUT;
					else if(!strcmp(argv[curarg],"this") || !strncmp(argv[curarg],"conn",4))
						blockhow=FWSAM_HOW_THIS;
					else
					{	fprintf(stderr,"Error: Invalid direction specified!\n");
						exittool(17);
					}
					curarg++;
				}
				else
				{	fprintf(stderr,"Error: Direction not specified!\n");
					exittool(29);
				}
			}
			else if(!strncmp(p,"log",3))
			{	if(++curarg <argc)
				{	snprintf(str,20,"%s1",argv[curarg]);
					i=atol(str);
					if(i>=1 && i<=41)
					{	blocklog=(i/10)&255;
						curarg++;
					}
					else
					{	fprintf(stderr,"Error: Invalid Log level specified!\n");
						exittool(18);
					}
				}
				else
				{	fprintf(stderr,"Error: Log level not specified!\n");
					exittool(30);
				}
			}
			else
			{	fprintf(stderr,"Error: Invalid option specified!\n");
				exittool(19);
			}
		}
		else
		{	if(!blockip[0])
			{	fprintf(stderr,"Error: Block IP address not specified!\n");
				exittool(40);
			}
			if(blockhow==FWSAM_HOW_THIS)
			{	if(!blockpeer[0])
				{	fprintf(stderr,"Error: Peer IP address not specified!\n");
					exittool(41);
				}
				if(!blockport)
				{	fprintf(stderr,"Error: Destination port not specified!\n");
					exittool(42);
				}
				if(!blockproto)
				{	fprintf(stderr,"Error: IP protocol not specified!\n");
					exittool(43);
				}
			}
			header();
			retval|=FWsamBlock(argv[curarg]);
			curarg++;
		}
	}
#ifdef WIN32
        WSACleanup();
#endif
	return retval;
}

#undef FWSAMDEBUG
#endif /* __SAMTOOL_C__ */
