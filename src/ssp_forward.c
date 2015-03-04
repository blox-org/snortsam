/* $Id: ssp_forward.c,v 2.8 2009/11/27 01:39:40 fknobbe Exp $
 *
 *
 * Copyright (c) 2005-2009 Frank Knobbe <frank@knobbe.us>
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
 * ssp_forward.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin send a blocking request to another Snortsam station.
 * White-listing and other local configurations (i.e. override, repetitive
 * block checking, rollback, etc) are applied before the request is forwarded.
 * 
 * In a future, a "passthrough" plugin will use the raw request from Snort in
 * its unprocessed fashion and pass that on. This will require some protocol
 * changes whereas this forward plugin does not.
 *
 */


#ifndef		__SSP_FORWARD_C__
#define		__SSP_FORWARD_C__


#include "snortsam.h"
#include "ssp_forward.h"


extern unsigned int disablepersistentconnections;
extern BLOCKQUEUE BlockQueue[];

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


/*  FWsamCheckOut will be called when this Snortsam exists. It de-registeres this station 
 *  from the list of sensors that the remote SnortSam agent keeps. 
*/
void FWsamCheckOut(FWsamStation *station)
{	FWsamPacket sampacket;
	int i,len;
	char *encbuf,*decbuf,msg[STRBUFSIZE+2];


	if(!station->persistentsocket)
	{	station->stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
		if(station->stationsocket==INVALID_SOCKET)
		{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckOut] Couldn't create socket!");
			logmessage(1,msg,"forward",station->stationip.s_addr);
			return;
		}
		if(bind(station->stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
		{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckOut] Couldn't bind socket!");
			logmessage(1,msg,"forward",station->stationip.s_addr);
			return;
		}
		/* let's connect to the agent */
		i=!connect(station->stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr));
	}
	else
		i=TRUE;
		
	if(i)
	{	snprintf(msg,sizeof(msg)-1,"Info: [Forward-CheckOut] Connected to host %s for Check-Out.",inet_ntoa(station->stationip));
		logmessage(3,msg,"forward",station->stationip.s_addr);
		
		/* now build the packet */
		station->myseqno+=station->stationseqno; /* increase my seqno */
		sampacket.endiancheck=1;
		sampacket.snortseqno[0]=(char)station->myseqno;
		sampacket.snortseqno[1]=(char)(station->myseqno>>8);
		sampacket.fwseqno[0]=(char)station->stationseqno; /* fill station seqno */
		sampacket.fwseqno[1]=(char)(station->stationseqno>>8);
		sampacket.status=FWSAM_STATUS_CHECKOUT;  /* checking out... */
		sampacket.version=station->packetversion;

#ifdef FWSAMDEBUG
			printf("Debug: [Forward-CheckOut] Sending CHECKOUT\n");
			printf("Debug: [Forward-CheckOut] Snort SeqNo:  %x\n",station->myseqno);
			printf("Debug: [Forward-CheckOut] Mgmt SeqNo :  %x\n",station->stationseqno);
			printf("Debug: [Forward-CheckOut] Status     :  %i\n",sampacket.status);
			printf("Debug: [Forward-CheckOut] Version    :  %i\n",sampacket.version);
#endif

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
					snprintf(msg,sizeof(msg)-1,"Info: [Forward-CheckOut] Had to use initial key!");
					logmessage(3,msg,"forward",station->stationip.s_addr);
				}
				if(len==sizeof(FWsamPacket)) /* valid decryption */
				{	if(sampacket.version!=station->packetversion) /* but don't really care since we are on the way out */
					{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckOut] Protocol version error!");
						logmessage(1,msg,"forward",station->stationip.s_addr);
					}	
				}
				else
				{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckOut] Password mismatch!");
					logmessage(1,msg,"forward",station->stationip.s_addr);
				}
			}
		}
		free(encbuf); /* release TwoFishAlloc'ed buffer */
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckOut] Could not connect to host %s for CheckOut. What the hell, we're quitting anyway!",inet_ntoa(station->stationip));
		logmessage(1,msg,"forward",station->stationip.s_addr);
	}
	closesocket(station->stationsocket);
	station->persistentsocket=FALSE;
}


/*  This routine registers this Snortsam with the remote SnortSam.
 *  It will also change the encryption key based on some variables.
*/
int FWsamCheckIn(FWsamStation *station)
{	int i,len,stationok=FALSE,again;
	FWsamPacket sampacket;
	char *encbuf,*decbuf,msg[STRBUFSIZE+2];


	do
	{	again=FALSE;
		/* create a socket for the station */
		station->stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
		if(station->stationsocket==INVALID_SOCKET)
		{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckIn] Couldn't create socket!");
			logmessage(1,msg,"forward",station->stationip.s_addr);
			return FALSE;
		}
		if(bind(station->stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
		{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckIn] Couldn't bind socket!");
			logmessage(1,msg,"forward",station->stationip.s_addr);
			return FALSE;
		}

		i=TRUE;
		/* let's connect to the agent */
		if(connect(station->stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr)))
		{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckIn] Could not connect to %s! Will try later.",inet_ntoa(station->stationip));
			logmessage(1,msg,"forward",station->stationip.s_addr);
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Info: [Forward-CheckIn] Connected to host %s for Check-In.",inet_ntoa(station->stationip));
			logmessage(3,msg,"forward",station->stationip.s_addr);

			/* now build the packet */
			sampacket.endiancheck=1;
			sampacket.snortseqno[0]=(char)station->myseqno; /* fill my sequence number number */
			sampacket.snortseqno[1]=(char)(station->myseqno>>8); /* fill my sequence number number */
			sampacket.status=FWSAM_STATUS_CHECKIN; /* let's check in */
			sampacket.version=station->packetversion; /* set the packet version */
			memcpy(sampacket.duration,station->mykeymod,4);  /* we'll send SnortSam our key modifier in the duration slot */
												   /* (the checkin packet is just the plain initial key) */
#ifdef FWSAMDEBUG
				printf("Debug: [Forward-CheckIn] Sending CHECKIN\n");
				printf("Debug: [Forward-CheckIn] Snort SeqNo:  %x\n",station->myseqno);
				printf("Debug: [Forward-CheckIn] Mode       :  %i\n",sampacket.status);
				printf("Debug: [Forward-CheckIn] Version    :  %i\n",sampacket.version);
#endif

			encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station->stationfish); /* get buffer for encryption */
			len=TwoFishEncrypt((char *)&sampacket,(char **)&encbuf,sizeof(FWsamPacket),FALSE,station->stationfish); /* encrypt with initial key */
			if(send(station->stationsocket,encbuf,len,0)!=len) /* weird...could not send */
			{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckIn] Could not send to host %s!",inet_ntoa(station->stationip));
				logmessage(1,msg,"forward",station->stationip.s_addr);
			}
			else
			{	i=FWSAM_NETWAIT;
				ioctlsocket(station->stationsocket,FIONBIO,&i);	/* set non blocking and wait for  */
				while(i-- >1)
				{	waitms(10); /* wait a maximum of 3 secs for response */
					if(recv(station->stationsocket,encbuf,len,0)==len)
						i=0;
				}
				if(!i) /* time up? */
				{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckIn] Did not receive response from host %s!",inet_ntoa(station->stationip));
					logmessage(1,msg,"forward",station->stationip.s_addr);
				}	
				else
				{	decbuf=(char *)&sampacket; /* got status packet */
					len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try to decrypt with initial key */
					if(len==sizeof(FWsamPacket)) /* valid decryption */
					{
#ifdef FWSAMDEBUG
							printf("Debug: [Forward-CheckIn] Received %s\n",sampacket.status==FWSAM_STATUS_OK?"OK":
																	   sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
																	   sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
																	   sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
							printf("Debug: [Forward-CheckIn] Snort SeqNo:  %x\n",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
							printf("Debug: [Forward-CheckIn] Mgmt SeqNo :  %x\n",sampacket.fwseqno[0]|(sampacket.fwseqno[1]<<8));
							printf("Debug: [Forward-CheckIn] Status     :  %i\n",sampacket.status);
							printf("Debug: [Forward-CheckIn] Version    :  %i\n",sampacket.version);
#endif

						if(sampacket.version==FWSAM_PACKETVERSION_PERSISTENT_CONN || sampacket.version==FWSAM_PACKETVERSION) /* master speaks my language */
						{	if(sampacket.status==FWSAM_STATUS_OK || sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC) 
							{	station->stationseqno=sampacket.fwseqno[0]|(sampacket.fwseqno[1]<<8); /* get stations seqno */
								station->lastcontact=(unsigned long)time(NULL);
								stationok=TRUE;
								
								if(sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)	/* generate new keys */
								{	memcpy(station->fwkeymod,sampacket.duration,4); /* note the key modifier */
									FWsamNewStationKey(station,&sampacket); /* and generate new TwoFish keys (with key modifiers) */
#ifdef FWSAMDEBUG
										printf("Debug: [Forward-CheckIn] Generated new encryption key...\n");
#endif
								}
								if(station->persistentsocket && sampacket.version==FWSAM_PACKETVERSION)
								{	snprintf(msg,sizeof(msg)-1,"Info: [Forward-CheckIn] Host %s doesn't support packet version %i for persistent connections. Silently adapting version %i.",inet_ntoa(station->stationip),FWSAM_PACKETVERSION_PERSISTENT_CONN,FWSAM_PACKETVERSION);
									logmessage(3,msg,"forward",station->stationip.s_addr);									
									station->persistentsocket=FALSE;
									station->packetversion=FWSAM_PACKETVERSION;
								}
							}
							else if(sampacket.status==FWSAM_STATUS_ERROR && sampacket.version==FWSAM_PACKETVERSION) 
							{	if(station->persistentsocket)
								{	snprintf(msg,sizeof(msg)-1,"Info: [Forward-CheckIn] Host %s doesn't support packet version %i for persistent connections. Trying packet version %i.",inet_ntoa(station->stationip),FWSAM_PACKETVERSION_PERSISTENT_CONN,FWSAM_PACKETVERSION);
									logmessage(3,msg,"forward",station->stationip.s_addr);									
									station->persistentsocket=FALSE;
									station->packetversion=FWSAM_PACKETVERSION;
									again=TRUE;
								}
								else
								{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckIn] Protocol version mismatch! Ignoring host %s!",inet_ntoa(station->stationip));
									logmessage(1,msg,"forward",station->stationip.s_addr);
								}
							}
							else /* weird, got a strange status back */
							{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckIn] Funky handshake error! Ignoring host %s!",inet_ntoa(station->stationip));
								logmessage(1,msg,"forward",station->stationip.s_addr);
							}
						}
						else /* packet version does not match */
						{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckIn] Protocol version error! Ignoring host %s!",inet_ntoa(station->stationip));
							logmessage(1,msg,"forward",station->stationip.s_addr);
						}
					}
					else /* key does not match */
					{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-CheckIn] Password mismatch! Ignoring host %s!",inet_ntoa(station->stationip));
						logmessage(1,msg,"forward",station->stationip.s_addr);
					}
				}
			}
			free(encbuf); /* release TwoFishAlloc'ed buffer */
		}

		if((!stationok && station->persistentsocket) || !station->persistentsocket)
			closesocket(station->stationsocket);
	}while(again);
	return stationok;
}


/* This routine parses the fwsam statements in the config file.
 * They should all be firewall IP addresses.
*/
void ForwardParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	FWsamStation *station=NULL;
	char msg[STRBUFSIZE+2],*p,*samport,*sampass,*samhost;
	struct hostent *hoste;
	unsigned long samip;


#ifdef FWSAMDEBUG
	printf("Debug: [Forward-Parse] Plugin Parsing...\n");
#endif

	remspace(val);
	p=val;
	samhost=p;
	samport=NULL;
	sampass=NULL;
	while(*p && *p!=':' && *p!='/' && *p!=',') 
		p++;
	if(*p==':')
	{	*p++=0;
		if(*p)
			samport=p;
		while(*p && *p!='/' && *p!=',')
			p++;
	}
	if(*p=='/' || *p==',')
	{	*p++=0;
		if(*p)
			sampass=p;
	}
	samip=0;
	if(inet_addr(samhost)==INADDR_NONE)
	{	hoste=gethostbyname(samhost);
		if(!hoste)
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Unable to resolve host '%s', ignoring entry!",file,line,samhost);
			logmessage(1,msg,"forward",0);	
			return;
		}
		else
			samip=*(unsigned long *)hoste->h_addr;
	}
	else
	{	samip=inet_addr(samhost);
		if(!samip)
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid host address '%s', ignoring entry!",file,line,samhost);
			logmessage(1,msg,"forward",0);	
			return;
		}
	}
	
	station=safemalloc(sizeof(FWsamStation),"ForwardParse","station");	/* create new Snortsam object */
	plugindatalist->data=station;

	station->stationip.s_addr=samip;
	if(samport!=NULL && atoi(samport)>0)
		station->stationport=atoi(samport);
	else
		station->stationport=FWSAM_DEFAULTPORT;
	if(sampass!=NULL)
	{	strncpy(station->stationkey,sampass,TwoFish_KEY_LENGTH);
		station->stationkey[TwoFish_KEY_LENGTH]=0;
	}
	else
		station->stationkey[0]=0;

	safecopy(station->initialkey,station->stationkey);
	station->stationfish=TwoFishInit(station->stationkey);

	station->localsocketaddr.sin_port=htons(0);
	station->localsocketaddr.sin_addr.s_addr=0;
	station->localsocketaddr.sin_family=AF_INET;
	station->stationsocketaddr.sin_port=htons(station->stationport);
	station->stationsocketaddr.sin_addr=station->stationip;
	station->stationsocketaddr.sin_family=AF_INET;

	do
		station->myseqno=rand();
	while(station->myseqno<20 || station->myseqno>65500);
	station->mykeymod[0]=rand();
	station->mykeymod[1]=rand();
	station->mykeymod[2]=rand();
	station->mykeymod[3]=rand();
	station->stationseqno=0;

	if(disablepersistentconnections)
	{	station->persistentsocket=FALSE;
		station->packetversion=FWSAM_PACKETVERSION;
	}
	else
	{	station->persistentsocket=TRUE;
		station->packetversion=FWSAM_PACKETVERSION_PERSISTENT_CONN;
	}
	
#ifdef FWSAMDEBUG
	printf("Debug: [Forward-Parse] Check-in to Snortsam at IP %s:%u\n",inettoa(station->stationip.s_addr),station->stationport);
#endif

	if(!FWsamCheckIn(station))
	{	snprintf(msg,sizeof(msg)-1,"Warning: [%s: %lu] Could not register with host '%s'!",file,line,samhost);
		logmessage(1,msg,"forward",0);	
		closesocket(station->stationsocket);
/*		plugindatalist->data=NULL;
		free(station);
*/
	}
}

/* This routine checks out from the registered Snortsam agents on exit.
*/
void ForwardExit(DATALIST *plugindatalist)
{	FWsamStation *station;

	while(plugindatalist)			/* Free global pointer list and stations */
	{	station=(FWsamStation *)plugindatalist->data;
		if(station)
		{
#ifdef FWSAMDEBUG
		printf("Debug: [Forward-Exit] Check-out from Snortsam at IP %s:%u\n",inettoa(station->stationip.s_addr),station->stationport);
#endif
			if(station->stationip.s_addr)
				FWsamCheckOut(station); 			/* Send a Check-Out to SnortSam, */
			TwoFishDestroy(station->stationfish);	/* toss the fish, */
		} 
		plugindatalist=plugindatalist->next;
	}
}

/* This routine forwards the block/unblock request to another Snortsam agent.
*/
void ForwardBlock(BLOCKINFO *bd,void *datapointer,unsigned long qp)
{	char msg[STRBUFSIZE+1],*encbuf,*decbuf;
	int i,delete=FALSE,try=0,len,recvlen=0,reconnect=FALSE;
	FWsamPacket sampacket;
	FWsamStation *station;


#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif
#endif

	if(!datapointer)
		return;
		
	station=(FWsamStation *)datapointer;
	
	if(station->stationip.s_addr==BlockQueue[qp-1].originator)
		return;
	
#ifdef FWSAMDEBUG
	printf("Debug: [Forward-Block][%lx] Plugin Blocking...\n",(unsigned long)threadid);
#endif

	do
	{	if(!station->stationip.s_addr)	/* Check if station has been marked inactive */
			return;
		
		try++;
		if(!station->persistentsocket || reconnect || station->stationsocket==0)
		{	/* create a socket for the station */
			station->stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); 
			if(station->stationsocket==INVALID_SOCKET)
			{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Couldn't create socket!");
				logmessage(1,msg,"forward",station->stationip.s_addr);
				return;
			}
			if(bind(station->stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
			{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Couldn't bind socket!");
				logmessage(1,msg,"forward",station->stationip.s_addr);
				return;
			}
			/* let's connect to the agent */
			reconnect=FALSE;
#ifdef FWSAMDEBUG
			printf("Debug: [Forward-Block][%lx] Attempting to connect to host %s.\n",(unsigned long)threadid,inet_ntoa(station->stationip));
#endif
			if(connect(station->stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr)))
			{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Could not connect to %s! Will try later.",inet_ntoa(station->stationip));
				logmessage(1,msg,"forward",station->stationip.s_addr);
				i=FALSE;
				reconnect=TRUE;
				try=2;
			}
			else
				i=TRUE;
		}
		else
			i=TRUE;
			
		if(i)
		{	snprintf(msg,sizeof(msg)-1,"Info: [Forward-Block] Connected to host %s. %s IP %s.",inet_ntoa(station->stationip),bd->block?"Blocking":"Unblocking",inettoa(bd->blockip));
			logmessage(3,msg,"forward",station->stationip.s_addr);

			/* now build the packet */
			station->myseqno+=station->stationseqno; /* increase my seqno by adding agent seq no */
			sampacket.endiancheck=1;						/* This is an endian indicator for Snortsam */
			sampacket.snortseqno[0]=(char)station->myseqno;
			sampacket.snortseqno[1]=(char)(station->myseqno>>8);
			sampacket.fwseqno[0]=(char)station->stationseqno;/* fill station seqno */
			sampacket.fwseqno[1]=(char)(station->stationseqno>>8);	
			sampacket.status=bd->block?FWSAM_STATUS_BLOCK:FWSAM_STATUS_UNBLOCK;		/* set block action */
			sampacket.version=station->packetversion;			/* set packet version */
			sampacket.duration[0]=(char)bd->duration;		/* set duration */
			sampacket.duration[1]=(char)(bd->duration>>8);
			sampacket.duration[2]=(char)(bd->duration>>16);
			sampacket.duration[3]=(char)(bd->duration>>24);
			sampacket.fwmode=(bd->mode & (FWSAM_LOG|FWSAM_HOW))|FWSAM_WHO_SRC; /* set to block the source */
			sampacket.dstip[0]=(char)bd->peerip; /* destination IP */
			sampacket.dstip[1]=(char)(bd->peerip>>8);
			sampacket.dstip[2]=(char)(bd->peerip>>16);
			sampacket.dstip[3]=(char)(bd->peerip>>24);
			sampacket.srcip[0]=(char)bd->blockip;	/* source IP */
			sampacket.srcip[1]=(char)(bd->blockip>>8);
			sampacket.srcip[2]=(char)(bd->blockip>>16);
			sampacket.srcip[3]=(char)(bd->blockip>>24);
			sampacket.protocol[0]=(char)bd->proto;	/* protocol */
			sampacket.protocol[1]=(char)(bd->proto>>8);/* protocol */

			if(bd->proto==6 || bd->proto==17)
			{	sampacket.dstport[0]=(char)bd->port;
				sampacket.dstport[1]=(char)(bd->port>>8);
			} 
			else
				sampacket.dstport[0]=sampacket.dstport[1]=0;
			sampacket.srcport[0]=sampacket.srcport[1]=0;

			sampacket.sig_id[0]=(char)bd->sig_id;		/* set signature ID */
			sampacket.sig_id[1]=(char)(bd->sig_id>>8);
			sampacket.sig_id[2]=(char)(bd->sig_id>>16);
			sampacket.sig_id[3]=(char)(bd->sig_id>>24);

#ifdef FWSAMDEBUG
				printf("Debug: [Forward-Block][%lx] Sending %s\n",(unsigned long)threadid,bd->block?"BLOCK":"UNBLOCK");
				printf("Debug: [Forward-Block][%lx] Snort SeqNo:  %x\n",(unsigned long)threadid,station->myseqno);
				printf("Debug: [Forward-Block][%lx] Mgmt SeqNo :  %x\n",(unsigned long)threadid,station->stationseqno);
				printf("Debug: [Forward-Block][%lx] Status     :  %i\n",(unsigned long)threadid,sampacket.status);
				printf("Debug: [Forward-Block][%lx] Version    :  %i\n",(unsigned long)threadid,sampacket.version);
				printf("Debug: [Forward-Block][%lx] Mode       :  %i\n",(unsigned long)threadid,sampacket.fwmode);
				printf("Debug: [Forward-Block][%lx] Duration   :  %lu\n",(unsigned long)threadid,(unsigned long)bd->duration);
				printf("Debug: [Forward-Block][%lx] Protocol   :  %i\n",(unsigned long)threadid,bd->proto);
				printf("Debug: [Forward-Block][%lx] Src IP     :  %s\n",(unsigned long)threadid,inettoa(bd->blockip));
				printf("Debug: [Forward-Block][%lx] Src Port   :  %i\n",(unsigned long)threadid,0);
				printf("Debug: [Forward-Block][%lx] Dest IP    :  %s\n",(unsigned long)threadid,inettoa(bd->peerip));
				printf("Debug: [Forward-Block][%lx] Dest Port  :  %i\n",(unsigned long)threadid,bd->port);
				printf("Debug: [Forward-Block][%lx] Sig_ID     :  %lu\n",(unsigned long)threadid,bd->sig_id);
#endif

			encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station->stationfish); /* get the encryption buffer */
			len=TwoFishEncrypt((char *)&sampacket,(char **)&encbuf,sizeof(FWsamPacket),FALSE,station->stationfish); /* encrypt the packet with current key */

			if(send(station->stationsocket,encbuf,len,0)!=len) /* weird...could not send */
			{	if(station->persistentsocket)
				{	try--;
					reconnect=TRUE;
					snprintf(msg,sizeof(msg)-1,"Info: [Forward-Block] Lost connection to host %s. Will try to reconnect.",inet_ntoa(station->stationip));
					logmessage(3,msg,"forward",station->stationip.s_addr);
				}
				else
				{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Could not send to host %s!",inet_ntoa(station->stationip));
					logmessage(1,msg,"forward",station->stationip.s_addr);
				}
			}
			else
			{	i=FWSAM_NETWAIT;
				ioctlsocket(station->stationsocket,FIONBIO,&i);	/* set non blocking and wait for  */
				while(i>1)							/* the response packet	 */
				{	waitms(10); /* wait for response (default maximum 3 secs */
					recvlen=recv(station->stationsocket,encbuf,len,0);
					if(recvlen==len)
						i=0; /* if we received packet we set the counter to 0. */
					else		 /* by the time we check with if, it's already dec'ed to -1 */
					{	if(recvlen==0 || recvlen==1)
							i=1;
					}
					i--;
				}
				if(!i) /* if we timed out (i was 1, then dec'ed)... */
				{	
#ifdef WIN32
					if(recvlen==SOCKET_ERROR || recvlen==0)
					{	if(errno==WSAECONNRESET || errno==WSAECONNABORTED || recvlen==0)
#else
					if(recvlen==-1 || recvlen==0)
					{	if(errno==ECONNRESET || errno==EINTR || recvlen==0)
#endif
						{	snprintf(msg,sizeof(msg)-1,"Info: [Forward-Block] Persistent connection to %s got reset.",inettoa(station->stationip.s_addr));
							logmessage(3,msg,"snortsam",station->stationip.s_addr);
							try--;
							reconnect=TRUE;
						}
					}
					else
					{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Did not receive response from host %s!",inet_ntoa(station->stationip));
						logmessage(1,msg,"forward",station->stationip.s_addr);
					}
				}
				else /* got a packet */
				{	decbuf=(char *)&sampacket; /* get the pointer to the packet struct */
					len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try to decrypt the packet with current key */

					if(len!=sizeof(FWsamPacket)) /* invalid decryption */
					{	safecopy(station->stationkey,station->initialkey); /* try the intial key */
						TwoFishDestroy(station->stationfish);
						station->stationfish=TwoFishInit(station->stationkey); /* re-initialize the TwoFish with the intial key */
						len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try again to decrypt */
						snprintf(msg,sizeof(msg)-1,"Info: [Forward-Block] Had to use initial key!");
						logmessage(3,msg,"forward",station->stationip.s_addr);
					}
					if(len==sizeof(FWsamPacket)) /* valid decryption */
					{	
#ifdef FWSAMDEBUG
									printf("Debug: [Forward-Block][%lx] Received %s\n",(unsigned long)threadid,sampacket.status==FWSAM_STATUS_OK?"OK":
																			  sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
																		      sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
																		      sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
									printf("Debug: [Forward-Block][%lx] Snort SeqNo:  %x\n",(unsigned long)threadid,sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
									printf("Debug: [Forward-Block][%lx] Mgmt SeqNo :  %x\n",(unsigned long)threadid,station->stationseqno);
									printf("Debug: [Forward-Block][%lx] Status     :  %i\n",(unsigned long)threadid,sampacket.status);
									printf("Debug: [Forward-Block][%lx] Version    :  %i\n",(unsigned long)threadid,sampacket.version);
#endif
					
						if(sampacket.version==station->packetversion || (sampacket.version==FWSAM_PACKETVERSION && sampacket.status==FWSAM_STATUS_ERROR))/* master speaks my language */
						{	if(sampacket.status==FWSAM_STATUS_OK || sampacket.status==FWSAM_STATUS_NEWKEY 
							|| sampacket.status==FWSAM_STATUS_RESYNC || sampacket.status==FWSAM_STATUS_HOLD) 
							{	station->stationseqno=sampacket.fwseqno[0] | (sampacket.fwseqno[1]<<8); /* get stations seqno */
								station->lastcontact=(unsigned long)time(NULL); /* set the last contact time (not used yet) */
								if(sampacket.status==FWSAM_STATUS_HOLD)
								{	i=FWSAM_NETHOLD;			/* Stay on hold for a maximum of 60 secs (default) */
									ioctlsocket(station->stationsocket,FIONBIO,&i);	/* set non blocking and wait for  */
									while(i-- >1)							/* the response packet	 */
									{	waitms(10); /* wait for response  */
										if(recv(station->stationsocket,encbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,0)==sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE)
										  i=0; /* if we received packet we set the counter to 0. */
							 		}
									if(!i) /* id we timed out (i was one, then dec'ed)... */
									{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Did not receive response from host %s!",inet_ntoa(station->stationip));
										logmessage(1,msg,"forward",station->stationip.s_addr);
										sampacket.status=FWSAM_STATUS_ERROR;
									}
									else /* got a packet */
									{	decbuf=(char *)&sampacket; /* get the pointer to the packet struct */
										len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try to decrypt the packet with current key */

										if(len!=sizeof(FWsamPacket)) /* invalid decryption */
										{	safecopy(station->stationkey,station->initialkey); /* try the intial key */
											TwoFishDestroy(station->stationfish);
											station->stationfish=TwoFishInit(station->stationkey); /* re-initialize the TwoFish with the intial key */
											len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try again to decrypt */
											snprintf(msg,sizeof(msg)-1,"Warning: [Forward-Block] Had to use initial key again!");
											logmessage(3,msg,"forward",station->stationip.s_addr);					
										}
#ifdef FWSAMDEBUG
											printf("Debug: [Forward-Block][%lx] Received %s\n", (unsigned long)threadid,sampacket.status==FWSAM_STATUS_OK?"OK":
																					   sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
																					   sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
																					   sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
											printf("Debug: [Forward-Block][%lx] Snort SeqNo:  %x\n",(unsigned long)threadid,sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
											printf("Debug: [Forward-Block][%lx] Mgmt SeqNo :  %x\n",(unsigned long)threadid,station->stationseqno);
											printf("Debug: [Forward-Block][%lx] Status     :  %i\n",(unsigned long)threadid,sampacket.status);
											printf("Debug: [Forward-Block][%lx] Version    :  %i\n",(unsigned long)threadid,sampacket.version);
#endif
										if(len!=sizeof(FWsamPacket)) /* invalid decryption */
										{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Password mismatch! Ignoring host %s!",inet_ntoa(station->stationip));
											logmessage(1,msg,"forward",station->stationip.s_addr);
											delete=TRUE;
											sampacket.status=FWSAM_STATUS_ERROR;
										}
										else if(sampacket.version!=station->packetversion) /* invalid protocol version */
										{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Protocol version error! Ignoring host %s!",inet_ntoa(station->stationip));
											logmessage(1,msg,"forward",station->stationip.s_addr);
											delete=TRUE;
											sampacket.status=FWSAM_STATUS_ERROR;
										}
										else if(sampacket.status!=FWSAM_STATUS_OK && sampacket.status!=FWSAM_STATUS_NEWKEY && sampacket.status!=FWSAM_STATUS_RESYNC) 
										{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Funky handshake error! Ignoring host %s!",inet_ntoa(station->stationip));
											logmessage(1,msg,"forward",station->stationip.s_addr);
											delete=TRUE;
											sampacket.status=FWSAM_STATUS_ERROR;
										}
									}
								}
								if(sampacket.status==FWSAM_STATUS_RESYNC)  /* if station want's to resync... */
								{	safecopy(station->stationkey,station->initialkey); /* ...we use the intial key... */
									memcpy(station->fwkeymod,sampacket.duration,4);	 /* and note the random key modifier */
								}
								if(sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)	
								{	
									FWsamNewStationKey(station,&sampacket); /* generate new TwoFish keys */
#ifdef FWSAMDEBUG
										printf("Debug: [Forward-Block] Generated new encryption key...\n");
#endif
								}
								try=99;
							}
							else if(sampacket.status==FWSAM_STATUS_ERROR) /* if SnortSam reports an error on second try, */
							{	if(try==1)
								{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Error! Trying once more to CheckIn to host %s!",inet_ntoa(station->stationip));
									logmessage(1,msg,"forward",station->stationip.s_addr);
									if(station->persistentsocket)
										closesocket(station->stationsocket);
									if(!FWsamCheckIn(station))
										delete=TRUE;
								}
								else
								{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Could not renegotiate key! Ignoring host %s!",inet_ntoa(station->stationip));
									logmessage(1,msg,"forward",station->stationip.s_addr);
									delete=TRUE;
								}
							}
							else /* an unknown status means trouble... */
							{	if(try==1)
								{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Error! Trying once more to CheckIn to host %s!",inet_ntoa(station->stationip));
									logmessage(1,msg,"forward",station->stationip.s_addr);
									if(station->persistentsocket)
										closesocket(station->stationsocket);
									if(!FWsamCheckIn(station))
										delete=TRUE;
								}
								else
								{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Funky handshake error! Ignoring host %s!",inet_ntoa(station->stationip));
									logmessage(1,msg,"forward",station->stationip.s_addr);
									delete=TRUE;
								}
							}
						}
						else   /* if the SnortSam agent uses a different packet version, we have no choice but to ignore it. */
						{	if(try==1)
							{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Error! Trying once more to CheckIn to host %s!",inet_ntoa(station->stationip));
								logmessage(1,msg,"forward",station->stationip.s_addr);
								if(station->persistentsocket)
									closesocket(station->stationsocket);
								if(!FWsamCheckIn(station))
									delete=TRUE;
							}
							else
							{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Protocol version error! Ignoring host %s!",inet_ntoa(station->stationip));
								logmessage(1,msg,"forward",station->stationip.s_addr);
								delete=TRUE;
							}
						}
					}
					else /* if the intial key failed to decrypt as well, the keys are not configured the same, and we ignore that SnortSam station-> */
					{	if(try==1)
						{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Error! Trying once more to CheckIn to host %s!",inet_ntoa(station->stationip));
							logmessage(1,msg,"forward",station->stationip.s_addr);
							if(station->persistentsocket)
								closesocket(station->stationsocket);
							if(!FWsamCheckIn(station))
								delete=TRUE;
						}
						else
						{	snprintf(msg,sizeof(msg)-1,"Error: [Forward-Block] Password mismatch! Ignoring host %s!",inet_ntoa(station->stationip));
							logmessage(1,msg,"forward",station->stationip.s_addr);
							delete=TRUE;
						}
					}
				}
			}
			free(encbuf); /* release of the TwoFishAlloc'ed encryption buffer */
		}
		if(!station->persistentsocket || reconnect || delete)
		{	closesocket(station->stationsocket);
			station->stationsocket=0;
		}
		if(delete)
			station->stationip.s_addr=0;
	}while(try<2);
}

#endif /* __SSP_FORWARD_C__ */
