/* $Id: ssp_forward.h,v 2.6 2009/09/21 23:54:37 fknobbe Exp $
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
 * ssp_forward.h 
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


#ifndef		__SSP_FORWARD_H__
#define		__SSP_FORWARD_H__


#define FWSAM_NETWAIT			500	/* 100th of a second. 5 sec timeout for network connections */
#define FWSAM_NETHOLD			6000	/* 100th of a second. 60 sec timeout for holding */



typedef struct _FWsamstation		/* structure of a mgmt station */
{	unsigned short 			myseqno;
	unsigned short 			stationseqno;
	unsigned char			mykeymod[4];
	unsigned char			fwkeymod[4];
	unsigned short			stationport;
	struct in_addr			stationip;
	struct sockaddr_in		localsocketaddr;
	struct sockaddr_in		stationsocketaddr;
	TWOFISH					*stationfish;
	SOCKET					stationsocket;		/* the socket of that station */
	char						initialkey[TwoFish_KEY_LENGTH+2];
	char						stationkey[TwoFish_KEY_LENGTH+2];
	time_t					lastcontact;
/*	time_t					sleepstart; */
	int						persistentsocket; /* Flag for permanent connection */
	unsigned char			packetversion;	/* The packet version the sensor uses. */
}	FWsamStation;


void FWsamNewStationKey(FWsamStation *,FWsamPacket *);
void FWsamCheckOut(FWsamStation *);
int FWsamCheckIn(FWsamStation *);
void ForwardParse(char *,char *,unsigned long ,DATALIST *);
void ForwardExit(DATALIST *);
void ForwardBlock(BLOCKINFO *,void *,unsigned long);

#endif /* __SSP_FORWARD_H__ */
