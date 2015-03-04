/* $Id: ssp_cisco_nullroute.h,v 2.2 2008/04/26 19:53:21 fknobbe Exp $
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


#ifndef		__SSP_CISCO_NULLROUTE_H__
#define		__SSP_CISCO_NULLROUTE_H__


#define CNRPWLEN		50			/* Maximum password length */
#define CNRNETWAIT		20			/* Network timeout in sec */


typedef struct _cnrdata				/* List of Routers */
{	struct in_addr	ip;
	SOCKET 			routersocket;
	int				userlogin;
	int 			loggedin;
	char			*telnetpw;
	char			username[(CNRPWLEN+1)*2];
	char			enablepw[CNRPWLEN+1];
}	CISCONULLROUTEDATA;


void CiscoNullRouteParse(char *,char *,unsigned long,DATALIST *);
void CiscoNullRouteBlock(BLOCKINFO *,void *,unsigned long);

#endif /* __SSP_CISCO_NULLROUTE_H__ */

