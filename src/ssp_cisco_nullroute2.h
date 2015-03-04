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
 *
 *
 */


#ifndef		__SSP_CISCO_NULLROUTE2_H__
#define		__SSP_CISCO_NULLROUTE2_H__


#define CNRPWLEN		50			/* Maximum password length */
#define CNRNETWAIT		20			/* Network timeout in sec */
#define RTAGVAL_LEN		10UL			/* Maximum length for route-tag */
#define RTAGVAL_MIN		1UL			/* Minimum value for route-tag */
#define RTAGVAL_MAX		4294967295UL		/* Maximum value for route-tag */


typedef struct _cnr2data				/* List of Routers */
{	struct in_addr	ip;
	SOCKET 			routersocket;
	int			userlogin;
	int 			loggedin;
	int			autoenable;
	char			username[CNRPWLEN+1];
	char			telnetpw[CNRPWLEN+1];
	char			enablepw[CNRPWLEN+1];
	char			routetag[RTAGVAL_LEN+1];
}	CISCONULLROUTE2DATA;


void CiscoNullRoute2Parse(char *,char *,unsigned long,DATALIST *);
void CiscoNullRoute2Block(BLOCKINFO *,void *,unsigned long);

#endif /* __SSP_CISCO_NULLROUTE2_H__ */

