/* $Id: ssp_ipf.h,v 2.7 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2002-2008 Frank Knobbe <frank@knobbe.us>, Erik Sneep <erik@webflex.nl>
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
 * ssp_ipf.h 
 * 
 * Purpose:  
 *
 * This SnortSam plugin is for a IPFilter firewall,
 * SnortSam will expire the blocks itself since the IPFilter does not 
 * have automatic time-out functionality.
 *
 *
 */


#if !defined(WIN32) && !defined(Linux)

#ifndef		__SSP_IPF_H__
#define		__SSP_IPF_H__

#define		IPFLOGLEVEL	"local7.info"

typedef struct _ipfdata				/* List of IPF firewalls */
{	char iface[10];
	char loglv[20];
}	IPFDATA;


void IPFParse(char *,char *,unsigned long,DATALIST *);
void IPFBlock(BLOCKINFO *,void *,unsigned long);

#endif /* __SSP_IPF_H__ */
#endif /* WIN32 */

