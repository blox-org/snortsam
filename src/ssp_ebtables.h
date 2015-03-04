/* $Id: ssp_ebtables.h,v 1.2 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2003-2008 Fabrizio Tivano <fabrizio@sad.it>,
 *                    Bruno Scatolin <ipsystems@uol.com.br>
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
 * ssp_ebtables.h 
 * 
 * Purpose:  
 *
 * This SnortSam plugin is for a ebtables firewall,
 * SnortSam will expire the blocks itself. 
 * 
 * The plugin for ebtables, created by Bruno, is based on the iptable plugin
 * created by Fabrizio.
 *
 *
 */


#ifdef Linux

#ifndef		__SSP_EBT_H__
#define		__SSP_EBT_H__

#define		EBTLOGLEVEL	"syslog.info"

typedef struct _ebtdata				/* List of EBTABLES firewalls */
{	char iface[10];
	char loglv[20];
}	EBTDATA;


void EBTParse(char *,char *,unsigned long,DATALIST *);
void EBTBlock(BLOCKINFO *,void *,unsigned long);

#endif /* __SSP_EBT_H__ */
#endif /* Linux */

