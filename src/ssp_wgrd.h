/* $Id: ssp_wgrd.h,v 2.2 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2003-2008 Thomas Maier <Thomas.Maier@arcos.de>
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
 * ssp_wgrd.h 
 * 
 * Purpose:  
 *
 * see ssp_wgrd.c
 *
 */


#ifndef		__SSP_WGRD_H__
#define		__SSP_WGRD_H__

#define WGRD_STRLEN          23              /* Maximum password length */

typedef struct _wgrddata				/* List of WGRD firewalls */
{	struct in_addr	ip_addr;
	char command[FILEBUFSIZE];
	char passphrase[WGRD_STRLEN];
	char passphrasefile[FILEBUFSIZE];
}	WGRDDATA;


void WGExecParse(char *,char *,unsigned long,DATALIST *);
void WGRDParse(char *,char *,unsigned long,DATALIST *);
void WGRDBlock(BLOCKINFO *,void *,unsigned long);

#endif /* __SSP_WGRD_H__ */

