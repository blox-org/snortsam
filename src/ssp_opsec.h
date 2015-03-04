/* $Id: ssp_opsec.h,v 2.2 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2001-2008 Frank Knobbe <frank@knobbe.us>
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
 * ssp_opsec.h 
 * 
 * Purpose:  
 *
 * This SnortSam plugin makes use of the OPSEC libraries of the OPSEC SDK in 
 * order to  communicate with Firewall-1. This implementation makes the process
 * fully OPSEC compliant. 
 *
 *
 */

#ifdef ENABLE_OPSEC

#ifndef		__SSP_OPSEC_H__
#define		__SSP_OPSEC_H__

#include "opsec/include/opsec/sam.h"
#include "opsec/include/opsec/opsec.h"
#include "opsec/include/opsec/opsec_error.h"


/* This is just a list of OPSEC conf files,
 * so that more than one firewall can be processed.
*/
typedef struct _opsecdata
{	char	cfgfile[FILEBUFSIZE];
}   OPSECDATA;


static int fw_sam_client_session_creator(OpsecSession *);
static void fw_sam_client_session_deletor(OpsecSession *);
static int SessionEstablishedHandler(OpsecSession *);
static int AckEventHandler(OpsecSession *,int ,int ,int ,int ,char *,void *);
static int MonitorAckEventHandler(OpsecSession *,int ,int ,int ,char *,void *,opsec_table );
static void clean_env(OpsecEnv *,OpsecEntity *,OpsecEntity *);
void OPSEC_Parse(char *,char *,unsigned long ,DATALIST *);
void OPSEC_Block(BLOCKINFO *,void *,unsigned long);

#endif /* __SSP_OPSEC_H__ */
#endif
