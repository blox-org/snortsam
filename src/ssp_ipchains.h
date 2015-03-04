/* $Id: ssp_ipchains.h,v 2.5 2008/04/26 19:53:21 fknobbe Exp $
 *
 * Copyright (c) 2002-2008 Hector Paterno <apaterno@dsnsecurity.com>
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
 * ssp_ipchains.h 
 * 
 * Purpose:  
 *
 * This SnortSam plugin is for a ipchains (Linux) firewall,
 * SnortSam will expire the blocks itself since the ipchains does not 
 * have automatic time-out functionality.
 *
 *
 */


#ifdef Linux

#ifndef		__SSP_IPCHAINS_H__
#define		__SSP_IPCHAINS_H__

#include <net/if.h>

typedef struct _ipchdata				/* List of ipchains firewalls */
{	char iface[10];
	u_int8_t logopt;
}	IPCHDATA;



#define IP_FW_LABEL_INPUT       "input"
#define IP_FW_LABEL_OUTPUT      "output"
#define IP_FW_LABEL_BLOCK       "DENY"
#define IP_FW_LABEL_REJECT      "REJECT"

#define IP_FW_MAX_LABEL_LENGTH 8
typedef char ip_chainlabel[IP_FW_MAX_LABEL_LENGTH+1];

#define IP_FW_BASE_CTL          64
#define IP_FW_APPEND            (IP_FW_BASE_CTL)
#define IP_FW_DELETE            (IP_FW_BASE_CTL+3)

struct ip_fw
{
           struct in_addr fw_src, fw_dst;
           struct in_addr fw_smsk, fw_dmsk;
           u_int32_t fw_mark;
           u_int16_t fw_proto;
           u_int16_t fw_flg;
           u_int16_t fw_invflg;
           u_int16_t fw_spts[2];
           u_int16_t fw_dpts[2];
           u_int16_t fw_redirpt;
           u_int16_t fw_outputsize;
           char      fw_vianame[IFNAMSIZ];
           u_int8_t  fw_tosand, fw_tosxor;
}
;

struct ip_fwuser
{
           struct ip_fw ipfw;
           ip_chainlabel label;
}
;

struct ip_fwchange
{  
           struct ip_fwuser fwc_rule;
           ip_chainlabel fwc_label;
}
;



void IPCHParse(char *,char *,unsigned long,DATALIST *);
void IPCHBlock(BLOCKINFO *, void *,unsigned long qp);

#endif /* __SSP_IPCHAINS_H__ */
#endif /* LINUX */

