/* $Id: ssp_ipchains.c,v 2.8 2008/04/26 19:53:21 fknobbe Exp $
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
 * ssp_ipchains.c
 *
 * Purpose:
 *
 * This SnortSam plugin is meant for dynamic (un)blocking on ipchains (Linux) firewall,
 * SnortSam will expire the blocks itself since ipchains does not have
 * automatic time-out functionality.
 *
 * Todo:
 *
 * This is a basic plugin, I'v a lot of ideas to implement on ipchains.
 *
 */


#ifdef Linux

#ifndef		__SSP_IPCHAINS_C__
#define		__SSP_IPCHAINS_C__


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <errno.h>
#include "snortsam.h"
#include "ssp_ipchains.h"


static int sockfd = -1;


static int ipfwc_init()
{
   return ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) != -1);
}

static int do_setsockopt(int cmd, const void *data, int length)
{
   return setsockopt(sockfd, IPPROTO_IP, cmd, (char *)data, length) != -1;
}

/*
 * This routine parses the ipchains statements in the config file.
 */
void
IPCHParse(char *val, char *file, unsigned long line, DATALIST * plugindatalist)
{
	IPCHDATA         *ipchp = NULL;
	char           *p2, msg[STRBUFSIZE + 2];

#ifdef FWSAMDEBUG
	printf("Debug: [ipchains] Plugin Parsing...\n");
#endif

	if (*val) 
        {
		p2 = val;
		while (*p2 && !myisspace(*p2))
			p2++;
		if (*p2)
			*p2++ = 0;
		ipchp = safemalloc(sizeof(IPCHDATA), "IPCHParse", "ipchp");
		plugindatalist->data = ipchp;
		ipchp->logopt = 0;
		safecopy(ipchp->iface, val);	/* save interface */

		if (*p2) 	/* if we have a log option defined */
		{	while (*p2 && myisspace(*p2)) p2++;
			if (strcmp(p2, "log") == 0) 
			{	ipchp->logopt = 1;	
			}
		}

#ifdef FWSAMDEBUG
		printf("Debug: [ipchains] Adding IPCH: interface \"%s\", log \"%d\"\n", ipchp->iface, ipchp->logopt);
#endif

	} else 
	{	snprintf(msg, sizeof(msg) - 1, "Error: [%s: %lu] ipchains defined without parameters!", file, line);
		logmessage(1, msg, "ipchains", 0);
	}
	   
}


/*
 * This routine initiates the block.
 */
void IPCHBlock(BLOCKINFO *bd, void *data,unsigned long qp)
{

   IPCHDATA * ipchp;
   struct ip_fwchange newfw;
   char            msg[STRBUFSIZE + 2];
   int             who;
#ifdef FWSAMDEBUG
    pthread_t       threadid = pthread_self();
#endif

   if (!data)
     return;
   ipchp=(IPCHDATA *)data;

#ifdef FWSAMDEBUG
	printf("Debug: [ipchains][%lx] Plugin Blocking...\n", threadid);
#endif


   bzero(&newfw, sizeof(struct ip_fwchange));

   if(ipfwc_init()==-1)
     {
	snprintf(msg, sizeof(msg) - 1, "Error: Can't open RAW socket, %s", strerror(errno));
	logmessage(1, msg, "ipchains", 0);
	return;
     }

      newfw.fwc_rule.ipfw.fw_smsk.s_addr = 0xffffffff;
      memcpy(newfw.fwc_rule.label, IP_FW_LABEL_BLOCK, sizeof(newfw.fwc_rule.label));
      memcpy(newfw.fwc_rule.ipfw.fw_vianame, ipchp->iface, IFNAMSIZ-1);
      newfw.fwc_rule.ipfw.fw_tosand = 255;	 
      newfw.fwc_rule.ipfw.fw_spts[0] = 0; /* Default all */
      newfw.fwc_rule.ipfw.fw_spts[1] = 65535;
      newfw.fwc_rule.ipfw.fw_dpts[0] = 0;
      newfw.fwc_rule.ipfw.fw_dpts[1] = 65535;
      
      if(ipchp->logopt)
        newfw.fwc_rule.ipfw.fw_flg = 0x0001;
   
      /* Future Improvments via config file
       newfw.fwc_rule.ipfw.fw_mark =
       newfw.fwc_rule.ipfw.fw_flg = 
       newfw.fwc_rule.ipfw.fw_invflg =
       newfw.fwc_rule.ipfw.fw_redirpt =
       newfw.fwc_rule.ipfw.fw_outputsize =
       newfw.fwc_rule.ipfw.fw_tosxor =  */
   
   if (bd->block) { // Will block
      snprintf(msg, sizeof(msg) - 1, "Info: Blocking ip %s", inettoa(bd->blockip));
      logmessage(1, msg, "ipchains", 0);
         
      switch (bd->mode & FWSAM_HOW) {
       case FWSAM_HOW_THIS:
	 memcpy(newfw.fwc_label, IP_FW_LABEL_INPUT, sizeof(newfw.fwc_label));
	 newfw.fwc_rule.ipfw.fw_src.s_addr = (u_int32_t) bd->blockip;
	 newfw.fwc_rule.ipfw.fw_dst.s_addr = (u_int32_t) bd->peerip;
         newfw.fwc_rule.ipfw.fw_dmsk.s_addr = 0xffffffff;
	 newfw.fwc_rule.ipfw.fw_proto = bd->proto;
	 
	 if(bd->port)
	   {
	      newfw.fwc_rule.ipfw.fw_dpts[0] = bd->port;
	      newfw.fwc_rule.ipfw.fw_dpts[1] = bd->port;
	   }
	 
       break;
      
       default: ; /* IN Rule */
       case FWSAM_HOW_IN:	/* Incoming FROM host ( src ) */
	 memcpy(newfw.fwc_label, IP_FW_LABEL_INPUT, sizeof(newfw.fwc_label));	 
	 newfw.fwc_rule.ipfw.fw_src.s_addr = (u_int32_t) bd->blockip;
	 
       break;

       case FWSAM_HOW_OUT:	/* Outgoing TO host ( dst ) */
         memcpy(newfw.fwc_label, IP_FW_LABEL_OUTPUT, sizeof(newfw.fwc_label));
	 newfw.fwc_rule.ipfw.fw_dst.s_addr = (u_int32_t) bd->blockip;
	 newfw.fwc_rule.ipfw.fw_smsk.s_addr = 0x0;
         newfw.fwc_rule.ipfw.fw_dmsk.s_addr = 0xffffffff;
	 
       break;

       case FWSAM_HOW_INOUT:	/* Need 2 rules 1 for IN, 1 for OUT */
  
			/* Incoming FROM */
	 memcpy(newfw.fwc_label, IP_FW_LABEL_INPUT, sizeof(newfw.fwc_label));	 
	 newfw.fwc_rule.ipfw.fw_src.s_addr = (u_int32_t) bd->blockip;

	 if(do_setsockopt(IP_FW_APPEND, &newfw, sizeof(newfw))==-1)
	   {
	      snprintf(msg, sizeof(msg) - 1, "Error: Can't Block ip %s, %s", inettoa(bd->blockip), strerror(errno));
	      logmessage(1, msg, "ipchains", 0);
	      return;
	   }
	 
			/* Outgoing TO */
	 memcpy(newfw.fwc_label, IP_FW_LABEL_OUTPUT, sizeof(newfw.fwc_label));	 
	 newfw.fwc_rule.ipfw.fw_dst.s_addr = (u_int32_t) bd->blockip;
	 newfw.fwc_rule.ipfw.fw_dmsk.s_addr = 0xffffffff;
         newfw.fwc_rule.ipfw.fw_smsk.s_addr = 0x0;
	 
      break;
	 
      }
      
	 if(do_setsockopt(IP_FW_APPEND, &newfw, sizeof(newfw))==-1)
	   {
	      snprintf(msg, sizeof(msg) - 1, "Error: Can't Block ip %s, %s", inettoa(bd->blockip), strerror(errno));
	      logmessage(1, msg, "ipchains", 0);
	      return;
	   }	   

      
   }else{ /* Will unblock */
      snprintf(msg, sizeof(msg) - 1, "Info: UnBlocking ip %s", inettoa(bd->blockip));
      logmessage(1, msg, "ipchains", 0);
            
      switch (bd->mode & FWSAM_HOW) {
       case FWSAM_HOW_THIS:
	 memcpy(newfw.fwc_label, IP_FW_LABEL_INPUT, sizeof(newfw.fwc_label));
	 newfw.fwc_rule.ipfw.fw_src.s_addr = (u_int32_t) bd->blockip;
	 newfw.fwc_rule.ipfw.fw_dst.s_addr = (u_int32_t) bd->peerip;
         newfw.fwc_rule.ipfw.fw_dmsk.s_addr = 0xffffffff;
	 
	 if(bd->port)
	   {
	      newfw.fwc_rule.ipfw.fw_dpts[0] = bd->port;
	      newfw.fwc_rule.ipfw.fw_dpts[1] = bd->port;
	   }
	 
       break;
      
       default: ; /* IN Rule */
       case FWSAM_HOW_IN:	/* Incoming FROM host ( src ) */
	 memcpy(newfw.fwc_label, IP_FW_LABEL_INPUT, sizeof(newfw.fwc_label));	 
	 newfw.fwc_rule.ipfw.fw_src.s_addr = (u_int32_t) bd->blockip;
	 
       break;

       case FWSAM_HOW_OUT:	/* Outgoing TO host ( dst ) */
         memcpy(newfw.fwc_label, IP_FW_LABEL_OUTPUT, sizeof(newfw.fwc_label));
	 newfw.fwc_rule.ipfw.fw_dst.s_addr = (u_int32_t) bd->blockip;
	 newfw.fwc_rule.ipfw.fw_smsk.s_addr = 0x0;
         newfw.fwc_rule.ipfw.fw_dmsk.s_addr = 0xffffffff;
	 
       break;

       case FWSAM_HOW_INOUT:	/* Need 2 rules 1 for IN, 1 for OUT */
  
			/* Incoming FROM */
	 memcpy(newfw.fwc_label, IP_FW_LABEL_INPUT, sizeof(newfw.fwc_label));	 
	 newfw.fwc_rule.ipfw.fw_src.s_addr = (u_int32_t) bd->blockip;

	 if(do_setsockopt(IP_FW_DELETE, &newfw, sizeof(newfw))==-1)
	   {
	      snprintf(msg, sizeof(msg) - 1, "Error: Can't UnBlock ip %s, %s", inettoa(bd->blockip), strerror(errno));
	      logmessage(1, msg, "ipchains", 0);
	      return;
	   }
	 
			/* Outgoing TO */
	 memcpy(newfw.fwc_label, IP_FW_LABEL_OUTPUT, sizeof(newfw.fwc_label));	 
	 newfw.fwc_rule.ipfw.fw_dst.s_addr = (u_int32_t) bd->blockip;
	 newfw.fwc_rule.ipfw.fw_dmsk.s_addr = 0xffffffff;
         newfw.fwc_rule.ipfw.fw_smsk.s_addr = 0x0;
	 
      break;
	 
      }
      

	 if(do_setsockopt(IP_FW_DELETE, &newfw, sizeof(newfw))==-1)
	   {
	      snprintf(msg, sizeof(msg) - 1, "Error: Can't UnBlock ip %s, %s", inettoa(bd->blockip), strerror(errno));
	      logmessage(1, msg, "ipchains", 0);
	      return;
	   }	   
      
      
     }

	close(sockfd);

	return;
}

#endif				/* __SSP_IPCHAINS_C__ */
#endif /* LINUX */
