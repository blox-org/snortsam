/* $Id: ssp_pf.c,v 3.6 2009/11/27 01:39:40 fknobbe Exp $
 *
 * Copyright (c) 2003 Hector Paterno <apaterno@dsnsecurity.com>
 * Copyright (c) 2004-2008 Olaf Schreck <chakl@syscall.de>
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
 * ssp_pf.c
 *
 * Purpose:
 *
 * This SnortSam plugin is meant for dynamic (un)blocking on PF (OpenBSD) firewall,
 * SnortSam will expire the blocks itself since PF does not have
 * automatic time-out functionality.
 *
 * It Works on OpenBSD >= 3_3, and for FreeBSD >= 5.1.
 * For newer *BSD versions use the PF2 plugin.
 */

#ifndef USE_SSP_PF
#if defined(OpenBSD) || defined(FreeBSD) || defined(NetBSD)

#ifndef		__SSP_PF_C__
#define		__SSP_PF_C__

#include "snortsam.h"
#include "ssp_pf.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* By pf */
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <sys/param.h>
#include <errno.h>
/* End */

/* Defines should be done in ssp_pf.h */


/* Routine for opt parsing ( opt=value opt2=value2 etc. ) */
int parse_opts(char *line, opt_s *opt, char *sep, char *int_sep, int nopt)
{
   char *last;
   char *last2;
   char *pt;
   char *pt2;
   int fo=0;
   int di=0;
   
   if((line==NULL) || (opt==NULL) || (sep==NULL) || (int_sep==NULL))
     return -1;

   for(pt=strtok_r(line, sep, &last); pt; pt=strtok_r(NULL, sep, &last))
     {
	for(pt2=strtok_r(pt, int_sep, &last2), fo=0; pt2; pt2=strtok_r(NULL, int_sep, &last2))
	  {	     
	     if(fo==0)
	       {
		  for(; fo<nopt; fo++)
		    {
		      if (strncmp(opt[fo].name, pt2, MAX_OPT_NAME)==0)
			 {
			    fo++;
			    di++;
			    break;
			 }		       
		    }		  
	       }
	     else
	       {
		  if(di)
		    if(opt[--fo].vt>0)
		      strncpy(opt[fo].v.value_s, pt2, MAX_OPT_VALUE);
		    else
		      opt[fo].v.value_d=atoi(pt2);
		  fo=0;
		  di=0;
	       }	     
	  }
     }
   
   return;
}


/*
 * This routine parses the pf statements in the config file.
 * TODO: If the "auto" parameter is pased, initialize the main rule, anchor and rulesets/rules
 */
void
PFParse(char *val, char *file, unsigned long line, DATALIST * plugindatalist)
{
   PFDATA         *pfp = NULL;
   char           msg[STRBUFSIZE + 2];
   opt_s          options[5]={	
	{"auto",   0,  0},
	{"log",    0,  0},
	{"eth",    "", 1},
	{"anchor", "", 1},
	{"table",  "", 1}
   };

   /* used for auto=1 */
   int pfdev;   
   struct pfioc_rule rule;
   struct pfioc_pooladdr paddr;
   struct pfioc_table tablemain;
   struct pfr_table table;
   
   
#ifdef FWSAMDEBUG
   printf("Debug: [pf] Plugin Parsing...\n");
#endif
   
   if (*val)
     {
	if(parse_opts(val, options, " \t", "=", (sizeof(options)/sizeof(opt_s)))<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: [%s: %lu] invalid PF parameters !. PF Plugin disabled.", file, line);
	     logmessage(1, msg, "pf", 0);
	     plugindatalist->data=NULL;			
	     return;
	  }

	pfp = safemalloc(sizeof(PFDATA), "PFParse", "pfp");
	bzero(pfp, sizeof(PFDATA));
	plugindatalist->data = pfp;

	/* Check Anchor */
	if(strlen(options[PF_OPT_ANCHOR].v.value_s)<1)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Info: [%s: %lu] PF anchor name not defined, using \"snortsam\"", file, line );
	     logmessage(1, msg, "pf", 0);
	     safecopy(pfp->anchorname, "snortsam");	/* save anchorname */		
	  }
	else
	  {
	     safecopy(pfp->anchorname, options[PF_OPT_ANCHOR].v.value_s);	/* save anchorname */		
	  }
	
	/* define the table (fixed cannot changed) */
	safecopy(pfp->tablename, "block");	/* save tablename */		

	   			       /* Check eth */
	if(strlen(options[PF_OPT_ETH].v.value_s)<1)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Warning: [%s: %lu] PF ethernet name not defined, the IPs will be blocked on all interfaces !", file, line);
	     logmessage(1, msg, "pf", 0);
	  }
	else
	  {
	     safecopy(pfp->iface, options[PF_OPT_ETH].v.value_s);	/* save eth */
	  }

	/* Save the log option */
	pfp->logopt = options[PF_OPT_LOG].v.value_d;
	
     }else
     {
	snprintf(msg, sizeof(msg) - 1, "Error: [%s: %lu] PF defined without parameters! PF plugin disabled.", file, line);
	logmessage(1, msg, "pf", 0);
	free(pfp);
	plugindatalist->data=NULL;
	return;
     }
   
   if(options[PF_OPT_AUTO].v.value_d)	       /* Create the anchor call rules, create the anchor, rulesets and tables */
     {
        if ((pfdev = open(PFDEV, PFPERM)) == -1) 
	  {		     
	     snprintf(msg, sizeof(msg) - 1, "Error: Can't open %s device (auto=1), %s. PF plugin disabled.", PFDEV, strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;
	  }
	
	/* Create the anchor call rule in main */
	bzero(&rule, sizeof(struct pfioc_rule));
	strncpy(rule.rule.ifname, pfp->iface, IFNAMSIZ);
	strncpy(rule.anchor_call, pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);

	rule.action = PF_CHANGE_GET_TICKET;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 1 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	if(ioctl(pfdev, DIOCBEGINADDRS, &paddr)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCBEGINADDRS 2 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	rule.pool_ticket = paddr.ticket;
	
	rule.action = PF_CHANGE_ADD_HEAD;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 3 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	/* Create the Ruleset IN With It rule and table in the anchor */
	bzero(&tablemain, sizeof(struct pfioc_table));
	bzero(&table, sizeof(struct pfr_table));

 	 /* The table */
	strncpy(&(table.pfrt_anchor[0]), pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	strncpy(&(table.pfrt_name[0]), "blockin", PF_TABLE_NAME_SIZE-1);
	table.pfrt_flags = PFR_TFLAG_PERSIST;	
	tablemain.pfrio_buffer = &table;
	tablemain.pfrio_size = 1;
	tablemain.pfrio_esize = sizeof(table);
	
	if(ioctl(pfdev, DIOCRADDTABLES, &tablemain)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCRADDTABLES (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }
	 /* The rule (block in <logopt> from <tablename> to any */	
	bzero(&rule, sizeof(struct pfioc_rule));
	strncpy(&(table.pfrt_anchor[0]), pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	strncpy(rule.anchor, pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	rule.rule.action=PF_DROP;
	rule.rule.direction=PF_IN;
	rule.rule.quick=1;
	rule.rule.log=pfp->logopt;	
	rule.rule.src.addr.type = PF_ADDR_TABLE;

	strncpy(rule.rule.src.addr.v.tblname, "blockin", PF_TABLE_NAME_SIZE-1);	
	
	rule.action = PF_CHANGE_GET_TICKET;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 4 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }
	
	if(ioctl(pfdev, DIOCBEGINADDRS, &paddr)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCBEGINADDRS (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	rule.pool_ticket = paddr.ticket;
	
	rule.action = PF_CHANGE_ADD_HEAD;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 5 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }
	
	/* Create the Ruleset OUT With It rule and table in the anchor */
	bzero(&tablemain, sizeof(struct pfioc_table));
	bzero(&table, sizeof(struct pfr_table));

 	 /* The table */
	strncpy(&(table.pfrt_anchor[0]), pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	strncpy(&(table.pfrt_name[0]), "blockout", PF_TABLE_NAME_SIZE-1);
	table.pfrt_flags = PFR_TFLAG_PERSIST;	
	tablemain.pfrio_buffer = &table;
	tablemain.pfrio_size = 1;
	tablemain.pfrio_esize = sizeof(table);
	
	if(ioctl(pfdev, DIOCRADDTABLES, &tablemain)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCRADDTABLES (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }
	 /* The rule (block out <logopt> from any to <tablename>*/	
	bzero(&rule, sizeof(struct pfioc_rule));
	strncpy(&(table.pfrt_anchor[0]), pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	strncpy(rule.anchor, pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	rule.rule.action=PF_DROP;
	rule.rule.direction=PF_OUT;
	rule.rule.quick=1;
	rule.rule.log=pfp->logopt;	
	rule.rule.dst.addr.type = PF_ADDR_TABLE;

	strncpy(rule.rule.dst.addr.v.tblname, "blockout", PF_TABLE_NAME_SIZE-1);	
	  
	rule.action = PF_CHANGE_GET_TICKET;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 6 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	if(ioctl(pfdev, DIOCBEGINADDRS, &paddr)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCBEGINADDRS (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	rule.pool_ticket = paddr.ticket;
	
	rule.action = PF_CHANGE_ADD_HEAD;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 7 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }
	
	/* Create the Ruleset INOUT With It rule and table in the anchor */
	bzero(&tablemain, sizeof(struct pfioc_table));
	bzero(&table, sizeof(struct pfr_table));

 	 /* The table */
	strncpy(&(table.pfrt_anchor[0]), pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	strncpy(&(table.pfrt_name[0]), "blockinout", PF_TABLE_NAME_SIZE-1);
	table.pfrt_flags = PFR_TFLAG_PERSIST;	
	tablemain.pfrio_buffer = &table;
	tablemain.pfrio_size = 1;
	tablemain.pfrio_esize = sizeof(table);
	
	if(ioctl(pfdev, DIOCRADDTABLES, &tablemain)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCRADDTABLES (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }
	 /* The rules (block in <logopt> from <tablename> to any, and, block out <logopt> from any to <tablename>*/	
	  /* The IN */
	bzero(&rule, sizeof(struct pfioc_rule));
	strncpy(&(table.pfrt_anchor[0]), pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	strncpy(rule.anchor, pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	rule.rule.action=PF_DROP;
	rule.rule.direction=PF_IN;
	rule.rule.quick=1;
	rule.rule.log=pfp->logopt;	
	rule.rule.src.addr.type = PF_ADDR_TABLE;

	strncpy(rule.rule.src.addr.v.tblname, "blockinout", PF_TABLE_NAME_SIZE-1);	
	  
	rule.action = PF_CHANGE_GET_TICKET;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 8 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	if(ioctl(pfdev, DIOCBEGINADDRS, &paddr)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCBEGINADDRS (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	rule.pool_ticket = paddr.ticket;
	
	rule.action = PF_CHANGE_ADD_HEAD;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 9 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }
	
	  /* The OUT */
	bzero(&rule, sizeof(struct pfioc_rule));
	strncpy(&(table.pfrt_anchor[0]), pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	strncpy(rule.anchor, pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
	rule.rule.action=PF_DROP;
	rule.rule.direction=PF_OUT;
	rule.rule.quick=1;
	rule.rule.log=pfp->logopt;	
	rule.rule.dst.addr.type = PF_ADDR_TABLE;

	strncpy(rule.rule.dst.addr.v.tblname, "blockinout", PF_TABLE_NAME_SIZE-1);	
	  
	rule.action = PF_CHANGE_GET_TICKET;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 10 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	if(ioctl(pfdev, DIOCBEGINADDRS, &paddr)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCBEGINADDRS (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	rule.pool_ticket = paddr.ticket;
	
	rule.action = PF_CHANGE_ADD_HEAD;
	if(ioctl(pfdev, DIOCCHANGERULE, &rule)<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: DIOCCHANGERULE 11 (auto=1) : %s. PF plugin disabled.", strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     free(pfp);
	     plugindatalist->data=NULL;	     
	     return;	     
	  }

	
	/* Start PF */

	if(ioctl(pfdev, DIOCSTART, 0)<0)
	  {
	     if(errno==EEXIST)
	       {
		  snprintf(msg, sizeof(msg) - 1, "Info: PF Already Enabled (auto=1).");
		  logmessage(1, msg, "pf", 0);		  
	       }
	     else
	       {		  
		  snprintf(msg, sizeof(msg) - 1, "Error: Can't start PF (auto=1) : %s. PF plugin disabled.", strerror(errno));
		  logmessage(1, msg, "pf", 0);
		  free(pfp);
		  plugindatalist->data=NULL;	     
		  return;
	       }
	     
	  }
	
	
	
     }				       /* auto=1 */
   
#ifdef FWSAMDEBUG
   printf("Debug: [pf] Adding PF: \n");
   printf("auto=%d\nlog=%d\neth=%s\n",options[PF_OPT_AUTO].v.value_d, pfp->logopt, pfp->iface);
   printf("anchor=%s\ntable=%s\n",pfp->anchorname, pfp->tablename);
#endif

}


/*
 * BLOCK/UNBLOCK Routine
 */
void
PFBlock(BLOCKINFO * bd, void * data,unsigned long qp)
{
   PFDATA *pfp;
   int    pfdev;
   struct pfioc_table table;
   struct pfr_addr pfr;
   char   msg[STRBUFSIZE + 2];
#ifdef FWSAMDEBUG
   pthread_t threadid=pthread_self();
#endif
   
   if(!data)
     return;
   
   pfp=(PFDATA *)data;
   
#ifdef FWSAMDEBUG
   printf("Debug: [pf][%lx] Plugin Blocking...\n", threadid);
#endif
   
   if((pfdev=open(PFDEV, PFPERM))==-1)
     {
	snprintf(msg, sizeof(msg) - 1, "Error: Can't open %d device, %s", PFDEV, strerror(errno));
	logmessage(1, msg, "pf", 0);
	return;
     }
   
   
   bzero(&table, sizeof(struct pfioc_table));
   bzero(&pfr, sizeof(struct pfr_addr));
   pfr.pfra_af = AF_INET;
   pfr.pfra_net = 32;
   table.pfrio_buffer = &pfr;
   table.pfrio_size = 1;
   table.pfrio_esize = sizeof(pfr);
   strncpy(table.pfrio_table.pfrt_anchor, pfp->anchorname, PF_ANCHOR_NAME_SIZE-1);
   switch(bd->mode & FWSAM_HOW)
     {	
      case FWSAM_HOW_THIS:
	strncpy(table.pfrio_table.pfrt_name, "blockinout", PF_TABLE_NAME_SIZE - 1);
	break;
      case FWSAM_HOW_IN:
	strncpy(table.pfrio_table.pfrt_name, "blockin", PF_TABLE_NAME_SIZE - 1);
	break;
      case FWSAM_HOW_OUT:
	strncpy(table.pfrio_table.pfrt_name, "blockout", PF_TABLE_NAME_SIZE - 1);
	break;
      case FWSAM_HOW_INOUT:
	strncpy(table.pfrio_table.pfrt_name, "blockinout", PF_TABLE_NAME_SIZE - 1);
	break;
     }
   
   
   /* BLOCK */
   if (bd->block)
     {
	snprintf(msg, sizeof(msg) - 1, "Info: Blocking ip %s", inettoa(bd->blockip));
	logmessage(3, msg, "pf", 0);
	switch(bd->mode & FWSAM_HOW)
	  {
	     
	   case FWSAM_HOW_THIS:	       /* We Need a rule for this */
	     /* No yet, because the need to track the rule number (rn) to delete it */
	     /* Handled as HOW_INOUT */
	     pfr.pfra_u._pfra_ip4addr.s_addr = (u_int32_t) bd->blockip;
	     break;
	     
	   case FWSAM_HOW_IN:     /* ruleset : IN */
	     pfr.pfra_u._pfra_ip4addr.s_addr = (u_int32_t) bd->blockip;
	     break;
	     
	   case FWSAM_HOW_OUT:    /* ruleset : OUT */
	     pfr.pfra_u._pfra_ip4addr.s_addr = (u_int32_t) bd->blockip;
	     break;
	     
	   case FWSAM_HOW_INOUT:  /* ruleset : INOUT */
	     pfr.pfra_u._pfra_ip4addr.s_addr = (u_int32_t) bd->blockip;
	     break;
	     
	  }
	if(ioctl(pfdev, DIOCRADDADDRS, &table) < 0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: Can't Block ip %s (%s)", inettoa(bd->blockip), strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     return;	       /* TODO: Should I return a negativa value ?, what if It Fails ? It will try to unblock it lather ? */
	  }		
     }				       /* BLOCK */
   else   /* UNBLOCK */
     {
	snprintf(msg, sizeof(msg) - 1, "Info: Unblocking ip %s", inettoa(bd->blockip));
	logmessage(3, msg, "pf", 0);

	
	switch(bd->mode & FWSAM_HOW)
	  {
	     
	   case FWSAM_HOW_THIS:	       /* We Need a rule for this */
	     			       /* Handled as INOUT */
	     pfr.pfra_u._pfra_ip4addr.s_addr = (u_int32_t) bd->blockip;
	     break;
	     
	   case FWSAM_HOW_IN:	       /* Uses the table */
	     pfr.pfra_u._pfra_ip4addr.s_addr = (u_int32_t) bd->blockip;
	     break;
	     
	   case FWSAM_HOW_OUT:
	     pfr.pfra_u._pfra_ip4addr.s_addr = (u_int32_t) bd->blockip;
	     break;
	     
	   case FWSAM_HOW_INOUT:
	     pfr.pfra_u._pfra_ip4addr.s_addr = (u_int32_t) bd->blockip;
	     break;
	  
	  }
	if(ioctl(pfdev, DIOCRDELADDRS, &table) < 0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: Can't Unblock ip %s (%s)", inettoa(bd->blockip), strerror(errno));
	     logmessage(1, msg, "pf", 0);
	     return;
	  }	
     }				       /* UNBLOCK */
   
   close(pfdev);
   return;
}				       /* PFBLOCK */

#endif				/* __SSP_PF_C__ */

#endif                         /* OpenBSD || FreeBSD || NetBSD */
#endif /* USE_SSP_PF */

