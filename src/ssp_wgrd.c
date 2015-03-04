/* $Id: ssp_wgrd.c,v 2.7 2009/11/08 22:35:58 fknobbe Exp $
 *
 *
 * Copyright (c) 2003-2008 Thomas Maier <thomas.maier@arcos.de>
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
 * ssp_wgrd.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin is for Watchguard firewalls,
 *
 * To use this plugin you will have to get a piece of software from 
 * watchguard called fbidsmate, which is a commandline tool which we 
 * use to initiate the block, since the communication to the firebox
 * is proprietary and watchguard do not want to let us know how it 
 * works.
 * 
 * SnortSam can not expire the blocks since the fbidsmate of Watchguard
 * has no unblock functionality. The duration of the block can be defined 
 * in the Policy Manager of the watchguard firebox under 
 * Setup/Blocked Sites/Duration for Auto-Blocked Sites.
 *
 */


#ifndef		__SSP_WGRD_C__
#define		__SSP_WGRD_C__


#include "snortsam.h"
#include "ssp_wgrd.h"


#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* This routine parses the wgrd statements in the config file.
*/
void WGRDParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist) {
  WGRDDATA *wgrdp=NULL;
  char *p2, msg[STRBUFSIZE+2];
  struct in_addr nsip;
#ifdef FWSAMDEBUG
  printf("Debug: [wgrd] Plugin Parsing...\n");
#endif
  if(*val) {
    char *cmd;
    p2=val;
    while(*p2 && !myisspace(*p2))   /* parse command */
      p2++;
    if(*p2)
      *p2++ =0;
    cmd=val;
    val=p2;
    while(*val && myisspace(*val))          /* skip spaces */
      val++;
    p2=val;
    while(*p2 && !myisspace(*p2))
      p2++;
    if(*p2)
      *p2++ =0;
    nsip.s_addr=getip(val);
    if(nsip.s_addr) {                 /* If we have a valid IP address */
      wgrdp=safemalloc(sizeof(WGRDDATA),"WGRDParse","wgrdp");	/* create new watchguard */
      plugindatalist->data=wgrdp;
      wgrdp->ip_addr.s_addr=nsip.s_addr;
      safecopy(wgrdp->command,cmd);     /* save command */
      wgrdp->passphrase[0]=0;
      wgrdp->passphrasefile[0]=0;
      val=p2;
      while(*val && myisspace(*val))          /* skip spaces */
        val++;
      if(*val) {
        p2=val;
        while(*p2 && !myisspace(*p2))   /* parse passphrase */
          p2++;
        if(*p2)
          *p2++ =0;
        safecopy(wgrdp->passphrase,val);     /* save passphrase */
        if(*p2) {                                      /* if we have a pass file */
          val=p2;
          while(*val && myisspace(*val))          /* skip spaces */
            val++;
          if(*val) {
            p2=val;
            while(*p2 && !myisspace(*p2))   /* parse it */
              p2++;
            if(*p2)
              *p2++ =0;
            safecopy(wgrdp->passphrasefile,val);     /* save passwordfile */
            wgrdp->passphrase[0]=0;		  /* erase passphrase */
          }
        }
      }
      if(!wgrdp->passphrase[0] && !wgrdp->passphrasefile[0] ) {
        snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Watchguard defined without login possibility!",file,line);
        logmessage(1,msg,"wgrd",0);
        free(wgrdp);
        plugindatalist->data=NULL;
#ifdef FWSAMDEBUG
      } else {
        printf("Debug: [wgrd] Adding Watchguard: CMD \"%s\", IP \"%s\", PP \"%s\", PPF \"%s\"\n", wgrdp->command ,inettoa( wgrdp->ip_addr.s_addr),wgrdp->passphrase,wgrdp->passphrasefile);
#endif
      }
    } else {
      snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Invalid Watchguard parameter '%s' ignored.",file,line,val);
      logmessage(1,msg,"wgrd",0);
    }
  } else {       
    snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Empty Watchguard parameter.",file,line);
    logmessage(1,msg,"wgrd",0);
  }
}


/* This routine initiates the block. 
 */
void WGRDBlock(BLOCKINFO *bd,void *data,unsigned long qp) 
{
  char wgrdcmd[255], msg[STRBUFSIZE+2];
  char *wgexecp = "fbidsmate";
  WGRDDATA *wgrdp = (WGRDDATA *)data;
#ifdef FWSAMDEBUG
#ifdef WIN32
  unsigned long threadid=GetCurrentThreadId();
#else
  pthread_t threadid=pthread_self();
#endif
#endif
  if(!wgrdp) return;
  if(wgrdp->command)
    wgexecp=wgrdp->command;
#ifdef FWSAMDEBUG
	printf("Debug: [wgrd][%lx] Plugin Blocking...\n",(unsigned long)threadid);
#endif
  if(bd->block) {
    snprintf(msg,sizeof(msg)-1,"Info: Blocking ip %s", inettoa(bd->blockip));
    logmessage(1,msg,"wgrd",0);
    /* Assemble command 2 possibilities with passphrase or with passphrasefile */
    if ( *(wgrdp->passphrase) ) {
      if (snprintf(wgrdcmd,sizeof(wgrdcmd)-1, "%s %s %s add_hostile %s", wgexecp, inettoa( wgrdp->ip_addr.s_addr), wgrdp->passphrase, inettoa(bd->blockip)) >= 255) {
        snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", wgrdcmd);
        logmessage(1,msg,"wgrd",0);
        return;
      }
    } else {
      if (snprintf(wgrdcmd,sizeof(wgrdcmd)-1, "%s %s -f %s add_hostile %s", wgexecp, inettoa( wgrdp->ip_addr.s_addr), wgrdp->passphrasefile, inettoa(bd->blockip)) >= 255) {
        snprintf(msg,sizeof(msg)-1,"Error: Command %s is too long", wgrdcmd);
        logmessage(1,msg,"wgrd",0);
        return;
      }
    }
  } else {
    snprintf(msg,sizeof(msg)-1,"Info: UnBlocking ip %s not supported", inettoa(bd->blockip));
    logmessage(3,msg,"wgrd",0);
  }
#ifdef FWSAMDEBUG
  printf("Debug: [wgrd][%lx] command %s\n", (unsigned long)threadid, wgrdcmd);
#endif
  /* Run the command */
  if (system(wgrdcmd) != 0) { 
    snprintf(msg,sizeof(msg)-1,"Error: Command %s Failed", wgrdcmd);
    logmessage(1,msg,"wgrd",0);
  } else {
    snprintf(msg,sizeof(msg)-1,"Info: Command %s Executed Successfully", wgrdcmd);
    logmessage(3,msg,"wgrd",0);
  }
  return;
}

#endif /* __SSP_WGRD_C__ */
