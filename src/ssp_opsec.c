/* $Id: ssp_opsec.c,v 2.6 2009/11/27 01:39:40 fknobbe Exp $
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
 * ssp_opsec.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin makes use of the OPSEC libraries of the OPSEC SDK in 
 * order to  communicate with Firewall-1. This implementation makes the process
 * fully OPSEC compliant. 
 *
 * Comments:
 *
 * - Needs some serious rewrite. The client/server objects should be created at
 * parse time of the plugin, and then kept in the data list (as opposed to keeping
 * the config file in list and creating client/server objects at every block).
 * 
 * - Look into possible thread conflict issue.
 *
 */


#ifndef		__SSP_OPSEC_C__
#define		__SSP_OPSEC_C__

#ifdef	ENABLE_OPSEC


#include "snortsam.h"
#include "ssp_opsec.h"


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



static BLOCKINFO *opsecblockinfo;  /* Since we're multi-threading, we need to dump the block info somewhere static */

/*
 * Session start handler dummy
*/
static int fw_sam_client_session_creator(OpsecSession *session)
{	return OPSEC_SESSION_OK;
}

/*
 * Session end handler dummy
*/
static void fw_sam_client_session_deletor(OpsecSession *session)
{
}

/*
 * Send SAM requests when session is established
*/
static int SessionEstablishedHandler(OpsecSession *session)
{	int rc,logtype,action,opmode;
	struct in_addr bip,bpip;
	static char msg[STRBUFSIZE+2];	/*	This msg buffer needs to be static so that the other
								handler can access it. It could also be malloc'ed and
								free'd (as in the SDK example), but why make it 
								complicated and open outselves up for a memory leak? 
								(as in the SDK...grin). After all, it's just 1 K... */

	if(!opsecblockinfo->block)
	{	action=SAM_INHIBIT_DROP_AND_CLOSE|SAM_CANCEL;
		safecopy(msg,"Cancel Inhibit");   
	}
	else
	{	action=SAM_INHIBIT_DROP_AND_CLOSE;
/*		safecopy(msg,"Inhibit & Close");     4.x lingo */
		safecopy(msg,"Inhibit-Drop");		/* ng lingo */
	}
	logtype=opsecblockinfo->mode&FWSAM_LOG;
/*	...which is cheating since the values match up. If we wanted to be politically correct,
	we'd need this:

	switch(opsecblockinfo->mode&FWSAM_LOG)
	{	default: ;
		case FWSAM_LOG_NONE:		logtype=SAM_NOLOG; break;
		case FWSAM_LOG_SHORTLOG:	logtype=SAM_SHORT_NOALERT; break;
		case FWSAM_LOG_SHORTALERT:	logtype=SAM_SHORT_ALERT; break;
		case FWSAM_LOG_LONGLOG:		logtype=SAM_LONG_NOALERT; break;
		case FWSAM_LOG_LONGALERT:	logtype=SAM_LONG_ALERT; break;
	}
*/
	switch(opsecblockinfo->mode&FWSAM_HOW)
	{	case FWSAM_HOW_IN:		
			strcat(msg," src ip"); 
			opmode=SAM_SRC_IP;
			break;
		case FWSAM_HOW_OUT:		
			strcat(msg," dst ip"); 
			opmode=SAM_DST_IP;
			break;
		default: ;				
		case FWSAM_HOW_INOUT:	
			strcat(msg," any ip"); 
			opmode=SAM_ANY_IP;
			break;
		case FWSAM_HOW_THIS:	
			strcat(msg," service"); 
			opmode=SAM_SERV_OLD;  /* using old format for backwards compatibility */
			break;
	}
	bip.s_addr=opsecblockinfo->blockip;
	snprintf(msg+strlen(msg),sizeof(msg)-1-strlen(msg)," %s",inettoa(bip.s_addr)); /* add IP to message */
	if(opsecblockinfo->mode&FWSAM_HOW_THIS)
	{	bpip.s_addr=opsecblockinfo->peerip; /* since this ia a service block, we get the peer ip */
		snprintf(msg+strlen(msg),sizeof(msg)-1-strlen(msg)," %s %i %i",inettoa(bpip.s_addr),opsecblockinfo->port,opsecblockinfo->proto);
		strcat(msg," on All");
		rc=sam_client_action(session,action,logtype,"All",msg,SAM_EXPIRE,opsecblockinfo->duration,
						 SAM_REQ_TYPE,opmode,opsecblockinfo->blockip,opsecblockinfo->peerip,
						 opsecblockinfo->port,opsecblockinfo->proto,NULL);	
	}
	else
	{	strcat(msg," on All");
		rc=sam_client_action(session,action,logtype,"All",msg,SAM_EXPIRE,opsecblockinfo->duration,
						 SAM_REQ_TYPE,opmode,opsecblockinfo->blockip,NULL);	
	}
	if(rc<0) 
	{	snprintf(msg,sizeof(msg)-1,"Error: OPSEC request '%s' failed (%s)!",msg,opsec_errno_str(opsec_errno));
		logmessage(1,msg,"opsec",0);
	}
	return OPSEC_SESSION_OK;
}

/*
 * Handle SAM action request acknowledgement
*/
static int AckEventHandler(OpsecSession *session,int n_closed,int sam_status,
						   int fw_index,int fw_total,char *fw_host,void *cb_data)
{	char msg[STRBUFSIZE+2];

	switch (sam_status)
	{	case SAM_REQUEST_RECEIVED:	/* the request is received */
			snprintf(msg,sizeof(msg)-1,"Info: OPSEC request for '%s' acknowledged.",(char *)cb_data);
			logmessage(3,msg,"opsec",0);
			break;
		case SAM_MODULE_DONE:		/* the module from firewall object is processed */
			snprintf(msg,sizeof(msg)-1,"Info: OPSEC request on '%s' (%d/%d) successfully completed processing '%s'.",fw_host,fw_index+1,fw_total,(char *)cb_data);
			logmessage(3,msg,"opsec",0);
			break;
		case SAM_MODULE_FAILED:		/* the module processing has failed */
			snprintf(msg,sizeof(msg)-1,"Error: OPSEC request on '%s' (%d/%d) failed processing '%s'.",fw_host,fw_index+1,fw_total,(char *)cb_data);
			logmessage(1,msg,"opsec",0);
			break;
		case SAM_REQUEST_DONE:		/* all modules are processed */
			snprintf(msg,sizeof(msg)-1,"Info: OPSEC request for '%s' done.",(char *)cb_data);
			logmessage(3,msg,"opsec",0);
			return OPSEC_SESSION_END;
			break;
		case SAM_RESOLVE_ERR:		/* resolving error for firewall object */
			snprintf(msg,sizeof(msg)-1,"Error: OPSEC could not resolve firewalled object name in '%s'. The SAM request was not enforced.",(char *)cb_data);
			logmessage(1,msg,"opsec",0);
			return OPSEC_SESSION_END;
		case SAM_UNEXPECTED_END_OF_SESSION:	/* unexpected end of session while processing the request */
			snprintf(msg,sizeof(msg)-1,"Error: Unexpected end of OPSEC session. It is possible that the SAM request for '%s' was not enforced.",(char *)cb_data);
			logmessage(1,msg,"opsec",0);
			return OPSEC_SESSION_END;
		default:
			snprintf(msg,sizeof(msg)-1,"Error: Unexpected OPSEC status '%d'.",sam_status);
			logmessage(1,msg,"opsec",0);
			return OPSEC_SESSION_ERR;
	}
	return OPSEC_SESSION_OK;
}

/*
 * Monitor handler dummy (since we don't monitor)
*/
static int MonitorAckEventHandler(OpsecSession *session,int sam_status,int fw_index,int fw_total,
								  char *fw_host,void *cb_data,opsec_table monitor_data)
{
	return OPSEC_SESSION_OK;
}

/*
 * Clean environment before exiting
*/
static void clean_env(OpsecEnv *env,OpsecEntity *client,OpsecEntity *server)
{	if(client)
		opsec_destroy_entity(client);
	if(server)
		opsec_destroy_entity(server);
	if(env)
		opsec_env_destroy(env);
}


/* This routine parses the opsec statements in the config file.
 * It builds a list of config files (i.e. sam.conf, opsec.conf)
*/
void OPSEC_Parse(char *val,char *file,unsigned long line,DATALIST *datalistp)
{	OPSECDATA *opsecp;
	char tmpstr[FILEBUFSIZE+2],msg[STRBUFSIZE+2];
	FILE *fp;

#ifdef FWSAMDEBUG
	printf("Debug: [opsec] Plugin Parsing...\n");
#endif
    if(*val)
	{	remspace(val);
		safecopy(tmpstr,val);
		if((fp=fopen(tmpstr,"r"))!= NULL)				/* if file exist */
		{	opsecp=safemalloc(sizeof(OPSECDATA),"OPSEC_Parse","opsecp");	/* create new cfg file entry */
			datalistp->data=opsecp;
			safecopy(opsecp->cfgfile,tmpstr);
			fclose(fp);
			snprintf(msg,sizeof(msg)-1,"OPSEC: Adding configuration file '%s'.",tmpstr);
			logmessage(3,msg,"opsec",0);
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] OPSEC conf file '%s' not found, parameter ignored.",file,line,tmpstr);
			logmessage(1,msg,"opsec",0);
		}
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s: %lu] Empty OPSEC parameter.",file,line);
		logmessage(1,msg,"opsec",0);
	}
}


/* This routine initiates the block. It walks the list of OPSEC
 * configuration files and establishes and OPSEC session to 
 * each host defined in the conf files, and sends the SAM
 * blocking request.
 */
void OPSEC_Block(BLOCKINFO *bd,void *data,unsigned long qp)
{   OPSECDATA *opsecp;
	int port_type;
	OpsecEnv *env;
	OpsecEntity *server,*client;
	OpsecSession *session;
	unsigned long sam_server;
	unsigned short port;
	char *conf,msg[STRBUFSIZE+2];
#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif


	printf("Debug: [opsec][%lx] Plugin Blocking...\n",threadid);
#endif

	opsecp=(OPSECDATA *)data;
	opsecblockinfo=bd;

	env=NULL;
	server=client=NULL;
	session=NULL;

	/* create SAM Session */
	env=opsec_init(OPSEC_CONF_FILE,opsecp->cfgfile,OPSEC_EOL);
	if(env==NULL)
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s] OPSEC init failed!",opsecp->cfgfile);
		logmessage(1,msg,"opsec",0);
		getout(1);
	}
	/* Next, get the port number out of the OPSEC conf file */
	conf=opsec_get_conf(env,"sam_server","auth_port",NULL);
	if(conf)
	{	port=atoi(conf);
		port_type=OPSEC_SERVER_AUTH_PORT;
	}
	else
	{	conf=opsec_get_conf(env,"sam_server","port",NULL);
		if(conf)
		{	port=atoi(conf);
			port_type=OPSEC_SERVER_PORT;
		}
		else
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s] File does not define sam_server port! Skipping file.",opsecp->cfgfile);
			logmessage(1,msg,"opsec",0);
			return;
		}
	}
	/* Here we pick the IP address out of the OPSEC conf file
	   (SDK didn't include this... tsk-tsk)  */
	conf=opsec_get_conf(env,"sam_server","ip",NULL);
	if(conf)
	{	sam_server=getip(conf);
		if(!sam_server)
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s] File does not define valid sam_server ip! Trying localhost.",opsecp->cfgfile);
			logmessage(1,msg,"opsec",0);
			sam_server=getip("localhost");
		}
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s] File does not define sam_server ip! Assuming localhost.",opsecp->cfgfile);
		logmessage(1,msg,"opsec",0);
		sam_server=getip("localhost");
	}

	/* create client entity */
	client=opsec_init_entity(env,SAM_CLIENT,OPSEC_SESSION_START_HANDLER,fw_sam_client_session_creator,
							 OPSEC_SESSION_END_HANDLER,fw_sam_client_session_deletor,
							 OPSEC_SESSION_ESTABLISHED_HANDLER,SessionEstablishedHandler,
							 SAM_ACK_HANDLER,AckEventHandler,
							 SAM_MONITOR_ACK_HANDLER,MonitorAckEventHandler,OPSEC_EOL);
		
	if(client)
	{	/* create server entity */
		server=opsec_init_entity(env,SAM_SERVER,OPSEC_ENTITY_NAME,"sam_server",
								 OPSEC_SERVER_IP,sam_server,port_type,port,OPSEC_EOL);

		if(server)
		{	session=sam_new_session(client,server); /* establich session and process handlers */
			if(session)
				opsec_mainloop(env);
			else
			{	snprintf(msg,sizeof(msg)-1,"Error: [%s] SAM session initialization failed (%s)! The SAM request was not performed.",opsecp->cfgfile,opsec_errno_str(opsec_errno));
				logmessage(1,msg,"opsec",0);
			}
		}			
		else	
		{	snprintf(msg,sizeof(msg)-1,"Error: [%s] OPSEC server entity initialization failed! The SAM request was not performed.",opsecp->cfgfile);
			logmessage(1,msg,"opsec",0);
		}
	}
	else
	{	snprintf(msg,sizeof(msg)-1,"Error: [%s] OPSEC client entity initialization failed! The SAM request was not performed.",opsecp->cfgfile);
		logmessage(1,msg,"opsec",0);
	}
	clean_env(env,client,server);
}

#endif
#endif /* __SSP_OPSEC_C__ */

