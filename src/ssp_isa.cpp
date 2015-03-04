/* $Id: ssp_isa.cpp,v 2.5 2009/10/16 22:19:36 fknobbe Exp $
 *
 *
 * Copyright (c) 2004-2008 nima sharifi mehr <nimahacker@yahoo.com>
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
 * ssp_isa.cpp 
 * 
 * Purpose:  
 *
 * This SnortSam plugin adds block/unblock rules to a MS ISA Server firewall.
 *
 */

#ifdef WIN32
#ifdef WITH_ISA2002

#ifndef		__SSP_ISA_CPP__
#define		__SSP_ISA_CPP__

#include "snortsam.h"
#include "ssp_isa.h"


/*  Use the supplied version of the DLL in the contrib folder.  */
#import "..\\contrib\\isa2000\\msfpccom.dll" no_namespace

/*  Use your version of the DLL in the ISA Server folder.  */
/* #import "C:\\program files\\microsoft isa server\\msfpccom.dll" no_namespace */


static void cpp_safecopy(char *dst,unsigned long max,char *src)		
{	if(dst && src && max)
	{	while(--max>0 && *src)
			*dst++ = *src++;
		*dst=0;
	}
}

static char *cpp_inettoa(unsigned long ip)
{	struct in_addr ips;
	static char addr[256][20];
	static unsigned char toggle;

	ips.s_addr=ip;
	toggle=(toggle+1)&255;
	cpp_safecopy(addr[toggle],sizeof(addr[toggle]),inet_ntoa(ips));
	return addr[toggle];
}


extern "C" void ISAParse(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	ISADATA	*isap;
	char *p;
	
#ifdef FWSAMDEBUG
	printf("Debug: [isa] Plugin Parsing...\n");
#endif
    
    isap=(ISADATA *)malloc(sizeof(ISADATA));		/* create new isa structure */
    assert(isap);
	plugindatalist->data=isap;
	isap->logflag=FALSE;			/* By default, we don't cause ISA log entries. */
	
	if(*val)
	{	p=val;
		while(*p && !isspace(*p))
			p++;
		*p=0;
		if(!stricmp(val,"log"))		/* If "log" is specified in the config line, */
			isap->logflag=TRUE;		/* then we do log. */
	}

	CoInitialize(NULL);				/* Initializing ISA stuff. */
		
#ifdef FWSAMDEBUG
	printf("Debug: [isa] ISA firewall added.%s\n",isap->logflag?" Will log access from blocked hosts.":"");
#endif
}

extern "C" void ISABlock(BLOCKINFO *bd,void *data,unsigned long qp)
{	ISADATA *isap;
#ifdef FWSAMDEBUG
#ifdef WIN32
	unsigned long threadid=GetCurrentThreadId();
#else
	pthread_t threadid=pthread_self();
#endif
#endif
	char blockname[STRBUFSIZE+2],description[STRBUFSIZE+2];
	IFPCPtr objFPC;
	HRESULT hr;
	IFPCArrayPtr arr;
	IFPCIpPacketFilterPtr pf;


	if(!data)
		return;
    isap=(ISADATA *)data;

	hr = objFPC.CreateInstance(__uuidof(FPC));
	
	if(!FAILED(hr))
	{
#ifdef FWSAMDEBUG
	printf("Debug: [isa][%lx] Plugin Blocking...\n",threadid);
#endif
		
		try
		{
			arr = objFPC->Arrays->GetContainingArray();
			
			snprintf(blockname,sizeof(blockname)-1,"SID:%lu:FWSAM:%u:%s:%u:%u:%s",bd->sig_id,bd->mode,cpp_inettoa(bd->blockip),bd->port,bd->proto,cpp_inettoa(bd->peerip));
			
			if(bd->block)
			{	pf = arr->ArrayPolicy->IpPacketFilters->Add(blockname, fpcBlockingPacketFilter);

				snprintf(description,sizeof(description)-1,"Blocked by Snortsam. SID: %lu",bd->sig_id);
				pf->Description = description;

				pf->AllServers = TRUE;
				pf->FilterType = fpcCustomFilterType;

				pf->LocalPortType = fpcPfAnyPort;
				pf->RemotePortType = fpcPfAnyRemotePort;
				pf->ProtocolNumber = 0;

				switch(bd->mode&FWSAM_HOW)
				{	case FWSAM_HOW_IN:		pf->PacketDirection = fpcPfDirectionIndexIn;
											break;

					case FWSAM_HOW_OUT:		pf->PacketDirection = fpcPfDirectionIndexOut;
											break;
					
					case FWSAM_HOW_INOUT: 	; 	/* For the moment we only block full IPs. Connections may come later. */
					default:				pf->PacketDirection = fpcPfDirectionIndexBoth;
											break;
				}

				pf->SetLocalHost(fpcPfDefaultProxyExternalIp,"","");
				pf->SetRemoteHost(fpcPfSingleHost,cpp_inettoa(bd->blockip),"255.255.255.255");
				
				pf->LogMatchingPackets = isap->logflag;
				/* enable the filter */
				pf->Enabled = TRUE;
				/* save the changes */
				arr->Save();
			}
			else
			{	arr->ArrayPolicy->IpPacketFilters->Remove(blockname);
				arr->Save();
			}
#ifdef FWSAMDEBUG
			printf("Debug: [isa] %s entry: %s\n",bd->block?"Blocked":"Unblocked",blockname);
#endif
		}
		catch(_com_error e)
		{
		}
	}

}

#endif /* __SSP_ISA_CPP__ */
#endif /* WITH_ISA */
#endif /* WIN32 */

