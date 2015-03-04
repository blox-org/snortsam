/* $Id: ssp_isa2004.cpp,v 1.3 2009/10/16 22:19:36 fknobbe Exp $
 *
 *
 * Copyright (c) 2004 nima sharifi mehr <nimahacker@yahoo.com>
 * All rights reserved.
 * Copyright (c) 2006-2008 mark p clift <mark_clift@yahoo.com>
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
 * ssp_isa2004.cpp 
 * 
 * Purpose:  
 *
 * This SnortSam plugin adds/deletes Computer Set Computers for use in firewall policy deny rules on a MS ISA 2004 Server firewall.
 * 
 * Notes:
 *
 * It assumes that the Computers Sets "Blocked IPs In" and "Blocked IPs Out" have been defined through the administrative interface
 * of the ISA 2004 server. If the Computer Sets are undefined it will exit gracefully due to the try catch block.
 *
 * In order for this plugin to function properly the ISA 2004 firewall must have the aforemention Computers Sets defined and 2 deny 
 * rules which utilize these Computer Sets one each for inbound and outbound. Please review the README.isa2004 file for details.
 *
 */

#ifdef WIN32
#ifdef WITH_ISA2004

#ifndef		__SSP_ISA2004_CPP__
#define		__SSP_ISA2004_CPP__

#include "snortsam.h"
#include "ssp_isa2004.h"


/*  Use the supplied version of the DLL in the contrib folder.  */
#import "..\\contrib\\isa2004\\msfpccom.dll" no_namespace

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


extern "C" void ISAParse2004(char *val,char *file,unsigned long line,DATALIST *plugindatalist)
{	ISADATA2004	*isap;
	char *p;
	
#ifdef FWSAMDEBUG
	printf("Debug: [isa2004] Plugin Parsing...\n");
#endif
    
    isap=(ISADATA2004 *)malloc(sizeof(ISADATA2004));		/* create new isa structure */
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
	printf("Debug: [isa2004] ISA 2004 firewall added.%s\n",isap->logflag?" Will log access from blocked hosts.":"");
#endif
}

extern "C" void ISABlock2004(BLOCKINFO *bd,void *data,unsigned long qp)
{	ISADATA2004 *isap;
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
	IFPCComputerSetsPtr pComputerSets;
	IFPCComputerSetPtr pComputerSet;
	IFPCComputerPtr pComputer;


	if(!data)
		return;
    isap=(ISADATA2004 *)data;

	hr = objFPC.CreateInstance(__uuidof(FPC));
	
	if(!FAILED(hr))
	{
#ifdef FWSAMDEBUG
	printf("Debug: [isa2004][%lx] Plugin Blocking...\n",threadid);
#endif
		
		try
		{
			pComputerSets = objFPC->GetContainingArray()->RuleElements->ComputerSets;
			
			snprintf(blockname,sizeof(blockname)-1,"SID:%lu:FWSAM:%u:%s:%u:%u:%s",bd->sig_id,bd->mode,cpp_inettoa(bd->blockip),bd->port,bd->proto,cpp_inettoa(bd->peerip));
			
			if(bd->block)
			{	
				

				switch(bd->mode&FWSAM_HOW)
				{	
					case FWSAM_HOW_IN:
						pComputerSet = pComputerSets->Item("Blocked IPs In");
						pComputer = pComputerSet->Computers->Add(blockname,cpp_inettoa(bd->blockip));		//Add Computer to ComputerSet
						pComputer->Save(0,1);																//Apply Settings
						break;

					case FWSAM_HOW_OUT:		
						pComputerSet = pComputerSets->Item("Blocked IPs Out");
						pComputer = pComputerSet->Computers->Add(blockname,cpp_inettoa(bd->blockip));		//Add Computer to ComputerSet
						pComputer->Save(0,1);																//Apply Settings
						break;
					
					case FWSAM_HOW_INOUT: 	
						pComputerSet = pComputerSets->Item("Blocked IPs In");
						pComputer = pComputerSet->Computers->Add(blockname,cpp_inettoa(bd->blockip));		//Add Computer to ComputerSet
						pComputer->Save(0,1);
						pComputerSet = pComputerSets->Item("Blocked IPs Out");
						pComputer = pComputerSet->Computers->Add(blockname,cpp_inettoa(bd->blockip));		//Add Computer to ComputerSet
						pComputer->Save(0,1);
						break; 	
					
					
					default:
						pComputerSet = pComputerSets->Item("Blocked IPs In");
						pComputer = pComputerSet->Computers->Add(blockname,cpp_inettoa(bd->blockip));		//Add Computer to ComputerSet
						pComputer->Save(0,1);
						pComputerSet = pComputerSets->Item("Blocked IPs Out");
						pComputer = pComputerSet->Computers->Add(blockname,cpp_inettoa(bd->blockip));		//Add Computer to ComputerSet
						pComputer->Save(0,1);
						break;
				}


			}
			else
			{	
				switch(bd->mode&FWSAM_HOW)
				{	
					case FWSAM_HOW_IN:
						pComputerSet = pComputerSets->Item("Blocked IPs In");
						pComputerSet->Computers->Remove(blockname);							//Remove Computer from ComputerSet
						pComputerSet->Save(0,1);											//Apply Settings
						break;

					case FWSAM_HOW_OUT:		
						pComputerSet = pComputerSets->Item("Blocked IPs Out");
						pComputerSet->Computers->Remove(blockname);							//Remove Computer from ComputerSet
						pComputer->Save(0,1);												//Apply Settings
						break;
					
					case FWSAM_HOW_INOUT: 	
						pComputerSet = pComputerSets->Item("Blocked IPs In");
						pComputerSet->Computers->Remove(blockname);							//Remove Computer from ComputerSet
						pComputerSet->Save(0,1);
						pComputerSet = pComputerSets->Item("Blocked IPs Out");
						pComputerSet->Computers->Remove(blockname);							//Remove Computer from ComputerSet
						pComputerSet->Save(0,1);
						break; 	
					
					
					default:
						pComputerSet = pComputerSets->Item("Blocked IPs In");
						pComputerSet->Computers->Remove(blockname);							//Remove Computer from ComputerSet
						pComputerSet->Save(0,1);
						pComputerSet = pComputerSets->Item("Blocked IPs Out");
						pComputerSet->Computers->Remove(blockname);							//Remove Computer from ComputerSet
						pComputerSet->Save(0,1);
						break;
				}			
					
				
			}

#ifdef FWSAMDEBUG
			printf("Debug: [isa2004] %s entry: %s\n",bd->block?"Blocked":"Unblocked",blockname);
#endif
		}
		catch(_com_error e)
		{
		

		}
	}

}

#endif /* __SSP_ISA2004_CPP__ */
#endif /* WITH_ISA2004 */
#endif /* WIN32 */

