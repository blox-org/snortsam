/* $Id: ssp_snmp_interface_down.h,v 2.2 2008/04/26 19:53:21 fknobbe Exp $
 *
 * Copyright (c) 2005-2008 Ali BASEL <ali@basel.name.tr>
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
 * ssp_snmp_interface_shutdown.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin calls the trackersnmp program of the tracker(http://www.basel.name.tr) to
 * shutdown the switch ports of the local intruders to block the IP addresses.
 *
 */

#ifndef		__SSP_SNMPINTERFACEDOWN_H__
#define		__SSP_SNMPINTERFACEDOWN_H__


typedef struct _snmpinterfacedowndata				
{	int logflag;
	char trackersnmppath[FILEBUFSIZE+2];	
}	SNMPINTERFACEDOWNDATA;

void SNMPINTERFACEDOWNParse(char *val, char *file, unsigned long line, DATALIST *);
void SNMPINTERFACEDOWNBlock(BLOCKINFO *bd, void *,unsigned long);

#endif /* __SSP_SNMPINTERFACEDOWN_H__ */

