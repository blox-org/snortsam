/* $Id: ssp_isa.h,v 2.3 2009/10/16 22:19:36 fknobbe Exp $
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
 * ssp_isa.h 
 * 
 * Purpose:  
 *
 * This SnortSam plugin adds block/unblock rules to a MS ISA Server firewall.
 *
 */

#ifdef WIN32
#ifdef WITH_ISA2002

#ifndef		__SSP_ISA_H__
#define		__SSP_ISA_H__

#ifdef __cplusplus
extern "C"	{
#endif

typedef struct _isadata				
{	int logflag;	
}	ISADATA;

void ISAParse(char *,char *,unsigned long,DATALIST *);
void ISABlock(BLOCKINFO *,void *,unsigned long);

#ifdef __cplusplus
}
#endif

#endif /* __SSP_ISA_H__ */
#endif /* WITH_ISA2002 */
#endif /* WIN32 */

