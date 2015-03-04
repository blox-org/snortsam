/* $Id: ssp_fwexec.h,v 2.4 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2004-2008 Frank Knobbe <frank@knobbe.us>
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
 * ssp_fwexec.h 
 * 
 * Purpose:  
 *
 * This SnortSam plugin calls the fw.exe program of Firewall-1 to block/unblock.
 * (This used to be a built-in function but has now been moved to a plugin as
 * an example for other executable plugins. Hopefully this will be wrapped into
 * a generic script wrapper at some time.)
 *
 */


#ifndef		__SSP_FWEXEC_H__
#define		__SSP_FWEXEC_H__

/* Instead of a data structure, this plugin just allocs a char pointer,
 * the fwexec string. So no definition required here.
 */

void FWExecParse(char *val,char *file,unsigned long line,DATALIST *);
void FWExecBlock(BLOCKINFO *bd,void *,unsigned long);

#endif /* __SSP_FWEXEC_H__ */

