/* $Id: ssp_8signs.h,v 2.3 2008/04/26 19:53:21 fknobbe Exp $
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
 * ssp_8signs.h 
 * 
 * Purpose:  
 *
 * This SnortSam plugin calls the dfw.exe program of the 8Signs firewall to
 * block/unblock IP addresses.
 *
 */

#if defined(WIN32)

#ifndef		__SSP_8SIGNS_H__
#define		__SSP_8SIGNS_H__

/* Instead of a data structure, this plugin just allocs a char pointer,
 * for the path to dfw. So no definition required here.
 * (It abuses the first byte as a boolean for the tar flag. That way
 * we don't need to allocate a structure and having to worry about
 * freeing members. Yeah, it's a hack, but it works.)
 */

void DFWParse(char *val,char *file,unsigned long line,DATALIST *);
void DFWBlock(BLOCKINFO *bd,void *,unsigned long);

#endif /* __SSP_8SIGNS_H__ */
#endif /* WIN32 */
