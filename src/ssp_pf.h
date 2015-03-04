/* $Id: ssp_pf.h,v 3.7 2009/11/27 01:39:40 fknobbe Exp $
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
 * ssp_pf.h
 *
 * Purpose:
 *  See inside ssp_pf.c
 *
 *
*/


#ifndef USE_SSP_PF
#if defined(OpenBSD) || defined(FreeBSD) || defined(NetBSD)

#ifndef		__SSP_PF_H__
#define		__SSP_PF_H__

#define         PFDEV     "/dev/pf"
#define         PFPERM    O_RDWR

#include <net/if.h>
#include <net/pfvar.h>
#include <sys/param.h>


typedef struct _pfdata
{
        char anchorname[PF_ANCHOR_NAME_SIZE];
	char tablename[PF_TABLE_NAME_SIZE];
        char iface[16];
        int logopt;
}	PFDATA;

/* opt parsing routine defines and structs */

#define MAX_OPT_NAME 16
#define MAX_OPT_VALUE 16

typedef struct _opt_s
{
   char name[MAX_OPT_NAME];            /* Option Name */
   union
     {
        char value_s[MAX_OPT_VALUE];   /* String Value */
        int value_d;	               /* Integet Value */
     } v;
   int vt;			       /* Value type */
}
opt_s;

enum { PF_OPT_AUTO, PF_OPT_LOG, PF_OPT_ETH, PF_OPT_ANCHOR, PF_OPT_TABLE };


void PFParse(char *,char *,unsigned long,DATALIST *);
void PFBlock(BLOCKINFO *, void *,unsigned long);

#endif /* __SSP_PF_H__ */

#endif /* OpenBSD || FreeBSD || NetBSD */
#endif /* USE_SSP_PF */
