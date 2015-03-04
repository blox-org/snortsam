/* $Id: ssp_pf2.h,v 3.3 2009/11/27 01:39:40 fknobbe Exp $
 *
 * Copyright (c) 2003 Hector Paterno <apaterno@dsnsecurity.com>
 * Copyright (c) 2004, 2005 Olaf Schreck <chakl@syscall.de>
 * Copyright (c) 2009  Olli Hauer <ohauer@gmx.de>
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
 * ssp_pf2.h 
 * 
 * Purpose:  
 *  See inside ssp_pf2.c
 *  
 *
 */

#ifndef USE_SSP_PF
#if defined(OpenBSD) || defined(FreeBSD) || defined(NetBSD)

#ifndef		__SSP_PF2_H__
#define		__SSP_PF2_H__

#define         PFDEV     "/dev/pf"

#include <sys/file.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <errno.h>

typedef struct _pf2data
{	
        char anchorname[PF_ANCHOR_NAME_SIZE];
	char tablein[PF_TABLE_NAME_SIZE];
	char tableout[PF_TABLE_NAME_SIZE];
	unsigned int kill;
}	PF2DATA;

/* opt parsing routine defines and structs */

#define MAX_OPT_NAME 16
#define MAX_OPT_VALUE 16

typedef struct _opt_pf2
{
   char name[MAX_OPT_NAME];            /* Option Name */
   union
     {
	char value_s[MAX_OPT_VALUE];   /* String Value */
	int value_d;	               /* Integer Value */
     }v;	
   int vt;			       /* Value type */
}
opt_pf2;

enum { PF2_OPT_ANCHOR, PF2_OPT_TABLE, PF2_OPT_KILL };
enum { PF2_KILL_STATE_ALL, PF2_KILL_STATE_DIR, PF2_KILL_STATE_NO };

void PF2Parse(char *,char *,unsigned long,DATALIST *);
void PF2Block(BLOCKINFO *, void *,unsigned long);
int pf2_kill_states(int, const char *, int, int);
int lookup_anchor(int, const char *);
int lookup_table(int, const char *, const char *);

#endif /* __SSP_PF2_H__ */

#endif /* OpenBSD || FreeBSD || NetBSD */
#endif /* !USE_SSP_PF */
