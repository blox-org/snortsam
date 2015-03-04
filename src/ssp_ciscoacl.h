/* $Id: ssp_ciscoacl.h,v 2.4 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2002-2008 Ali BASEL <alib@sabanciuniv.edu>
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
 * ssp_ciscoacl.h 
 * 
 * Purpose:  
 *
 * This SnortSam cisco_acl plugin blocks attackers using cisco router ACLs. 
 *
 *
 */


#ifndef		__SSP_CISCOACL_H__
#define		__SSP_CISCOACL_H__


#define CISCOACLPWLEN	50	/* Maximum password length */
#define CISCOACLFILELEN	100
#define CISCOACLNETWAIT	20	/* Network timeout in sec */

typedef struct _ciscoacldata	/* List of ciscoacl routers */
{	struct in_addr	ip;
	char	username[CISCOACLPWLEN+2];
	char	telnetpw[CISCOACLPWLEN+2];
	char	enablepw[CISCOACLPWLEN+2];
	char	aclfile[CISCOACLFILELEN+2];
	char	ftpfile[CISCOACLFILELEN+2];
} CISCOACLDATA;


void CISCOACLParse(char *,char *,unsigned long,DATALIST *);
void CISCOACLBlock(BLOCKINFO *,void *,unsigned long);
int CISCOACLCheck(char *,char *);
int CISCOACLsendreceive(SOCKET,char *,char *);

#endif /* __SSP_CISCOACL_H__ */

