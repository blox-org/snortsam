/* $Id: ssp_email.h,v 2.6 2008/04/26 19:53:21 fknobbe Exp $
 *
 *
 * Copyright (c) 2002-2008 Frank Knobbe <frank@knobbe.us>
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
 * ssp_email.h 
 * 
 * Purpose:  
 *
 * This SnortSam plugin sends an email with a notification of the block/unblock.
 * It connects to a specified mail server and sends to a specified recipient via
 * standard SMTP (not ESMTP) commands.
 *
 * AUTHENTICATION (AUTH) AND/OR ENCRYPTION (OVER SSL) IS NOT SUPPORTED.
 * If you need to authenticate to your mail server, or prefer SMTP over SSL,
 * please use a program like swatch to check for changes in the log file and
 * have a third party mailer send them. 
 *
 *
 */


#ifndef		__SSP_EMAIL_H__
#define		__SSP_EMAIL_H__


#define EMAILNETWAIT		30	/* 30 sec network timeout */


typedef struct _emaildata				/* List of email servers */
{	struct in_addr		ip;
	SOCKET 				mailsocket;
	int					loggedin;
	unsigned short		port;
	char				recipient[STRBUFSIZE+2];
	char				sender[STRBUFSIZE+2];
}	EMAILDATA;


void EmailParse(char *,char *,unsigned long,DATALIST *);
void EmailSend(BLOCKINFO *,void *,unsigned long);
void EmailSendBlockOnly(BLOCKINFO *,void *,unsigned long);

#endif /* __SSP_EMAIL_H__ */

