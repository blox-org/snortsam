/* $Id: ssp_pix.h,v 2.5 2008/04/26 19:53:21 fknobbe Exp $
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
 * Acknowledgements:
 *
 * Thanks to Aaron Carr for letting me use his PIX and making test machines
 * accessible.
 *
 *
 *
 * ssp_pix.h 
 * 
 * Purpose:  
 *
 * This SnortSam plugin telnet's into one or more Cisco PIX firewalls,
 * and issues the shun command. SnortSam will also expire the blocks
 * itself since the PIX does not have automatic time-out functionality.
 *
 *
 */


#ifndef		__SSP_PIX_H__
#define		__SSP_PIX_H__


#define PIXPWLEN		50			/* Maximum password length */
#define PIXNETWAIT		20			/* Network timeout in sec */


typedef struct _pixdata				/* List of PIX firewalls */
{	struct 			in_addr	ip;
	SOCKET 			pixsocket;
	int				userlogin;
	int 			loggedin;
	char			*telnetpw;
	char			username[(PIXPWLEN+1)*2];
	char			enablepw[PIXPWLEN+1];
}	PIXDATA;


void PIXParse(char *,char *,unsigned long,DATALIST *);
void PIXBlock(BLOCKINFO *,void *,unsigned long);

#endif /* __SSP_PIX_H__ */

