/* $Id: ssp_ciscoacl.c,v 2.12 2008/04/26 19:53:21 fknobbe Exp $
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
 * ssp_ciscoacl.c 
 * 
 * Purpose:  
 *
 * This SnortSam plugin ciscoacl telnet's into one or more Cisco CISCOACL routers,
 * and issues the blocking ACL statements. SnortSam will also expire the blocks
 * itself since the routers do not have automatic time-out functionality.
 *
 * Comments:
 *
 *
 */


#ifndef		__SSP_CISCOACL_C__
#define		__SSP_CISCOACL_C__


#include "snortsam.h"
#include "ssp_ciscoacl.h"


#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif


/* This routine parses the ciscoacl statements in the config file.
 * It builds a list of ciscoacls)
*/
void
CISCOACLParse(char *val, char *file, unsigned long line, DATALIST * datalistp)
{
    CISCOACLDATA *ciscoaclp;
    char msg[STRBUFSIZE + 1], *p2;
    struct in_addr ciscoaclip;

    char buf[CISCOACLFILELEN + 1], *pp;
    int i, j, change;

    logmessage(3, "Plugin Parsing...", "ciscoacl", 0);

    if(*val) {
	p2 = val;
	while(*p2 && !myisspace(*p2))
	    p2++; /* go to first space */
	if(*p2)
	    *p2++ = 0;

	ciscoaclip.s_addr = getip(val);
	if(ciscoaclip.s_addr) {	/* If we have a valid IP address */
	    ciscoaclp = safemalloc(sizeof(CISCOACLDATA), "CISCOACLParse", "ciscoaclp");	/* create new ciscoacl */
	    datalistp->data = ciscoaclp;
	    ciscoaclp->ip.s_addr = ciscoaclip.s_addr;
	   /* ciscoaclp->username[0] = (char) NULL;
	    ciscoaclp->telnetpw[0] = (char) NULL;
	    ciscoaclp->enablepw[0] = (char) NULL;
	    ciscoaclp->aclfile[0] = (char) NULL;
	    ciscoaclp->ftpfile[0] = (char) NULL;
	    */
	    if(*p2) {
		val = p2;
		while(*val && myisspace(*val))	/* jump spaces */
		    val++;
		if(*val) {
		    p2 = val;
		    while(*p2 && !myisspace(*p2)) /* go to first following space */
			p2++;
		    if(*p2)
			*p2++ = 0;
		    safecopy(buf, val); /* username/password or only telnet password */

		    pp = buf;
		    i=j=0;
		    change = 0;
		    do {
			if(myisspace(*pp))
			    continue;
			if(*pp == '/') {
			    change = 1;
			    continue;
			}
			if(!change)
			    ciscoaclp->username[i++] = *pp;
			else
			    ciscoaclp->telnetpw[j++] = *pp;
		    }
		    while(*(++pp) && !myisspace(*pp));
		    ciscoaclp->username[i] = (char) 0;
		    ciscoaclp->telnetpw[j] = (char) 0;

		    if(*p2) {
			val = p2;
			while(*val && myisspace(*val))	/* jump spaces */
			    val++;
			if(*val) {
			    p2 = val;
			    while(*p2 && !myisspace(*p2))
				p2++;
			    if(*p2)
				*p2++ = 0;
			    safecopy(ciscoaclp->enablepw, val);	/* save enable password */
			}
			if(*p2) {
			    while(*p2 && myisspace(*p2))
				p2++;	/* jump spaces */

			    safecopy(buf, p2);	/* this would be the aclfile name... */

			    pp = buf;
			    i=j=0;
			    change = 0;
			    do {
				if(myisspace(*pp))
				    continue;
				if(*pp == '|') {
				    change = 1;
				    continue;
				}
				if(!change)
				    ciscoaclp->aclfile[i++] = *pp;
				else
				    ciscoaclp->ftpfile[j++] = *pp;
			    }
			    while(*(++pp) && !myisspace(*pp));
			    ciscoaclp->aclfile[i] = (char) 0;
			    ciscoaclp->ftpfile[j] = (char) 0;
			    snprintf(msg, sizeof(msg) - 1, 
				     "Adding CISCOACL: IP \"%s\", UName \"%s\", PW \"%s\", EN \"%s\", ACL \"%s\", FTPFILE \"%s\"",
				     inettoa(ciscoaclp->ip.s_addr),
				     ciscoaclp->username,
				     ciscoaclp->telnetpw,
				     ciscoaclp->enablepw,
				     ciscoaclp->aclfile,
				     ciscoaclp->ftpfile
				);
			    logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr );
			    return;
			} else {
			    snprintf(msg, sizeof(msg) - 1,
				     "Error: [%s: %lu] CISCOACL defined without aclfile name !",
				     file, line);
			    logmessage(1, msg, "ciscoacl", 0);
			    getout(3);
			}
		    } else {
			snprintf(msg, sizeof(msg) - 1,
				 "Error: [%s: %lu] CISCOACL defined without enable passwords!",
				 file, line);
			logmessage(1, msg, "ciscoacl", 0);
			getout(3);
		    }
		} else {
		    snprintf(msg, sizeof(msg) - 1,
			     "Error: [%s: %lu] CISCOACL defined without passwords and ACL-file-name !",
			     file, line);
		    logmessage(1, msg, "ciscoacl", 0);
		    getout(3);
		}
	    } else {
		snprintf(msg, sizeof(msg) - 1,
			 "Error: [%s: %lu] CISCOACL defined without passwords and ACL-file-name !",
			 file, line);
		logmessage(1, msg, "ciscoacl", 0);
		getout(3);
	    }

	    snprintf(msg, sizeof(msg) - 1,
		     "Adding CISCOACL: IP \"%s\", UN \"%s\", PW \"%s\", EN \"%s\", ACL \"%s\", FTPFILE \"%s\"",
		     inettoa(ciscoaclp->ip.s_addr), ciscoaclp->username,
		     ciscoaclp->telnetpw, ciscoaclp->enablepw,
		     ciscoaclp->aclfile, ciscoaclp->ftpfile);
	    logmessage(3, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	} else {
	    snprintf(msg, sizeof(msg) - 1,
		     "Error: [%s: %lu] Invalid CISCOACL parameter '%s' ignored.",
		     file, line, val);
	    logmessage(1, msg, "ciscoacl", 0);
	    getout(3);
	}
    } else {
	snprintf(msg, sizeof(msg) - 1,
		 "Error: [%s: %lu] Empty CISCOACL parameter.", file, line);
	logmessage(1, msg, "ciscoacl", 0);
	getout(3);
    }
}

/* This routine initiates the block. It walks the list of CISCOACL's
 * telnet's in, and issues the blocking ACL statement.
 */
void CISCOACLBlock(BLOCKINFO * bd, void *data,unsigned long qp)
{
    CISCOACLDATA *ciscoaclp;
    struct sockaddr_in thissocketaddr, ciscoaclsocketaddr;
    SOCKET ciscoaclsocket = 0;
    signed long len;
    char msg[STRBUFSIZE + 2];
    struct in_addr blockthis;

    FILE *readfile, *writefile, *writefile_upload, *readftpfile;
    char ace[STRBUFSIZE + 1], buf[STRBUFSIZE + 1];
    char filename_temp[FILEBUFSIZE + 1];
    const char *ciscoaclbegin = "snortsam-ciscoacl-begin";
    const char *ciscoaclend = "snortsam-ciscoacl-end";
    int uzbegin = strlen(ciscoaclbegin), uzend = strlen(ciscoaclend);
    int error, search, present, i, blank, ftp = 0, expect = 0, result = 0;

    /* Holds the expect script's file name, if it's defined in the snortsam config file */
    /* this plugin arranges the ACL file, and then will call this expect script to upload the ACL file */
    char expect_file[STRBUFSIZE + 1];

    /* Copy of the actual ACL file, "snortsam-ciscoacl-begin" and "snortsam-ciscoacl-end" lines are removed */
    /* These two lines are removed in order to avoid errors when uploading this ACL file into the router */
    char aclfile_upload[STRBUFSIZE + 1];
    /* This file will be removed after beeing uploaded into the router */


    if(!data)
	return;			/* if we don't have ciscoacls, we exit */
    ciscoaclp = (CISCOACLDATA *) data;

    snprintf(msg, sizeof(msg) - 1, "Plugin Blocking... block=%d", bd->block);
    logmessage(2, msg, "ciscoacl", 0);

    blockthis.s_addr = bd->blockip;
    snprintf(msg, sizeof(msg) - 1, "deny ip host %s any",
	     inettoa(blockthis.s_addr));
    present = CISCOACLCheck(msg, ciscoaclp->aclfile);	/* check the ACL file if the blocking rule is already applied ? */
    if(present && bd->block) {
	logmessage(3, "already blocked, no thing to do.", "ciscoacl",
		   ciscoaclp->ip.s_addr);
	return;
	/* no need to reapply to this router, continue with the other */
    }
    if(!present && !bd->block) {
	logmessage(3, "This is not blocked, no thing to do.", "ciscoacl",
		   ciscoaclp->ip.s_addr);
	return;
	/* it doesn't exist, so nothing to do */
    }

    if(strlen(ciscoaclp->ftpfile)) {
	ftp = 1;
	if(strstr(ciscoaclp->ftpfile, "expect:")) {
	    /* Remove the "expect:" string from the file name */
	    safecopy(expect_file, &ciscoaclp->ftpfile[strlen("expect:")] );
	    ftp = 2;
	    expect = 1;		/* There is an expect script to call */
	    snprintf(msg, sizeof(msg) - 1, "Expect script name:%s",
		     expect_file);
	    logmessage(1, msg, "ciscoacl", 0);
	    readftpfile = fopen(expect_file, "r");
	    if(!readftpfile) {
		snprintf(msg, sizeof(msg) - 1,
			 "Error: file: %s doesn't exist!", expect_file);
		logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
		return;
	    }
	    fclose(readftpfile);
	} else {
	    readftpfile = fopen(ciscoaclp->ftpfile, "r");
	    if(!readftpfile) {
		snprintf(msg, sizeof(msg) - 1,
			 "Error: file: %s doesn't exist!", ciscoaclp->ftpfile);
		logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
		return;
	    }
	    fclose(readftpfile);
	}
    } else
	ftp = 0;
    /* If there is an expect script to be called, there is no need to connect to the router...
       Otherwise make the telnet connection as usual */
    if(!expect) {
	ciscoaclsocketaddr.sin_port = htons(23);	/* telnet */
	ciscoaclsocketaddr.sin_addr.s_addr = ciscoaclp->ip.s_addr;
	ciscoaclsocketaddr.sin_family = AF_INET;

	thissocketaddr.sin_port = htons(0);	/* get a dynamic port  */
	thissocketaddr.sin_addr.s_addr = 0;
	thissocketaddr.sin_family = AF_INET;

	/* create socket */
	ciscoaclsocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(ciscoaclsocket == INVALID_SOCKET) {
	    snprintf(msg, sizeof(msg) - 1,
		     "Error: [ciscoacl] Couldn't create socket!");
	    logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	    return;
	}
	/* bind it */
	if(bind
	   (ciscoaclsocket, (struct sockaddr *) &(thissocketaddr),
	    sizeof(struct sockaddr))) {
	    snprintf(msg, sizeof(msg) - 1,
		     "Error: [ciscoacl] Couldn't bind socket!");
	    logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	    return;
	}
	/* and connect to ciscoacl */
	if(connect
	   (ciscoaclsocket, (struct sockaddr *) &ciscoaclsocketaddr,
	    sizeof(struct sockaddr))) {
	    snprintf(msg, sizeof(msg) - 1,
		     "Error: [ciscoacl] Could not connect to CISCOACL at %s! Will try later.",
		     inettoa(ciscoaclp->ip.s_addr));
	    logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	    return;
	}

	snprintf(msg, sizeof(msg) - 1, "Connected to CISCOACL at %s.",
		 inettoa(ciscoaclp->ip.s_addr));
	logmessage(2, msg, "ciscoacl", ciscoaclp->ip.s_addr);

	len = 1;

	ioctlsocket(ciscoaclsocket, FIONBIO, &len);	/* set non blocking  */

	if(ciscoaclp->telnetpw[0]) {	/* there are username and password, so apply tacacs+ authentication */
	    if(CISCOACLsendreceive(ciscoaclsocket, "", "Username: ")) {
		closesocket(ciscoaclsocket);
		return;
	    }

	    if(CISCOACLsendreceive
	       (ciscoaclsocket, ciscoaclp->username, "Password: ")) {
		closesocket(ciscoaclsocket);
		return;
	    }

	    if(CISCOACLsendreceive(ciscoaclsocket, ciscoaclp->telnetpw, ">")) {
		closesocket(ciscoaclsocket);
		return;
	    }
	} else {		/* do simple authentication with password */
	    if(CISCOACLsendreceive(ciscoaclsocket, "", "Password: ")) {
		closesocket(ciscoaclsocket);
		return;
	    }

	    if(CISCOACLsendreceive(ciscoaclsocket, ciscoaclp->username, ">")) {
		closesocket(ciscoaclsocket);
		return;
	    }
	}

	if(CISCOACLsendreceive(ciscoaclsocket, "enable", "Password: ")) {
	    closesocket(ciscoaclsocket);
	    return;
	}
	if(CISCOACLsendreceive(ciscoaclsocket, ciscoaclp->enablepw, "#")) {
	    closesocket(ciscoaclsocket);
	    return;
	}
	/* A Telnet connection has been established */
	/* If expect was 0 */
    }

    blockthis.s_addr = bd->blockip;
    snprintf(msg, sizeof(msg) - 1, "deny ip host %s any",
	     inettoa(blockthis.s_addr));
    /* don't search the whole file; search only between snortsam-acl-begin and snortsam-acl-end */
    error = 0;
    present = 0;
    search = 0;

    /* Expect script and tftp will use the file "ciscoaclp->aclfile"_upload */
    snprintf(aclfile_upload, sizeof(aclfile_upload) - 1, "%s_upload",
	     ciscoaclp->aclfile);

    readfile = fopen(ciscoaclp->aclfile, "r");
    if(!readfile) {
	snprintf(msg, sizeof(msg) - 1, "Error: file: %s doesn't exist!",
		 ciscoaclp->aclfile);
	logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	if(!expect)
	    closesocket(ciscoaclsocket);
	return;
    }
    snprintf(filename_temp, sizeof(filename_temp) - 1, "%s-%x%x",
	     ciscoaclp->aclfile, rand() * 65536 + rand(),
	     rand() * 65536 + rand());


    writefile_upload = fopen(aclfile_upload, "w");
    if(!writefile_upload) {
	snprintf(msg, sizeof(msg) - 1, "Error: can not create file: %s !",
		 aclfile_upload);
	logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	fclose(readfile);
	if(!expect)
	    closesocket(ciscoaclsocket);
	return;
    }

    writefile = fopen(filename_temp, "w");
    if(!writefile_upload) {
	snprintf(msg, sizeof(msg) - 1, "Error: can not create file: %s !",
		 ciscoaclp->aclfile);
	logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	fclose(readfile);
	fclose(writefile_upload);
	if(!expect)
	    closesocket(ciscoaclsocket);
	return;
    }


    while(!feof(readfile)) {
	fgets(ace, sizeof(ace) - 1, readfile);
	ace[sizeof(ace) - 1] = 0;
	if(strlen(ace) < 4)
	    continue;		/* skip blank lines */

	/* if the file is created in Linux with the vi editor, lines end with 0x0A newline
	   but if in windows, lines end with 0x0D 0x0A; so, check 0x0D */
	if(ace[strlen(ace) - 2] == (char) 0x0d)
	    ace[strlen(ace) - 2] = (char) 0;	/*  in windows */
	else
	    ace[strlen(ace) - 1] = (char) 0;	/* in Linux with vi */

	blank = 0;		/* skip initial blank characters */
	for(i = 0; i < strlen(ace); i++) {
	    if(myisspace(ace[i]))
		blank++;
	    else
		break;
	}
	safecopy(buf, &ace[blank]);
	safecopy(ace, buf);


	if(!strncmp("snortsam-ciscoacl-begin", ace, uzbegin)) {
	    search = 1;
	    fprintf(writefile, "%s\r\n", ace);
	    ace[0] = (char) 0;
	    continue;
	}

	if(!strncmp("snortsam-ciscoacl-end", ace, uzend)) {
	    search = 0;

	    if(!present && bd->block) {	/* if this ACE doesn't already exist add it. */
		fprintf(writefile, "%s\r\n", msg);
		fprintf(writefile_upload, "%s\r\n", msg);
		if(!ftp)
		    CISCOACLsendreceive(ciscoaclsocket, msg, "#");
	    }

	    fprintf(writefile, "%s\r\n", ace);
	    ace[0] = (char) 0;
	    present = 0;
	    continue;
	}

	if(search)		/* search this ACE if it already exists ? */
	    if(!strcmp(msg, ace))
		present = 1;

	if(!bd->block && present) {
	    ace[0] = (char) 0;
	    present = 0;
	    continue;		/* once we found a match, make present=0 in order to no skip others */
	}

	fprintf(writefile, "%s\r\n", ace);
	fprintf(writefile_upload, "%s\r\n", ace);

	if(!ftp) {
	    logmessage(2, "sending command to the router...", "ciscoacl",
		       ciscoaclp->ip.s_addr);

	    if(CISCOACLsendreceive(ciscoaclsocket, ace, "#")) {
		error = 1;
		break;
	    }
	}

	ace[0] = (char) 0;
    }


    if(error) {
	snprintf(msg, sizeof(msg) - 1,
		 "Error: [ciscoacl] Did not receive a response from CISCOACL at %s (wait for # prompt), and skipping to the next router, check acl_temp file!!!",
		 inettoa(ciscoaclp->ip.s_addr));
	logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	fclose(readfile);
	fclose(writefile);
	fclose(writefile_upload);
	if(!expect)
	    closesocket(ciscoaclsocket);
	return;
    }

    fclose(readfile);
    fclose(writefile);
    fclose(writefile_upload);
    unlink(ciscoaclp->aclfile);
    rename(filename_temp, ciscoaclp->aclfile);

#ifndef WIN32
    /* Changes permissions of the aclfile to make it readable by the tftp daemon */
    chmod(ciscoaclp->aclfile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
    if(expect) {
	snprintf(msg, sizeof(msg) - 1, "%s>>/var/log/snortsam_expect.log",
		 expect_file);
	result = system(msg);
	logmessage(1, "expect script has been executed", "ciscoacl",
		   ciscoaclp->ip.s_addr);
	snprintf(msg, sizeof(msg) - 1, "Expect return code:%d", result);
	logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	unlink(aclfile_upload);	/* Remove the temporary upload file */

    } else if(ftp) {
	readftpfile = fopen(ciscoaclp->ftpfile, "r");

	while(!feof(readftpfile)) {
	    fgets(ace, sizeof(ace) - 1, readftpfile);
	    ace[sizeof(ace) - 1] = 0;
	    if(strlen(ace) < 4)
		continue;	/* skip blank lines */

	    /* if the file is created in Linux with the vi editor, lines end with 0x0A newline
	       but if in windows, lines end with 0x0D 0x0A; so, check 0x0D */
	    if(ace[strlen(ace) - 2] == (char) 0x0d)
		ace[strlen(ace) - 2] = (char) 0;	/*  in windows */
	    else
		ace[strlen(ace) - 1] = (char) 0;	/* in Linux with vi */

	    blank = 0;		/* skip initial blank characters */
	    for(i = 0; i < strlen(ace); i++) {
		if(myisspace(ace[i]))
		    blank++;
		else
		    break;
	    }
	    safecopy(buf, &ace[blank]);
	    safecopy(ace, buf);


	    logmessage(2, "sending command to the router...", "ciscoacl",
		       ciscoaclp->ip.s_addr);

	    if(CISCOACLsendreceive(ciscoaclsocket, ace, "]? ")) {
		error = 1;
		break;
	    }

	    ace[0] = (char) 0;
	}

	fclose(readftpfile);

	if(!error)		// if there is no error send the last two answers
	{
	    if(CISCOACLsendreceive(ciscoaclsocket, ciscoaclp->aclfile, "]? "))
		error = 1;
	    else if(CISCOACLsendreceive(ciscoaclsocket, "running-config", "#"))
		error = 1;
	}
	if(error) {
	    snprintf(msg, sizeof(msg) - 1,
		     "Error: [ciscoacl] Did not receive a response from CISCOACL at %s, and skipping to the next router, check %s file!!!",
		     inettoa(ciscoaclp->ip.s_addr), ciscoaclp->ftpfile);
	    logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
	    fclose(readftpfile), closesocket(ciscoaclsocket);
	    return;
	}
    }

    if(!expect)
	closesocket(ciscoaclsocket);	/* If there is an expect script, a telnet connection 
					   hasn't been established, so there is not any open socket to close */

    snprintf(msg, sizeof(msg) - 1,
	     "Uploading has finished and disconnected from the router:%s",
	     inettoa(ciscoaclp->ip.s_addr));
    logmessage(1, msg, "ciscoacl", ciscoaclp->ip.s_addr);
    logmessage(3, "Return from ciscoacl Blocking function", "ciscoacl", 0);
}



/* 
 * 
 */
int CISCOACLCheck(char *message, char *filename)
{
    char msg[STRBUFSIZE + 1];

    FILE *readfile;
    char ace[STRBUFSIZE + 1], buf[STRBUFSIZE + 1];
    const char *ciscoaclbegin = "snortsam-ciscoacl-begin";
    const char *ciscoaclend = "snortsam-ciscoacl-end";
    int uzbegin = strlen(ciscoaclbegin), uzend =
	strlen(ciscoaclend), search = 1, present = 0, i, blank;

    readfile = fopen(filename, "r");
    if(!readfile) {
	puts("hata: dosya yok !");
	return 0;
    }

    snprintf(msg, sizeof(msg) - 1, "ACL existence check:%s", message);
    logmessage(1, msg, "ciscoacl", 0);

    while(!feof(readfile)) {
	fgets(ace, sizeof(ace) - 1, readfile);
	ace[sizeof(ace) - 1] = 0;
	if(strlen(ace) < 4)
	    continue;		/* skip blank lines */

	/* if the file is created in Linux with the vi editor, lines end with 0x0A newline
	   but if in windows, lines end with 0x0D 0x0A; so, check 0x0D */
	if(ace[strlen(ace) - 2] == (char) 0x0d)
	    ace[strlen(ace) - 2] = (char) 0;	/*  in windows */
	else
	    ace[strlen(ace) - 1] = (char) 0;	/* in Linux with vi */

	blank = 0;		/* skip inital blank characters */
	for(i = 0; i < strlen(ace); i++) {
	    if(myisspace(ace[i]))
		blank++;
	    else
		break;
	}
	safecopy(buf, &ace[blank]);
	safecopy(ace, buf);

	if(!strncmp("snortsam-ciscoacl-begin", ace, uzbegin)) {
	    search = 1;
	    ace[0] = (char) 0;
	    continue;
	}

	if(!strncmp("snortsam-ciscoacl-end", ace, uzend)) {
	    break;
	}

	if(search)		/*  search this ACE if it already exists ? */
	    if(!strcmp(message, ace)) {
		present = 1;
		break;
	    }
	ace[0] = (char) 0;
    }

    fclose(readfile);
    if(present)
	logmessage(1, "Present", "ciscoacl", 0);
    else
	logmessage(1, "Not Present", "ciscoacl", 0);
    return present;
}



int CISCOACLsendreceive(SOCKET ciscoaclsocket, char *message, char *receive)
{
    signed long len;
    char msg[STRBUFSIZE + 1], buf[STRBUFSIZE + 1];

    if(*message) {
	snprintf(msg, sizeof(msg) - 1, "%s\r", message);	/* send  */
	len = strlen(msg);

	snprintf(buf, sizeof(buf) - 1, "Sending:%s", msg);
	logmessage(3, buf, "ciscoacl", 0);

	if(send(ciscoaclsocket, msg, len, 0) != len) {	/* weird...could not send */
	    snprintf(msg, sizeof(msg) - 1,
		     "Error: [ciscoacl] Could not send to CISCOACL at %s !",
		     message);
	    logmessage(1, msg, "ciscoacl", 0);
	    return 1;
	}
    }

    if(*receive) {
	snprintf(buf, sizeof(buf) - 1, "Receiving: --%s--", receive);
	logmessage(3, buf, "ciscoacl", 0);

	if(!waitfor(ciscoaclsocket, receive, CISCOACLNETWAIT)) {	/* wait for prompt */
	    snprintf(msg, sizeof(msg) - 1,
		     "Error: [ciscoacl] Did not receive a response from CISCOACL at %s !",
		     receive);
	    logmessage(1, msg, "ciscoacl", 0);
	    return 1;
	}
    }

    return 0;
}

#endif				/* __SSP_CISCOACL_C__ */
