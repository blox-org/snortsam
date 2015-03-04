/* $Id: showblocks.c,v 1.2 2009/04/15 21:02:20 fknobbe Exp $
 *
 *
 * Copyright (c) 2005 Frank Knobbe <frank@knobbe.us>
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
 * showblocks
 *
 * Purpose:
 *
 * showblocks is a quick hack that reads out the Snortsam state file and
 * prints information about current blocks on the screen. It should be
 * easy to parse with custom tools since the fields are delimited while
 * still easy to view on screen.
 *
*/

#include "../src/snortsam.h"
#include <stdio.h>


char *inettoa(unsigned long ip)
{	struct in_addr ips;
	static char addr[256][20];
	static unsigned char toggle;

	ips.s_addr=ip;
	toggle=(toggle+1)&255;
	strncpy(addr[toggle],inet_ntoa(ips),18);
	addr[toggle][18]=0;
	return addr[toggle];
}

int main(int argc, char **argv)
{	int i=0;
	FILE *fp;
	char buf[STRBUFSIZE+2],histversion=-1,buf2[STRBUFSIZE+2],buf3[STRBUFSIZE+2];
	BLOCKINFO blockinfo;
	OLDBLOCKINFO obi;
	time_t now,b2,b3;
	struct protoent *protoe;
	unsigned long remaining;
	
	
		printf("Checking for existing state file: ");
		fp=fopen(FWSAMHISTORYFILE,"rb");		/* We check if a state file is present (check new location first) */
		if(!fp)
			printf("Not present.\n");
		else
		{	printf("Present. Reading state.\n");
			do
			{		
				if(histversion== -1)		/* If we don't know yet what version the file is... */
				{	fread(buf,6,1,fp);		/* ...read first 6 bytes and check. */
					buf[6]=0;
					if(!strncmp(buf,FWSAMHISTORYVERSION,4)) /* If it has a header... */
						histversion=atoi(buf+4);			/* ...note the version. */
					else
					{	histversion=0;						/* If it doesn't, it's old-style */
						rewind(fp);							/* Since the old version didn't have a header, rewind file. */
					}
				}
				switch(histversion)
				{	case 0:		i=fread(&obi,sizeof(OLDBLOCKINFO),1,fp);
								if(i==1)
								{	blockinfo.blockip=obi.blockip;
									blockinfo.peerip=obi.peerip;
									blockinfo.duration=obi.duration;
									blockinfo.blocktime=obi.blocktime;
									blockinfo.port=obi.port;
									blockinfo.proto=obi.proto;
									blockinfo.mode=obi.mode;
									blockinfo.block=obi.block;
									blockinfo.sig_id=0;
								}
								break;
					case 1:		i=fread(&blockinfo,sizeof(BLOCKINFO),1,fp);
								break;
				}
				if(i==1) /* Read in one history element */
				{
								now=time(NULL);
							
								if(blockinfo.duration)
									remaining=(blockinfo.blocktime+blockinfo.duration-now); 
								b2=blockinfo.blocktime;
								b3=b2+blockinfo.duration;
								strcpy(buf2,ctime(&b2));
								buf2[strlen(buf2)-1]=0;
								strcpy(buf3,ctime(&b3));
								buf3[strlen(buf3)-1]=0;
								printf("%-15s | Blocked: %s | Expires: %s | Left: %lu\n",inettoa(blockinfo.blockip),buf2,buf3,remaining);
							
				}
				else
				{	fclose(fp);		/* if there is no more data, close file. */				
					fp=NULL;
				}
			}while(fp);
		}			
	return 0;
}
