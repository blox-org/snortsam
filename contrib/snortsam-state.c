///////////////////////////////////////////////////////////////////////////////
//
// SnortSam State
// -Display binary SnortSam state file in delimited form.
// -Delete SnortSam blocks.  If SnortSam is running, then we as SnortSam to
//  do the unblock.  If it's not running, we manipulate the state file ourself.
//
// $Id: snortsam-state.c,v 1.1 2005/07/26 17:51:51 fknobbe Exp $
//
///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2001-2005 Frank Knobbe <frank@knobbe.us>
// Copyright (c) 2005 Point Clark Networks <darryl@pointclark.net>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
///////////////////////////////////////////////////////////////////////////////

#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>		

#include "twofish.h"
#include "snortsam.h"

extern int errno;
extern int h_errno;

static int verbose = 0;

static unsigned long const crctab[256] =
{
	0x0,
	0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B,
	0x1A864DB2, 0x1E475005, 0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6,
	0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
	0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC,
	0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8, 0x6ED82B7F,
	0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A,
	0x745E66CD, 0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039,
	0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0xBE2B5B58,
	0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033,
	0xA4AD16EA, 0xA06C0B5D, 0xD4326D90, 0xD0F37027, 0xDDB056FE,
	0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
	0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4,
	0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D, 0x34867077, 0x30476DC0,
	0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5,
	0x2AC12072, 0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16,
	0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA, 0x7897AB07,
	0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C,
	0x6211E6B5, 0x66D0FB02, 0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1,
	0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
	0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B,
	0xBB60ADFC, 0xB6238B25, 0xB2E29692, 0x8AAD2B2F, 0x8E6C3698,
	0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D,
	0x94EA7B2A, 0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E,
	0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2, 0xC6BCF05F,
	0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34,
	0xDC3ABDED, 0xD8FBA05A, 0x690CE0EE, 0x6DCDFD59, 0x608EDB80,
	0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
	0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A,
	0x58C1663D, 0x558240E4, 0x51435D53, 0x251D3B9E, 0x21DC2629,
	0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C,
	0x3B5A6B9B, 0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF,
	0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623, 0xF12F560E,
	0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65,
	0xEBA91BBC, 0xEF68060B, 0xD727BBB6, 0xD3E6A601, 0xDEA580D8,
	0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
	0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2,
	0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B, 0x9B3660C6, 0x9FF77D71,
	0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74,
	0x857130C3, 0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640,
	0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21,
	0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A,
	0x61043093, 0x65C52D24, 0x119B4BE9, 0x155A565E, 0x18197087,
	0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
	0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D,
	0x2056CD3A, 0x2D15EBE3, 0x29D4F654, 0xC5A92679, 0xC1683BCE,
	0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB,
	0xDBEE767C, 0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18,
	0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4, 0x89B8FD09,
	0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662,
	0x933EB0BB, 0x97FFAD0C, 0xAFB010B1, 0xAB710D06, 0xA6322BDF,
	0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4
};

static unsigned long cksum(unsigned char *data, long length)
{
	long bytes = length;
	unsigned long crc = 0;
	unsigned char *cp = data;

	while(bytes--)
		crc = (crc << 8) ^ crctab[((crc >> 24) ^ *(cp++)) & 0xFF];

	bytes = length;

	while(bytes > 0)
	{
		crc = (crc << 8) ^ crctab[((crc >> 24) ^ bytes) & 0xFF];

		bytes >>= 8;
	}

	crc = ~crc & 0xFFFFFFFF;

	return crc;
}

static pid_t pidof(void)
{
	FILE *p;
	pid_t pid = -1;
	char *cmd = { "pidof snortsam" };

	if((p = popen(cmd, "r")))
	{
		fscanf(p, "%d", &pid);
		if(pclose(p) != 0) return -1;
	}

	return pid;
}

static int my_rename(const char *name, const char *old, const char *new)
{
	struct stat st;
	int chunk = getpagesize();
	u_char *buffer;
	int fd_in, fd_out, rc = 0;

	if(rename(old, new) == 0) return 0;

	if(errno != EXDEV)
	{
		fprintf(stderr, "%s: can't rename %s to %s: %s.\n", 
			name, old, new, strerror(errno));
		return -1;
	}

	if((fd_in = open(old, O_RDONLY)) == -1)
	{
		fprintf(stderr, "%s: can't open: %s: %s\n", name, old, strerror(errno));
		return -1;
	}

	if(fstat(fd_in, &st) == -1)
	{
		fprintf(stderr, "%s: can't stat: %s: %s.\n", name, old, strerror(errno));
		return -1;
	}

	if((fd_out = open(new, O_CREAT | O_WRONLY, st.st_mode)) == -1)
	{
		fprintf(stderr, "%s: can't open: %s: %s\n", name, new, strerror(errno));
		return -1;
	}

	buffer = malloc(chunk);

	while(buffer)
	{
		ssize_t bytes;

		if((bytes = read(fd_in, buffer, chunk)) == -1)
		{
			fprintf(stderr, "%s: can't read: %s: %s.\n", name, old, strerror(errno));
			rc = -1; break;
		}

		if(!bytes) break;

		if(write(fd_out, buffer, bytes) != bytes)
		{
			fprintf(stderr, "%s: can't write: %s: %s.\n", name, new, strerror(errno));
			rc = -1; break;
		}
	}

	close(fd_in);
	close(fd_out);
	free(buffer);

	if(rc == 0)
	{
		if(verbose) fprintf(stderr, "%s: renamed %s as %s.\n", name, old, new);
		unlink(old);
	}

	return rc;
}

static void ipt_unblock(const char *name, const char *conf, const BLOCKINFO *bi)
{
	struct in_addr addr;
	FILE *h = fopen(conf, "r");
	char buffer[80], iface[IFNAMSIZ + 1];

	if(!h)
	{
		fprintf(stderr, "%s: can't open SnortSam configuration: %s: %s.\n",
			name, conf, strerror(errno));
		return;
	}

	memset(iface, 0, IFNAMSIZ + 1);
	memset(buffer, 0, sizeof(buffer));

	while(fgets(buffer, sizeof(buffer) - 1, h))
	{
		if(sscanf(buffer, "iptables %s", iface) == 1) break;
	}

	fclose(h);

	if(!strnlen(iface, IFNAMSIZ))
	{
		fprintf(stderr, "%s: can't find iptables interface in: %s\n", name, conf);
		return;
	}

	addr.s_addr = bi->blockip;

	sprintf(buffer, "/sbin/iptables -D INPUT -i %s -s %s -j DROP",
		iface, inet_ntoa(addr));

	if(!(h = popen(buffer, "r")) || pclose(h) != 0)
		fprintf(stderr, "%s: failed: %s\n", name, buffer);

	sprintf(buffer, "/sbin/iptables -D FORWARD -i %s -s %s -j DROP",
		iface, inet_ntoa(addr));

	if(!(h = popen(buffer, "r")) || pclose(h) != 0)
		fprintf(stderr, "%s: failed: %s\n", name, buffer);

	return;
}

// 100th of a second. 60 sec timeout for holding
#define FWSAM_NETHOLD			6000
// 100th of a second. 3 sec timeout for network connections
#define FWSAM_NETWAIT			300

// A SnortSam station
typedef struct FWsamStation_t
{
	unsigned short myseqno;
	unsigned short stationseqno;
	unsigned char mykeymod[4];
	unsigned char fwkeymod[4];
	unsigned short stationport;
	struct in_addr stationip;
	struct sockaddr_in localsocketaddr;
	struct sockaddr_in stationsocketaddr;
	TWOFISH *stationfish;
	char initialkey[TwoFish_KEY_LENGTH + 2];
	char stationkey[TwoFish_KEY_LENGTH + 2];
	time_t lastcontact;
} FWsamStation;

// Create a new station structure
static FWsamStation *station_init(const char *host, u_short port, const char *pass)
{
	struct hostent *he;
	unsigned long ip;

	FWsamStation *station = NULL;

	if(inet_addr(host) == INADDR_NONE)
	{
		if(!(he = gethostbyname(host)))
		{
			fprintf(stderr, "%s: Invalid host: %s: %s\n", __func__, host, hstrerror(h_errno));
			return NULL;
		}
		else ip = *(unsigned long *)he->h_addr;
	} 
	else if(!(ip = inet_addr(host)))
	{
			fprintf(stderr, "%s: Invalid IP address: %s\n", __func__, host);
			return NULL;
	}

	if((station = (FWsamStation *)malloc(sizeof(FWsamStation))) == NULL)
	{
		fprintf(stderr, "%s: malloc failed for station: %s.\n", __func__, strerror(errno));
		return NULL;
	}

	station->stationip.s_addr = ip;

	if(port > 0)
		station->stationport = port;
	else
		station->stationport = FWSAM_DEFAULTPORT;

	if(pass == NULL)
		station->stationkey[0] = 0;
	else
		strncpy(station->stationkey, pass, TwoFish_KEY_LENGTH);

	station->stationkey[TwoFish_KEY_LENGTH] = 0;

	strcpy(station->initialkey, station->stationkey);
	station->stationfish = TwoFishInit(station->stationkey);

	station->localsocketaddr.sin_port = htons(0);
	station->localsocketaddr.sin_addr.s_addr = 0;
	station->localsocketaddr.sin_family = AF_INET;
	station->stationsocketaddr.sin_port = htons(station->stationport);
	station->stationsocketaddr.sin_addr = station->stationip;
	station->stationsocketaddr.sin_family = AF_INET;

	do
		station->myseqno = rand();
	while(station->myseqno < 20 || station->myseqno > 65500);

	station->stationseqno = 0;

	station->mykeymod[0] = rand();
	station->mykeymod[1] = rand();
	station->mykeymod[2] = rand();
	station->mykeymod[3] = rand();

	return station;
}

// Generates a new encryption key based on seq numbers and a random that the
// SnortSam agents send on checkin (in protocol).
static void station_new_key(FWsamStation *station, FWsamPacket *packet)
{
	int i;
	unsigned char newkey[TwoFish_KEY_LENGTH + 2];

	newkey[0] = packet->snortseqno[0];		// current snort seq # (which both know)
	newkey[1] = packet->snortseqno[1];			
	newkey[2] = packet->fwseqno[0];			// current SnortSam seq # (which both know)
	newkey[3] = packet->fwseqno[1];
	newkey[4] = packet->protocol[0];		// the random SnortSam chose
	newkey[5] = packet->protocol[1];

	strncpy(newkey + 6, station->stationkey, TwoFish_KEY_LENGTH - 6); // append old key
	newkey[TwoFish_KEY_LENGTH] = 0;

	newkey[0] ^= station->mykeymod[0];		// modify key with key modifiers which were
	newkey[1] ^= station->mykeymod[1];		// exchanged during the check-in handshake.
	newkey[2] ^= station->mykeymod[2];
	newkey[3] ^= station->mykeymod[3];
	newkey[4] ^= station->fwkeymod[0];
	newkey[5] ^= station->fwkeymod[1];
	newkey[6] ^= station->fwkeymod[2];
	newkey[7] ^= station->fwkeymod[3];

	for(i = 0; i <= 7; i++) if(newkey[i] == 0) newkey[i]++;

	strcpy(station->stationkey, newkey);
	TwoFishDestroy(station->stationfish);
	station->stationfish = TwoFishInit(newkey);
}

// This routine registers this Snort sensor with SnortSam.
// It will also change the encryption key based on some variables.
static int station_check_in(FWsamStation *station)
{
	int i = TRUE, len;
	SOCKET stationsocket;
	FWsamPacket sampacket;
	unsigned char *encbuf, *decbuf;

	if((stationsocket = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) == INVALID_SOCKET)
	{
		fprintf(stderr, "%s: Funky socket error (socket)!\n", __func__);
		return -1;
	}

	if(bind(stationsocket, (struct sockaddr *)&(station->localsocketaddr), sizeof(struct sockaddr)))
	{
		fprintf(stderr, "%s: Could not bind socket!\n", __func__);
		return -1;
	}

	if(connect(stationsocket, (struct sockaddr *)&station->stationsocketaddr, sizeof(struct sockaddr)))
	{
		fprintf(stderr, "%s: Could not connect to host %s.\n", __func__, inet_ntoa(station->stationip));
		return -1;
	}

	// build the packet
	sampacket.endiancheck = 1;
	sampacket.snortseqno[0] = (char)station->myseqno;
	sampacket.snortseqno[1] = (char)(station->myseqno >> 8);
	sampacket.status = FWSAM_STATUS_CHECKIN;
	sampacket.version = FWSAM_PACKETVERSION;
	memcpy(sampacket.duration, station->mykeymod, 4);

	encbuf = TwoFishAlloc(sizeof(FWsamPacket), FALSE, FALSE, station->stationfish);
	len = TwoFishEncrypt((char *)&sampacket, (char **)&encbuf, sizeof(FWsamPacket), FALSE, station->stationfish);

	if(send(stationsocket, encbuf, len, 0) != len)
	{
		fprintf(stderr, "%s: Could not send to host %s.\n", __func__, inet_ntoa(station->stationip));
		free(encbuf);
		return -1;
	}

	i = FWSAM_NETWAIT;
	ioctl(stationsocket, FIONBIO, &i);

	while(i-- > 1)
	{
		waitms(10);
		if(recv(stationsocket, encbuf, len, 0) == len) i = 0;
	}

	if(!i)
	{
		fprintf(stderr, "%s: Did not receive response from host %s.\n", __func__, inet_ntoa(station->stationip));
		close(stationsocket);
		free(encbuf);
		return -1;
	}

	decbuf = (char *)&sampacket;
	len = TwoFishDecrypt(encbuf, (char **)&decbuf, sizeof(FWsamPacket) + TwoFish_BLOCK_SIZE, FALSE, station->stationfish);

	if(len == sizeof(FWsamPacket))
	{	
		if(sampacket.version != FWSAM_PACKETVERSION)
		{
			fprintf(stderr, "%s: Protocol version error from host %s.\n", __func__, inet_ntoa(station->stationip));
			close(stationsocket);
			free(encbuf);
			return -1;
		}

		if(sampacket.status == FWSAM_STATUS_OK ||
			sampacket.status == FWSAM_STATUS_NEWKEY || sampacket.status == FWSAM_STATUS_RESYNC)
		{
			station->stationseqno = sampacket.fwseqno[0] | (sampacket.fwseqno[1] << 8);
			station->lastcontact = (unsigned long)time(NULL);
						
			if(sampacket.status == FWSAM_STATUS_NEWKEY || sampacket.status == FWSAM_STATUS_RESYNC)
			{
				memcpy(station->fwkeymod, sampacket.duration, 4);
				station_new_key(station, &sampacket);
			}
		}
		else
		{
			fprintf(stderr, "%s: Funky handshake error from host %s.\n", __func__, inet_ntoa(station->stationip));
			close(stationsocket);
			free(encbuf);
			return -1;
		}
	}
	else
	{
		fprintf(stderr, "%s: Password mismatch from host %s.\n", __func__, inet_ntoa(station->stationip));
		close(stationsocket);
		free(encbuf);
		return -1;
	}

	free(encbuf);
	close(stationsocket);
	return 0;
}

// De-register ourself from the list of sensors that SnortSam keeps. 
static int station_check_out(FWsamStation *station)
{
	int i = 1,len;
	FWsamPacket sampacket;
	SOCKET stationsocket;
	unsigned char *encbuf,*decbuf;

	if((stationsocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	{
		fprintf(stderr, "%s: Funky socket error (socket)!\n", __func__);
		return -1;
	}

	if(bind(stationsocket, (struct sockaddr *)&(station->localsocketaddr), sizeof(struct sockaddr)))
	{
		fprintf(stderr, "%s: Could not bind socket!\n", __func__);
		close(stationsocket);
		return -1;
	}

	if(!connect(stationsocket, (struct sockaddr *)&station->stationsocketaddr, sizeof(struct sockaddr)))
	{
		// build the packet
		station->myseqno += station->stationseqno;

		sampacket.endiancheck=1;
		sampacket.snortseqno[0] = (char)station->myseqno;
		sampacket.snortseqno[1] = (char)(station->myseqno>>8);
		sampacket.fwseqno[0] = (char)station->stationseqno;
		sampacket.fwseqno[1] = (char)(station->stationseqno>>8);
		sampacket.status = FWSAM_STATUS_CHECKOUT;
		sampacket.version = FWSAM_PACKETVERSION;

		encbuf = TwoFishAlloc(sizeof(FWsamPacket), FALSE, FALSE, station->stationfish);
		len = TwoFishEncrypt((char *)&sampacket, (char **)&encbuf, sizeof(FWsamPacket), FALSE, station->stationfish);

		if(send(stationsocket, encbuf, len, 0) != len)
		{
			fprintf(stderr, "%s: Error sending packet to host %s.\n", __func__, inet_ntoa(station->stationip));
			free(encbuf);
			close(stationsocket);
			return -1;
		}

		i = FWSAM_NETWAIT;
		ioctl(stationsocket, FIONBIO, &i);

		while(i-- > 1)
		{
			waitms(10);
			if(recv(stationsocket, encbuf, len, 0) == len) i = 0;
		}

		if(i)
		{
			decbuf = (char *)&sampacket;
			len = TwoFishDecrypt(encbuf, (char **)&decbuf, sizeof(FWsamPacket) + TwoFish_BLOCK_SIZE, FALSE, station->stationfish);

			// Invalid decryption?
			if(len != sizeof(FWsamPacket))
			{
				if(verbose)
					fprintf(stderr, "%s: Trying initial key!\n", __func__);
				
				strcpy(station->stationkey, station->initialkey);
				TwoFishDestroy(station->stationfish);
				station->stationfish = TwoFishInit(station->stationkey);
				len = TwoFishDecrypt(encbuf, (char **)&decbuf, sizeof(FWsamPacket) + TwoFish_BLOCK_SIZE, FALSE, station->stationfish);
			}

			if(len == sizeof(FWsamPacket))
			{
					// but don't really care since we are on the way out
					if(sampacket.version != FWSAM_PACKETVERSION)
					fprintf(stderr, "%s: Protocol version error! What the hell, we're quitting anyway! :)\n", __func__);
			}
			else fprintf(stderr, "%s: Password mismatch! What the hell, we're quitting anyway! :)\n", __func__);
		}

		free(encbuf);
	}
	else fprintf(stderr, "%s: Could not connect to host %s for check out. What the hell, we're quitting anyway! :)\n",
		__func__, inet_ntoa(station->stationip));

	close(stationsocket);

	return 0;
}

// Ask SnortSam to perform an unblock
static int station_unblock(FWsamStation *station, const BLOCKINFO *bi)
{
	int i = 1, len;
	SOCKET stationsocket;
	FWsamPacket sampacket;
	unsigned char *encbuf, *decbuf;
	static int retries = 0;

	// create a socket for the station
	if((stationsocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	{
		fprintf(stderr, "%s: Funky socket error (socket)!\n", __func__);
		return -1;
	}

	if(bind(stationsocket, (struct sockaddr *)&(station->localsocketaddr), sizeof(struct sockaddr)))
	{
		fprintf(stderr, "%s: Could not bind socket!\n", __func__);
		return -1;
	}
	
	if(connect(stationsocket, (struct sockaddr *)&station->stationsocketaddr, sizeof(struct sockaddr)))
	{
		fprintf(stderr, "%s: Could not send block to host %s.\n", __func__, inet_ntoa(station->stationip));
		close(stationsocket);
		return -1;
	}

	// increase my seqno by adding agent seq no
	station->myseqno += station->stationseqno;

	// build the packet
	sampacket.endiancheck = 1;								// This is an endian indicator for Snortsam
	sampacket.snortseqno[0] = (char)station->myseqno;
	sampacket.snortseqno[1] = (char)(station->myseqno >> 8);
	sampacket.fwseqno[0] = (char)station->stationseqno;		// fill station sequence number
	sampacket.fwseqno[1] = (char)(station->stationseqno >> 8);	
	sampacket.status = FWSAM_STATUS_UNBLOCK;				// set unblock mode
	sampacket.version = FWSAM_PACKETVERSION;				// set packet version

	sampacket.duration[0] = (char)bi->duration;				// set duration 
	sampacket.duration[1] = (char)(bi->duration >> 8);
	sampacket.duration[2] = (char)(bi->duration >> 16);
	sampacket.duration[3] = (char)(bi->duration >> 24);

	sampacket.fwmode = bi->mode;

	sampacket.dstip[0] = (char)bi->peerip;
	sampacket.dstip[1] = (char)(bi->peerip >> 8);
	sampacket.dstip[2] = (char)(bi->peerip >> 16);
	sampacket.dstip[3] = (char)(bi->peerip >> 24);
	sampacket.srcip[0] = (char)bi->blockip;
	sampacket.srcip[1] = (char)(bi->blockip >> 8);
	sampacket.srcip[2] = (char)(bi->blockip >> 16);
	sampacket.srcip[3] = (char)(bi->blockip >> 24);

	sampacket.protocol[0] = (char)bi->proto;
	sampacket.protocol[1] = (char)(bi->proto >> 8);

	if(bi->proto == IPPROTO_TCP || bi->proto == IPPROTO_UDP)
	{
		sampacket.srcport[0] = (char)bi->port;
		sampacket.srcport[1] = (char)(bi->port >> 8);
		sampacket.dstport[0] = (char)bi->port;
		sampacket.dstport[1] = (char)(bi->port >> 8);
	} 
	else
		sampacket.srcport[0] = sampacket.srcport[1] = sampacket.dstport[0] = sampacket.dstport[1] = 0;

	// set signature ID
	sampacket.sig_id[0] = (char)bi->sig_id;
	sampacket.sig_id[1] = (char)(bi->sig_id >> 8);
	sampacket.sig_id[2] = (char)(bi->sig_id >> 16);
	sampacket.sig_id[3] = (char)(bi->sig_id >> 24);

	// encrypt and send packet
	encbuf = TwoFishAlloc(sizeof(FWsamPacket), FALSE, FALSE, station->stationfish);
	len = TwoFishEncrypt((char *)&sampacket, (char **)&encbuf, sizeof(FWsamPacket), FALSE, station->stationfish);

	if(send(stationsocket, encbuf, len, 0) != len)
	{	
		fprintf(stderr, "%s: Could not send to host %s.\n", __func__, inet_ntoa(station->stationip));
		close(stationsocket);
		free(encbuf);
		return -1;
	}

	i = FWSAM_NETWAIT;
	ioctl(stationsocket, FIONBIO, &i);

	while(i-- > 1)
	{
		waitms(10);
		if(recv(stationsocket, encbuf, len, 0) == len) i = 0;
	}

	if(!i)
	{	
		fprintf(stderr, "%s: Did not receive response from host %s\n", __func__, inet_ntoa(station->stationip));
		close(stationsocket);
		free(encbuf);
		return -1;
	}

	// got a packet
	decbuf = (char *)&sampacket;
	len = TwoFishDecrypt(encbuf, (char **)&decbuf, sizeof(FWsamPacket) + TwoFish_BLOCK_SIZE, FALSE, station->stationfish);

	// invalid decryption?
	if(len != sizeof(FWsamPacket))
	{
		if(verbose)
			fprintf(stderr, "%s: Trying initial key!\n", __func__);
		
		strcpy(station->stationkey, station->initialkey);
		TwoFishDestroy(station->stationfish);
		station->stationfish = TwoFishInit(station->stationkey);
		len = TwoFishDecrypt(encbuf, (char **)&decbuf, sizeof(FWsamPacket) + TwoFish_BLOCK_SIZE, FALSE, station->stationfish);
	}

	// invalid decryption?
	if(len != sizeof(FWsamPacket))
	{
		fprintf(stderr, "%s: Decryption failed!\n", __func__);
		close(stationsocket);
		free(encbuf);
		return -1;
	}
		
	// version check
	if(sampacket.version != FWSAM_PACKETVERSION)
	{
		fprintf(stderr, "%s: Version mismatch!\n", __func__);
		close(stationsocket);
		free(encbuf);
		return -1;
	}

	switch(sampacket.status)
	{
	case FWSAM_STATUS_OK:
	case FWSAM_STATUS_NEWKEY:
	case FWSAM_STATUS_RESYNC:
	case FWSAM_STATUS_HOLD:
		station->lastcontact = (unsigned long)time(NULL);
		station->stationseqno = sampacket.fwseqno[0] | (sampacket.fwseqno[1] << 8);

		if(sampacket.status == FWSAM_STATUS_HOLD)
		{
			// stay on hold for a maximum of FWSAM_NETHOLD secs
			i = FWSAM_NETHOLD;

			while(i-- > 1)
			{
				waitms(10);
				if(recv(stationsocket, encbuf, sizeof(FWsamPacket) + TwoFish_BLOCK_SIZE, 0) ==
					sizeof(FWsamPacket) + TwoFish_BLOCK_SIZE) i = 0;
			}

			// did we timed out?
			if(!i)
			{
				fprintf(stderr, "%s: Did not receive response from host %s.\n", __func__, inet_ntoa(station->stationip));
				close(stationsocket);
				free(encbuf);
				return -1;
			}
		
			decbuf = (char *)&sampacket;
			len = TwoFishDecrypt(encbuf, (char **)&decbuf, sizeof(FWsamPacket) + TwoFish_BLOCK_SIZE, FALSE, station->stationfish);

			// invalid decryption?
			if(len != sizeof(FWsamPacket))
			{
				if(verbose)
					fprintf(stderr, "%s: Trying initial key again!\n", __func__);

				strcpy(station->stationkey, station->initialkey);
				TwoFishDestroy(station->stationfish);
				station->stationfish = TwoFishInit(station->stationkey);
				len = TwoFishDecrypt(encbuf, (char **)&decbuf, sizeof(FWsamPacket) + TwoFish_BLOCK_SIZE, FALSE, station->stationfish);
			}

			// invalid decryption?
			if(len != sizeof(FWsamPacket))
			{
				fprintf(stderr, "%s: Password mismatch from host %s.\n", __func__, inet_ntoa(station->stationip));
				sampacket.status = FWSAM_STATUS_ERROR;
			}
			else if(sampacket.version != FWSAM_PACKETVERSION)
			{
				fprintf(stderr, "%s: Protocol version error from host %s.\n", __func__, inet_ntoa(station->stationip));
				sampacket.status = FWSAM_STATUS_ERROR;
			}
			else if(sampacket.status != FWSAM_STATUS_OK && sampacket.status != FWSAM_STATUS_NEWKEY && sampacket.status != FWSAM_STATUS_RESYNC) 
			{
				fprintf(stderr, "%s: Funky handshake error from host %s.\n", __func__, inet_ntoa(station->stationip));
				sampacket.status=FWSAM_STATUS_ERROR;
			}
		}

		// station want's to resync?
		if(sampacket.status == FWSAM_STATUS_RESYNC)
		{
			strcpy(station->stationkey, station->initialkey);
			memcpy(station->fwkeymod, sampacket.duration, 4);
		}

		// generate new keys?
		if(sampacket.status == FWSAM_STATUS_NEWKEY || sampacket.status == FWSAM_STATUS_RESYNC)	
			station_new_key(station, &sampacket);

		break;

	case FWSAM_STATUS_ERROR:
		if(station_check_in(station) == -1 || retries == 2)
		{
			fprintf(stderr, "%s: SnortSam error from host %s.\n", __func__, inet_ntoa(station->stationip));
			close(stationsocket);
			free(encbuf);
			return -1;
		}

		retries++;
		station_unblock(station, bi);
		break;

	default:
		fprintf(stderr, "%s: Unknown status (0x%x) from host %s.\n", __func__, sampacket.status, inet_ntoa(station->stationip));
		close(stationsocket);
		free(encbuf);
		return -1;
	}

	close(stationsocket);
	free(encbuf);

	return 0;
}

static void station_free(FWsamStation *station)
{
	// send a check-out?
	if(station->stationip.s_addr)
	{
		station_check_out(station);
		TwoFishDestroy(station->stationfish);
	} 

	free(station);
}

// Version info
#define VER_MAJOR				1
#define VER_MINOR				2

// SnortSam configuration file, used to determine input interface name
#define SNORTSAM_CONF			"/etc/snortsam.conf"
// Default SnortSam host
#define SNORTSAM_HOST			"127.0.0.1"

int main(int argc, char *argv[])
{
	int opt;
	FILE *h_f;
	char magic[4];
	short sssf_ver = 0;
	struct protoent *pe;
	BLOCKINFO blockinfo;
	char *state, *conf = NULL;
	char delim = ' ', quiet = 0;
	struct in_addr in_block, in_peer;
	unsigned long crc = 0u;
	FWsamStation *station = NULL;
	char *host = SNORTSAM_HOST, *pass = NULL;
	u_short port = FWSAM_DEFAULTPORT;
	static struct option const long_options[] =
	{
		{ "help", 0, 0, 'h' },
		{ "quiet", 0, 0, 'q' },
		{ "delimiter", 1, 0, 'd' },
		{ "delete", 1, 0, 'D' },
		{ "conf", 1, 0, 'c' },
		{ "host", 1, 0, 'H' },
		{ "port", 1, 0, 'p' },
		{ "pass", 1, 0, 'P' },
		{ "verbose", 0, 0, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	// command line arguments
	while((opt = getopt_long(argc, argv,
		"hqd:D:c:H:P:p:v", long_options, (int *)0)) != EOF)
	{
		switch(opt)
		{
			case 'q':
				quiet = 1;
				break;
			case 'd':
				delim = optarg[0];
				break;
			case 'D':
				if(strcasecmp(optarg, "all") == 0)
					crc = 0xffffff;
				else if(sscanf(optarg, "%x", &crc) != 1)
				{
					fprintf(stderr, "%s: invalid CRC argument.\n", argv[0]);
					return 1;
				}
				break;
			case 'c':
				conf = optarg;
				break;
			case 'H':
				host = optarg;
				break;
			case 'P':
				pass = optarg;
				break;
			case 'p':
				port = (u_short)atoi(optarg);
				if(!port)
				{
					fprintf(stderr, "%s: invalid CRC argument.\n", argv[0]);
					return 1;
				}
				break;
			case 'v':
				verbose = 1;
				break;
			case 'h':
			default:
				fprintf(stderr, "SnortSam state utility v%d.%d:\n",
					VER_MAJOR, VER_MINOR);
				fprintf(stderr, "%s [options] [<snortsam state file>]\n", argv[0]);
				fprintf(stderr, "  -q, --quiet            Plain output format.\n");
				fprintf(stderr, "  -d, --delimiter <n>    Field delimiter, default: '%c'\n", delim);
				fprintf(stderr, "  -D, --delete <n>|all   Delete block record matching CRC <n> or all.\n");
				fprintf(stderr, "  -c, --conf <s>         SnortSam configuration file, default: %s\n",
					SNORTSAM_CONF);
				fprintf(stderr, "  -H, --host <s>         SnortSam hostname, default: %s\n", host);
				fprintf(stderr, "  -p, --port <n>         SnortSam port address, default: %d\n", port);
				fprintf(stderr, "  -P, --pass <s>         SnortSam password, default: NULL\n");
				fprintf(stderr, "  -v, --verbose          Be more verbose.\n");
				fprintf(stderr, "  <snortsam state file>  Default: %s\n", FWSAMHISTORYFILE);
				return 0;
		}
	}

	if(argc != optind)
		state = argv[optind];
	else
		state = FWSAMHISTORYFILE;

	if(!(h_f = fopen(state, "rb")))
	{
		fprintf(stderr, "%s: unable to open %s: %s.\n",
			argv[0], state, strerror(errno));
		return 1;
	}

	if(fread(magic, sizeof(magic), 1, h_f) != 1)
	{
		if(errno != 0)
		{
			fprintf(stderr, "%s: error reading magic: %s: %s.\n",
				argv[0], state, strerror(errno));
		}

		fclose(h_f);
		return 1;
	}

	if(magic[0] != 'S' || magic[1] != 'S' || magic[2] != 'S' || magic[3] != 'F')
	{
		fprintf(stderr,
			"%s: invalid state file; no magic or too old: %s\n",
			argv[0], state);
		fclose(h_f);
		return 1;
	}

	if(fscanf(h_f, "%2hd", &sssf_ver) != 1)
	{
		fprintf(stderr, "%s: error reading magic: %s: %s.\n",
			argv[0], state, strerror(errno));
		fclose(h_f);
		return 1;
	}
	else
	{
		char sssf_magic[sizeof(magic) + 2 + 1];

		sprintf(sssf_magic, "SSSF%02hd", sssf_ver);

		if(memcmp(sssf_magic, FWSAMHISTORYVERSION, 6))
		{
			fprintf(stderr, "%s: invalid state file version: SSSF%02hd, expected: %s: %s\n",
				argv[0], sssf_ver, FWSAMHISTORYVERSION, state);
			fclose(h_f);
			return 1;
		}
	}		

	// delete block?
	if(crc)
	{
		pid_t pid;
		int rc = 0;
		char *tmp = strdup("/tmp/.snortsamXXXXXX");
		FILE *h_t = fdopen(mkstemp(tmp), "w");

		if(!h_t)
		{
			fprintf(stderr, "%s: can't create temp file: %s.\n",
				argv[0], strerror(errno));
			free(tmp);
			fclose(h_f);
			return 1;
		}

		if((pid = pidof()) == -1)
			fprintf(stderr, "%s: SnortSam isn't running, will unblock manually.\n", argv[0]);
		else
		{
			if((station = station_init("localhost", 0, NULL)))
				station_check_in(station);
		}

		fwrite(magic, sizeof(magic), 1, h_t);
		fprintf(h_t, "%02hd", sssf_ver);

		while(fread(&blockinfo, sizeof(BLOCKINFO), 1, h_f) == 1)
		{
			if(crc == 0xffffff ||
				cksum((unsigned char *)&blockinfo, sizeof(BLOCKINFO)) == crc)
			{
				if(pid != -1 && station)
					station_unblock(station, &blockinfo);
				else
					ipt_unblock(argv[0], (conf) ? conf : SNORTSAM_CONF, &blockinfo);

				continue;
			}

			if(pid != -1) continue;

			if(fwrite(&blockinfo, sizeof(BLOCKINFO), 1, h_t) != 1)
			{
				fprintf(stderr, "%s: can't write to: %s: %s.\n",
					argv[0], tmp, strerror(errno));
				rc = 1; break;
			}
		}

		if(station) station_free(station);
		if(!rc && pid == -1) my_rename(argv[0], tmp, state);

		fclose(h_t);
		fclose(h_f);
		unlink(tmp);
		free(tmp);

		return rc;
	}

	// show blocks
	if(!quiet)
	{
		fprintf(stdout, "%-9s%-16s%-16s%-7s%-9s%-11s%-11s%-5s%-8s\n",
			"SID", "Blocked Host", "Peer Host", "Port", "Protocol", "Timestamp", "Duration", "Mode", "CRC");
		fprintf(stdout, "-------- --------------- --------------- ------ -------- ---------- ---------- ---- --------\n");
	}

	while(!feof(h_f))
	{
		if(fread(&blockinfo, sizeof(BLOCKINFO), 1, h_f) != 1) break;

		pe = getprotobynumber(blockinfo.proto);

		in_peer.s_addr = blockinfo.peerip;
		in_block.s_addr = blockinfo.blockip;

		if(quiet)
		{
			fprintf(stdout, "%ld%c%s%c%s%c%d%c%s%c%ld%c%ld%c0x%02x%c%08x\n",
				blockinfo.sig_id, delim,
				inet_ntoa(in_block), delim, inet_ntoa(in_peer),
				delim, blockinfo.port, delim, (pe) ? pe->p_name : "???",
				delim, blockinfo.blocktime, delim, blockinfo.duration, delim,
				blockinfo.mode, delim, cksum((unsigned char *)&blockinfo, sizeof(BLOCKINFO)));
		}
		else
		{
			fprintf(stdout, "%8ld %-15s %-15s %6d %-8s %10ld %10ld 0x%02x %08x\n",
				blockinfo.sig_id,
				inet_ntoa(in_block), inet_ntoa(in_peer),
				blockinfo.port, (pe) ? pe->p_name : "???",
				blockinfo.blocktime, blockinfo.duration,
				blockinfo.mode, cksum((unsigned char *)&blockinfo, sizeof(BLOCKINFO)));
		}

		fflush(stdout);
	}

	fclose(h_f);

	return 0;
}

// vi: ts=4
