/* $Id: ssp_pf2.c,v 3.3 2009/11/27 01:39:40 fknobbe Exp $
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
 * ssp_pf2.c
 *
 * Purpose:
 *
 * This SnortSam plugin is meant for dynamic (un)blocking on the PF firewall
 * for OpenBSD >= 3.5, FreeBSD and NetBSD.
 * SnortSam will expire the blocks itself since PF does not have automatic
 * time-out functionality.
 *
 * This is a reimplementation of the original ssp_pf plugin in order to
 * simplify it and make it portable.
 */

#ifndef USE_SSP_PF
#if defined(OpenBSD) || defined(FreeBSD) || defined(NetBSD)

#ifndef		__SSP_PF2_C__
#define		__SSP_PF2_C__

#include "snortsam.h"
#include "ssp_pf2.h"

unsigned int PF2use_anchor = TRUE;
unsigned int PF2val_count = 0;


/* Routine for opt parsing ( opt=value opt2=value2 etc. ) */
int parse_opts(char *line, opt_pf2 *opt, char *sep, char *int_sep, int nopt)
{
   char *last;
   char *last2;
   char *pt;
   char *pt2;
   int fo=0;
   int di=0;

   if((line==NULL) || (opt==NULL) || (sep==NULL) || (int_sep==NULL))
     return -1;

   for(pt=strtok_r(line, sep, &last); pt; pt=strtok_r(NULL, sep, &last))
     {
	for(pt2=strtok_r(pt, int_sep, &last2), fo=0; pt2; pt2=strtok_r(NULL, int_sep, &last2))
	  {
	     if(fo==0)
	       {
		  for(; fo<nopt; fo++)
		    {
		      if (strncmp(opt[fo].name, pt2, MAX_OPT_NAME)==0)
			 {
			    fo++;
			    di++;
			    break;
			 }
		    }
	       }
	     else
	       {
		  if(di)
		    if(opt[--fo].vt>0)
		      strncpy(opt[fo].v.value_s, pt2, MAX_OPT_VALUE);
		    else
		      opt[fo].v.value_d=atoi(pt2);
		  fo=0;
		  di=0;
	       }
	  }
     }

   return;
}


/*
 * This routine parses the pf2 statements in the config file.
 */
void
PF2Parse(char *val, char *file, unsigned long line, DATALIST * plugindatalist)
{
   PF2DATA        *pfp = NULL;
   char           msg[STRBUFSIZE + 2];
   char           tbuf[PF_TABLE_NAME_SIZE];
   int            pfdev;
   opt_pf2        options[3]={
	{"anchor", "", 1},
	{"table",  "", 1},
	{"kill",   "", 1}
   };

#ifdef FWSAMDEBUG
   printf("Debug: [pf2] Plugin Parsing...\n");
#endif

    PF2val_count += 1;
    if (PF2val_count > 1) {
	snprintf(msg, sizeof(msg) - 1, "Info: [%s: %lu] line ignored ! More than one pf2 statements configured.", file, line);
	logmessage(1, msg, "pf2", 0);
	return;
    }

   if (val != NULL && *val)
     {
	if(parse_opts(val, options, " \t", "=", (sizeof(options)/sizeof(opt_pf2)))<0)
	  {
	     snprintf(msg, sizeof(msg) - 1, "Error: [%s: %lu] invalid PF parameters !. PF2 Plugin disabled.", file, line);
	     logmessage(1, msg, "pf2", 0);
	     plugindatalist->data=NULL;
	     return;
	  }
     }
    else
    {
	snprintf(msg, sizeof(msg) - 1, "Info: [%s: %lu] no parameters configured, using defaults.", file, line);
	logmessage(1, msg, "pf2", 0);
    }

	pfp = safemalloc(sizeof(PF2DATA), "PF2Parse", "pfp");
	bzero(pfp, sizeof(PF2DATA));
	plugindatalist->data = pfp;

	/* Check Anchor */
	if(strlen(options[PF2_OPT_ANCHOR].v.value_s)<1)
	  {
	     snprintf(msg, sizeof(msg) - 1,
		      "Info: [%s: %lu] PF anchor name not defined, using \"snortsam\"", file, line);
	     logmessage(1, msg, "pf2", 0);
	     safecopy(pfp->anchorname, "snortsam");	/* save anchorname */
	  }
	else
	  {
	     safecopy(pfp->anchorname, options[PF2_OPT_ANCHOR].v.value_s);	/* save anchorname */
	     /* if PF2use_anchor == FALSE then tables from the main pf section will be used */
	     if ((strncmp(options[PF2_OPT_ANCHOR].v.value_s, "notused", MAX_OPT_VALUE)==0) ||
		(strncmp(options[PF2_OPT_ANCHOR].v.value_s, "none", MAX_OPT_VALUE)==0)) {
		 PF2use_anchor = FALSE;
		 /* If anchor is not used, wipe none/notused with zeros */
		 bzero(&(pfp->anchorname), sizeof(pfp->anchorname));
	     }
	  }

	/* Check Table */
	if(strlen(options[PF2_OPT_TABLE].v.value_s)<1)
	  {
	     snprintf(msg, sizeof(msg) - 1,
		"Info: [%s: %lu] PF table not defined, using \"blockin,blockout\" for tables", file, line);
	     logmessage(1, msg, "pf2", 0);
	     safecopy(pfp->tablein,  "blockin");
	     safecopy(pfp->tableout, "blockout");
	  }
	else
	  {
	    /* save tablenames */
	    snprintf(tbuf, PF_TABLE_NAME_SIZE, "%sin", options[PF2_OPT_TABLE].v.value_s);
	    safecopy(pfp->tablein,  tbuf);
	    snprintf(tbuf, PF_TABLE_NAME_SIZE, "%sout", options[PF2_OPT_TABLE].v.value_s);
	    safecopy(pfp->tableout, tbuf);
	  }

    /* Check kill option, for safety reason default: kill=all */
    if (strlen(options[PF2_OPT_KILL].v.value_s)>1) {
	if (strncmp(options[PF2_OPT_KILL].v.value_s, "all", MAX_OPT_VALUE)==0)
	    pfp->kill = PF2_KILL_STATE_ALL;
	else if (strncmp(options[PF2_OPT_KILL].v.value_s, "dir", MAX_OPT_VALUE)==0)
	    pfp->kill = PF2_KILL_STATE_DIR;
	else if (strncmp(options[PF2_OPT_KILL].v.value_s, "no", MAX_OPT_VALUE)==0)
	    pfp->kill = PF2_KILL_STATE_NO;
	else {
	    pfp->kill = PF2_KILL_STATE_ALL;
	    snprintf(msg, sizeof(msg) - 1,
		"Error: [%s: %lu] invalid PF parameters \"kill=%s\"! Fallback to \"kill=all\"",
		file, line, options[PF2_OPT_KILL].v.value_s);
	    logmessage(1, msg, "pf2", 0);
	}
    }
    else {
	pfp->kill = PF2_KILL_STATE_ALL;
	snprintf(msg, sizeof(msg) - 1,
	    "Info: [%s: %lu] PF kill option not defined, using \"kill=all\"", file, line);
	logmessage(1, msg, "pf2", 0);
    }


    /* check if we can open PFDEV, else disable the plugin */
    pfdev = open(PFDEV, O_RDWR);
    if (pfdev == -1) {
	snprintf(msg, sizeof(msg) - 1, "Error: cannot open device \"%s\" ! PF2 Plugin disabled.", PFDEV);
	logmessage(1, msg, "pf2", 0);
	free(pfp);
	plugindatalist->data=NULL;
	return;
    }

    /*
     * check if anchor and tables exist.
     * We could disable the plugin if anchor/tables do not exist, but we will throw an error
     * showing what is missing at start time and for every block/unblock request.
     */
    if(PF2use_anchor)
	lookup_anchor(pfdev, pfp->anchorname);
    lookup_table(pfdev, pfp->tablein,  pfp->anchorname);
    lookup_table(pfdev, pfp->tableout, pfp->anchorname);

    if(pfdev)
	close(pfdev);

#ifdef FWSAMDEBUG
    printf("Debug: [pf2] Adding PF: \n");
    printf("\tanchor=%s\n\ttables=%s,%s\n\tkill=%s\n",
	pfp->anchorname, pfp->tablein, pfp->tableout ,
	pfp->kill==PF2_KILL_STATE_ALL ? "all" :
	pfp->kill==PF2_KILL_STATE_DIR ? "dir" : "no");
#endif

}


/*
 * BLOCK/UNBLOCK Routine
 */
void
PF2Block(BLOCKINFO * bd, void * data,unsigned long qp)
{
	PF2DATA	*pfp;
	struct	 pf_status status;
	int	 pfdev;
	int	 tin=0, tout=0;
	char	 ipsrc[256];		/* ip as a string */
	char	 msg[STRBUFSIZE + 2];
#ifdef FWSAMDEBUG
	pthread_t threadid=pthread_self();
#endif

	if(!data)
		return;

	pfp=(PF2DATA *)data;

#ifdef FWSAMDEBUG
	printf("Debug: [pf2][%lx] Plugin Blocking...\n", threadid);
#endif

	snprintf(ipsrc, sizeof(ipsrc) - 1, inettoa(bd->blockip));
	switch(bd->mode & FWSAM_HOW)
	{
	case FWSAM_HOW_THIS:
		tin = tout = 1;
		break;
	case FWSAM_HOW_IN:
		tin = 1;
		break;
	case FWSAM_HOW_OUT:
		tout = 1;
		break;
	case FWSAM_HOW_INOUT:
		tin = tout = 1;
		break;
	}

	/* open the pf device */
	pfdev = open(PFDEV, O_RDWR);
	if (pfdev == -1) {
		snprintf(msg, sizeof(msg) - 1, "Error: cannot open device %s", PFDEV);
		logmessage(1, msg, "pf2", 0);
		return;
	}

	if (ioctl(pfdev, DIOCGETSTATUS, &status)) {
	    logmessage(1, "Error: cannot get pf status", "pf2", 0);
	    return;
	}

	if (!status.running) {
	    /* even pf is not enabled, we can add IP's to pf tables if they exist */
	    logmessage(1, "Info: pf is not enabled", "pf2", 0);
	}

	/* BLOCK */
	if (bd->block)
	{
		snprintf(msg, sizeof(msg) - 1, "Info: Blocking ip %s", ipsrc);
		logmessage(3, msg, "pf2", 0);

		if (tin)
		    if ( lookup_table(pfdev, pfp->tablein, pfp->anchorname)==0 )
			change_table(pfdev, 1, pfp->tablein, pfp->anchorname, ipsrc);

		if (tout)
		    if ( lookup_table(pfdev, pfp->tableout, pfp->anchorname)==0 )
			change_table(pfdev, 1, pfp->tableout, pfp->anchorname, ipsrc);
		
		/* kill PF states after IP is placed in table */
		if (pfp->kill != PF2_KILL_STATE_NO)
			pf2_kill_states(pfdev, ipsrc, tin, tout);
	}
	else   /* UNBLOCK */
	{
		snprintf(msg, sizeof(msg) - 1, "Info: Unblocking ip %s", ipsrc);
		logmessage(3, msg, "pf2", 0);

		if (tin)
		    if ( lookup_table(pfdev, pfp->tablein, pfp->anchorname)==0 )
			change_table(pfdev, 0, pfp->tablein, pfp->anchorname, ipsrc);

		if (tout)
		    if ( lookup_table(pfdev, pfp->tableout, pfp->anchorname)==0 )
			change_table(pfdev, 0, pfp->tableout, pfp->anchorname, ipsrc);
	}
	close(pfdev);
	return;
}				       /* PF2BLOCK */

/* borrowed from OpenBSDs pfctl code */
int
change_table(int pfdev, int add, const char *table, const char *anchor, const char *ipsrc)
{
	char   msg[STRBUFSIZE + 2];
	struct pfioc_table	io;
	struct pfr_addr		addr;

	bzero(&io, sizeof(io));
	strlcpy(io.pfrio_table.pfrt_name, table, sizeof(io.pfrio_table.pfrt_name));

	if (PF2use_anchor == TRUE)
		strlcpy(io.pfrio_table.pfrt_anchor, anchor, sizeof(io.pfrio_table.pfrt_anchor));
	io.pfrio_buffer = &addr;
	io.pfrio_esize = sizeof(addr);
	io.pfrio_size = 1;

	bzero(&addr, sizeof(addr));
	if (ipsrc == NULL || !ipsrc[0])
		return (-1);
	if (inet_pton(AF_INET, ipsrc, &addr.pfra_ip4addr) == 1) {
		addr.pfra_af = AF_INET;
		addr.pfra_net = 32;
	} else if (inet_pton(AF_INET6, ipsrc, &addr.pfra_ip6addr) == 1) {
		addr.pfra_af = AF_INET6;
		addr.pfra_net = 128;
	} else {
	        snprintf(msg, sizeof(msg) - 1, "invalid ipsrc");
                logmessage(3, msg, "pf2", 0);
		return (-1);
	}

	if (ioctl(pfdev, add ? DIOCRADDADDRS : DIOCRDELADDRS, &io) && errno != ESRCH) {
	        snprintf(msg, sizeof(msg) - 1, "cannot %s %s %s table %s: %s",
			 add ? "add" : "remove", ipsrc, add ? "to" : "from", table, strerror(errno));
                logmessage(3, msg, "pf2", 0);
		return (-1);
	}
#ifdef FWSAMDEBUG
	printf("Debug: [pf2] %s %s %s anchor=%s table=%s\n",
		add ? "add" : "remove", ipsrc, add ? "to" : "from", anchor, table);
#endif
	return (0);
}


/* Kill ipsrc state(s) from PF statefull table, so we can catch the IP with the
 * configured tables. If states are not killed existing connections stay open as
 * long they have a valid entry in the PF state.
 * We can drop all states or only those matching the direction in/out.
 */
int
pf2_kill_states(int pfdev, const char *ipsrc, int tin, int tout )
{
    char   msg[STRBUFSIZE + 2];
    struct pf_addr pfa;
    struct pfioc_state_kill psk;
    sa_family_t saf;        /* stafe AF_INET family */
    unsigned long killed=0, killed_src=0, killed_dst=0;

    bzero(&pfa, sizeof(pfa));
    bzero(&psk, sizeof(psk));

    if (ipsrc == NULL || !ipsrc[0])
	return (-1);

    if (inet_pton(AF_INET, ipsrc, &pfa.v4) == 1)
	    psk.psk_af = saf = AF_INET;
    else if (inet_pton(AF_INET6, ipsrc, &pfa.v6) == 1)
	    psk.psk_af = saf = AF_INET6;
    else {
	snprintf(msg, sizeof(msg) - 1, "invalid ipsrc");
	logmessage(3, msg, "pf2", 0);
	    return (-1);
    }

    /* Kill all states from pfa */
    if (tin || PF2_KILL_STATE_ALL) {
	memcpy(&psk.psk_src.addr.v.a.addr, &pfa, sizeof(psk.psk_src.addr.v.a.addr));
	memset(&psk.psk_src.addr.v.a.mask, 0xff, sizeof(psk.psk_src.addr.v.a.mask));
	if (ioctl(pfdev, DIOCKILLSTATES, &psk)) {
	    snprintf(msg, sizeof(msg) - 1, "Error: DIOCKILLSTATES failed (%s)", strerror(errno));
	    logmessage(1, msg, "pf2", 0);
	}
	else {
#if OpenBSD >= 200811 /* since OpenBSD4_4 killed states returned in psk_killed */
	    killed_src += psk.psk_killed;
#else
	    killed_src += psk.psk_af;
#endif
#ifdef FWSAMDEBUG
	    printf("Debug: [pf2] killed %lu (tin) states for host %s\n", killed_src, ipsrc);
#endif
	}
    psk.psk_af = saf; /* restore AF_INET */
    }

    /* Kill all states to pfa */
    if (tout || PF2_KILL_STATE_ALL) {
	bzero(&psk.psk_src, sizeof(psk.psk_src));  /* clear source address field (set before for incomming) */
	memcpy(&psk.psk_dst.addr.v.a.addr, &pfa, sizeof(psk.psk_dst.addr.v.a.addr));
	memset(&psk.psk_dst.addr.v.a.mask, 0xff, sizeof(psk.psk_dst.addr.v.a.mask));
	if (ioctl(pfdev, DIOCKILLSTATES, &psk)) {
	    snprintf(msg, sizeof(msg) - 1, "Error: DIOCKILLSTATES failed (%s)", strerror(errno));
	    logmessage(1, msg, "pf2", 0);
	}
	else {
#if OpenBSD >= 200811 /* since OpenBSD4_4 killed states returned in psk_killed */
	    killed_dst += psk.psk_killed;
#else
	    killed_dst += psk.psk_af;
#endif
#ifdef FWSAMDEBUG
	    printf("Debug: [pf2] killed %lu (tout) states for host %s\n", killed_dst, ipsrc);
#endif
	}
    }

    if ((killed_src + killed_dst)>0) {
	    snprintf(msg, sizeof(msg) - 1, "Info: Killed %lu PF state(s) (in: %lu, out: %lu) for host %s",
		killed_src + killed_dst, killed_src, killed_dst, ipsrc);
	    logmessage(3, msg, "pf2", 0);
    }
    return(0);
} /* pf2_kill_states */


/* check if anchor exist */
int
lookup_anchor(int dev, const char *anchorname)
{
    struct pfioc_ruleset pr;
    char   msg[STRBUFSIZE + 2];

    bzero(&pr, sizeof(pr));
    strlcpy(pr.path, anchorname, sizeof(pr.path));
    if (ioctl(dev, DIOCGETRULESETS, &pr)) {
        if (errno == EINVAL){
            snprintf(msg, sizeof(msg) - 1, "Error: anchor \"%s\" not found", anchorname);
            logmessage(1, msg, "pf2", 0);
            return (-1);
        }
    }
#ifdef FWSAMDEBUG
    printf("Debug: [pf2] lookup_anchor: found anchor %s\n", anchorname);
#endif
    return (0);
}


/* check if table exist */
int
lookup_table(int dev, const char *tablename, const char *anchorname)
{
    struct pfioc_table io;
    struct pfr_table table;
    struct pfr_addr pfa;
    char   msg[STRBUFSIZE + 2];

    if (strlen(tablename) == 0)
        return(-1);

    bzero(&io, sizeof(io));
    bzero(&table, sizeof(table));
    bzero(&pfa, sizeof(pfa));

    strlcpy(table.pfrt_anchor, anchorname, sizeof(table.pfrt_anchor));
    strlcpy(table.pfrt_name, tablename, sizeof(table.pfrt_name));

    io.pfrio_table = table;
    io.pfrio_esize = sizeof(pfa);

#ifdef FWSAMDEBUG
    printf("Debug: [pf2] lookup_table: anchor=%s table=%s\n", io.pfrio_table.pfrt_anchor, io.pfrio_table.pfrt_name);
#endif

    if (ioctl(dev, DIOCRGETADDRS, &io)) {
        snprintf(msg, sizeof(msg) - 1, "Error: table \"%s\" not found, anchor=%s table=%s",
            io.pfrio_table.pfrt_name, io.pfrio_table.pfrt_anchor, io.pfrio_table.pfrt_name);
        logmessage(1, msg, "pf2", 0);
        return(-1);
    }

#ifdef FWSAMDEBUG
    printf("Debug: [pf2] table \"%s\" contains [%d] entries\n", io.pfrio_table.pfrt_name, io.pfrio_size);
#endif
    return(0);
}

#endif				/* __SSP_PF2_C__ */

#endif /* OpenBSD || FreeBSD || NetBSD */
#endif /* !USE_SSP_PF */
/* vim: set ts=8 sw=4: */
