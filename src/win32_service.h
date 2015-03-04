/* $Id: win32_service.h,v 2.2 2005/11/11 09:10:30 fknobbe Exp $
 *
 *
 * Copyright (c) 2005 nima sharifi mehr <nimahacker@yahoo.com>
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
 *
*/

#ifdef WIN32

#ifndef		__WIN32_SERVICE_H__
#define		__WIN32_SERVICE_H__

//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: EVMSG_SIMPLE
//
// MessageText:
//
//  %1
//
#define EVMSG_SIMPLE                     ((WORD)0x00000001L)

//
// MessageId: EVMSG_INSTALLED
//
// MessageText:
//
//  The %1 service was installed.
//
#define EVMSG_INSTALLED                  ((WORD)0x00000002L)

//
// MessageId: EVMSG_REMOVED
//
// MessageText:
//
//  The %1 service was removed.
//
#define EVMSG_REMOVED                    ((WORD)0x00000003L)

//
// MessageId: EVMSG_NOTREMOVED
//
// MessageText:
//
//  The %1 service could not be removed.
//
#define EVMSG_NOTREMOVED                 ((WORD)0x00000004L)

//
// MessageId: EVMSG_CTRLHANDLERNOTINSTALLED
//
// MessageText:
//
//  The control handler could not be installed.
//
#define EVMSG_CTRLHANDLERNOTINSTALLED    ((WORD)0x00000005L)

//
// MessageId: EVMSG_FAILEDINIT
//
// MessageText:
//
//  The initialization process failed.
//
#define EVMSG_FAILEDINIT                 ((WORD)0x00000006L)

//
// MessageId: EVMSG_STARTED
//
// MessageText:
//
//  The service was started.
//
#define EVMSG_STARTED                    ((WORD)0x00000007L)

//
// MessageId: EVMSG_BADREQUEST
//
// MessageText:
//
//  The service received an unsupported request.
//
#define EVMSG_BADREQUEST                 ((WORD)0x00000008L)

//
// MessageId: EVMSG_DEBUG
//
// MessageText:
//
//  Debug: %1
//
#define EVMSG_DEBUG                      ((WORD)0x00000009L)

//
// MessageId: EVMSG_STOPPED
//
// MessageText:
//
//  The service was stopped.
//
#define EVMSG_STOPPED                    ((WORD)0x00000010L)


#if defined(ENABLE_WIN32_SERVICE)

	#define SERVICE_CMDLINE_PARAM            "/SERVICE"
    #define SERVICE_INSTALL_CMDLINE_PARAM    "/INSTALL"
    #define SERVICE_UNINSTALL_CMDLINE_PARAM  "/UNINSTALL"
    #define SERVICE_SHOW_CMDLINE_PARAM       "/SHOW"

    int   SnortSamServiceMain(int argc, char* argv[]);
	void  CreateApplicationEventLogEntry(const char *msg);

#endif  /* ENABLE_WIN32_SERVICE */

#endif	/* __WIN32_SERVICE_H__ */
#endif	/* WIN32 */
