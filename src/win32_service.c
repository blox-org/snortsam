/* $Id: win32_service.c,v 2.2 2005/11/11 09:10:30 fknobbe Exp $
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
 * Purpose: Lets SnortSam register as a Win32 Service.  This includes both
 *          an installation an uninstallation aspect.
 *
 * Author:  Nima Sharifi Mehr (nimahacker@yahoo.com)
 *
 * Notes:   The SnortSam command-line arguments need to be
 *          saved into the registry when the SnortSam service is
 *          being installed.  They are stored in:
 *              HKLM \ SOFTWARE \ SnortSam
 *          
 * Usage:
 *          SnortSam.exe /SERVICE /INSTALL -path <Absolute Path of SnortSam.exe> [regular command-line params]
 *          
 *          SnortSam.exe /SERVICE /UNINSTALL
 * 
 *          SnortSam.exe /SERVICE /SHOW
 * 
 * References 
 *          Microsoft has full docs on programming Win32 Services in their
 *          MSDN (Microsoft Developer Network) library.
 *          http://msdn.microsoft.com/
 */

#ifdef WIN32
#ifdef ENABLE_WIN32_SERVICE

/*
 * Enable the next line to automatically assign a description to the Service.
 * According to the Microsoft documentation, the call to ChangeServiceConfig2()
 * which sets the description is only available on Windows 2000 or newer.
 *
 *  #define SET_SERVICE_DESCRIPTION
 */


#include "win32_service.h"
#include "conio.h"
#include <Windows.h>
#include <Winsvc.h>  /* for Service stuff */
#include <stdio.h>   /* for printf(), etc */
#include <direct.h>  /* for _getcwd()     */
#include "snortsam.h"

static LPTSTR g_lpszServiceName        = "SnortSamSvc";
static LPTSTR g_lpszServiceDisplayName = "SnortSam";
static LPTSTR g_lpszServiceDescription = "The Open Source Firewall Connectivity Plugin For Snort";

static LPTSTR g_lpszRegistryKey        = "SOFTWARE\\SnortSam";
static LPTSTR g_lpszRegistryCmdFormat  = "CmdLineParam_%03d";
static LPTSTR g_lpszRegistryCountFormat= "CmdLineParamCount";

static SERVICE_STATUS          g_SnortSamServiceStatus; 
static SERVICE_STATUS_HANDLE   g_SnortSamServiceStatusHandle; 

#define MAX_REGISTRY_KEY_LENGTH		255
#define MAX_REGISTRY_DATA_LENGTH	1000
#define READ_TIMEOUT				500
#define STD_BUF						1024

static VOID  SvcDebugOut(LPSTR String, DWORD Status);
static VOID  SvcFormatMessage(LPSTR szString, int iCount);
static VOID  ReadServiceCommandLineParams( int * piArgCounter, char** * pargvDynamic );
static VOID  WINAPI SnortSamServiceStart (DWORD argc, LPTSTR *argv); 
static VOID  WINAPI SnortSamServiceCtrlHandler (DWORD opcode); 
static DWORD SnortSamServiceInitialization (DWORD argc, LPTSTR *argv, DWORD *specificError); 
static VOID  InstallSnortSamService(int argc, char* argv[]);
static VOID  UninstallSnortSamService();
static VOID  ShowSnortSamServiceParams();
static VOID	 FatalError(const char *format,...);
static VOID	 CreateApplicationEventLogEntry(const char *msg);
static VOID  AddEventSource(char *ident);


/* Taken from MSDN. */
void AddEventSource(char *ident)
{
    HKEY hk; 
    DWORD dwData; 
    char szFilePath[_MAX_PATH];
	char key[_MAX_PATH];
	
    // Add your source name as a subkey under the Application 
    // key in the EventLog registry key. 
    _snprintf(key, sizeof(key), "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s", ident);

    if (RegCreateKey(HKEY_LOCAL_MACHINE, key, &hk)) {
		printf("Could not create the registry key."); 
		exit(-1);
	}
 
    // Set the name of the message file. 
	GetModuleFileName(NULL, szFilePath, sizeof(szFilePath));
    // Add the name to the EventMessageFile subkey. 
 
    if (RegSetValueEx(hk,             // subkey handle 
            "EventMessageFile",       // value name 
            0,                        // must be zero 
            REG_EXPAND_SZ,            // value type 
            (LPBYTE) szFilePath,           // pointer to value data 
            strlen(szFilePath) + 1)) {       // length of value data 
        printf("Could not set the event message file."); 
		exit(-1);
	}
 
    // Set the supported event types in the TypesSupported subkey. 
 
    dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | 
        EVENTLOG_INFORMATION_TYPE | EVENTLOG_AUDIT_SUCCESS | EVENTLOG_AUDIT_FAILURE; 
 
    if (RegSetValueEx(hk,      // subkey handle 
            "TypesSupported",  // value name 
            0,                 // must be zero 
            REG_DWORD,         // value type 
            (LPBYTE) &dwData,  // pointer to value data 
            sizeof(DWORD))){    // length of value data 
        printf("Could not set the supported types."); 
		exit(-1);
	}
 
    RegCloseKey(hk); 
} 

/*
 * Function: CreateApplicationEventLogEntry(const char *)
 *
 * Purpose: Add an entry to the Win32 "Application" EventLog
 *
 * Arguments: szMessage => the formatted error string to print out
 *
 * Returns: void function
 */
void CreateApplicationEventLogEntry(const char *msg)
{
    HANDLE hEventLog; 
    char*  pEventSourceName = "SnortSam";

    /* prepare to write to Application log on local host
      * with Event Source of SnortService
      */
    AddEventSource(pEventSourceName);
    hEventLog = RegisterEventSource(NULL, pEventSourceName);
    if (hEventLog == NULL)
    {
        /* Could not register the event source. */
        return;
    }
 
    if (!ReportEvent(hEventLog,   /* event log handle               */
            EVENTLOG_ERROR_TYPE,  /* event type                     */
            0,                    /* category zero                  */
            EVMSG_SIMPLE,         /* event identifier               */
            NULL,                 /* no user security identifier    */
            1,                    /* one substitution string        */
            0,                    /* no data                        */
            &msg,                 /* pointer to array of strings    */
            NULL))                /* pointer to data                */
    {
        /* Could not report the event. */
    }
 
    DeregisterEventSource(hEventLog); 
} 


void FatalError(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);

    vsnprintf(buf, STD_BUF, format, ap);

    CreateApplicationEventLogEntry(buf);

    exit(0);
}

/*******************************************************************************
 * (This documentation was taken from Microsoft's own doc's on how to create
 * a Win32 Service.)
 *
 * Writing a Service Program's main Function
 * -----------------------------------------------------------------------------
 * 
 * The main function of a service program calls the StartServiceCtrlDispatcher
 * function to connect to the SCM and start the control dispatcher thread. The
 * dispatcher thread loops, waiting for incoming control requests for the
 * services specified in the dispatch table. This thread does not return until
 * there is an error or all of the services in the process have terminated. When
 * all services in a process have terminated, the SCM sends a control request
 * to the dispatcher thread telling it to shut down. The thread can then return
 * from the StartServiceCtrlDispatcher call and the process can terminate.
 * 
 * The following example is a service process that supports only one service. It
 * takes two parameters: a string that can contain one formatted output
 * character and a numeric value to be used as the formatted character. The
 * SvcDebugOut function prints informational messages and errors to the debugger.
 * For information on writing the SnortSamServiceStart and SnortSamServiceInitialization
 * functions, see Writing a ServiceMain Function. For information on writing the
 * SnortSamServiceCtrlHandler function, see Writing a Control Handler Function. 
 *******************************************************************************/


/* this is the entry point which is called from main() */
int SnortSamServiceMain(int argc, char* argv[]) 
{
    int i;
    SERVICE_TABLE_ENTRY   steDispatchTable[] = 
    { 
        { g_lpszServiceName, SnortSamServiceStart }, 
        { NULL,       NULL                     } 
    }; 

	

    for( i=1; i<argc; i++ )
    {
        if( _stricmp(argv[i],SERVICE_CMDLINE_PARAM) == 0)
        {
            /* Ignore param, because we already know that this is a service
             * simply by the fact that we are already in this function.
             * However, perform a sanity check to ensure that the user
             * didn't just type "SnortSam /SERVICE" without an indicator
             * following.
             */

            if( (i+1) < argc &&
                ( _stricmp(argv[(i+1)], SERVICE_INSTALL_CMDLINE_PARAM)!=0   ||
                  _stricmp(argv[(i+1)], SERVICE_UNINSTALL_CMDLINE_PARAM)!=0 ||
                  _stricmp(argv[(i+1)], SERVICE_SHOW_CMDLINE_PARAM)!=0       ) )
            {
                /* user entered correct command-line parameters, keep looping */
                continue;
            }
        }
        else if( _stricmp(argv[i],SERVICE_INSTALL_CMDLINE_PARAM) == 0)
        {
            InstallSnortSamService(argc, argv);
            exit(0);
        }
        else if( _stricmp(argv[i],SERVICE_UNINSTALL_CMDLINE_PARAM) == 0)
        {
            UninstallSnortSamService();
            exit(0);
        }
        else if( _stricmp(argv[i],SERVICE_SHOW_CMDLINE_PARAM) == 0)
        {
            ShowSnortSamServiceParams();
            exit(0);
        }
        else
        {
            break;  /* out of for() */
        }
    }

	

    /* If we got to this point, then it's time to start up the Win32 Service */
    if (!StartServiceCtrlDispatcher(steDispatchTable)) 
    {
        char szString[1024];
        memset(szString, sizeof(szString), '\0');
        SvcFormatMessage(szString, sizeof(szString));

        SvcDebugOut(szString, 0); 
        SvcDebugOut(" [SnortSam_SERVICE] StartServiceCtrlDispatcher error = %d\n%s\n", GetLastError()); 
        FatalError (" [SnortSam_SERVICE] StartServiceCtrlDispatcher error = %d\n%s\n", GetLastError(), szString); 
    }

    return(0);
} 
 
VOID SvcDebugOut(LPSTR szString, DWORD dwStatus) 
{ 
    CHAR  szBuffer[1024]; 
    if (strlen(szString) < 1000) 
    { 
        sprintf(szBuffer, szString, dwStatus); 
        OutputDebugStringA(szBuffer); 
    } 
}

/* Copy the system error message into the buffer provided.
 * The buffer length is indicated in iCount.
 */
VOID SvcFormatMessage(LPSTR szString, int iCount)
{
    LPVOID lpMsgBuf;
    if( szString!=NULL && iCount>0)
    {
        memset(szString, 0, iCount);
        FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                       FORMAT_MESSAGE_FROM_SYSTEM | 
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL,
                       GetLastError(),
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
                       (LPTSTR) &lpMsgBuf,
                       0,
                       NULL 
                     );

        strncpy(szString, (LPCTSTR) lpMsgBuf, iCount);
        /* Free the buffer. */
        LocalFree( lpMsgBuf );
        lpMsgBuf = NULL;
    }
}


VOID ReadServiceCommandLineParams( int * piArgCounter, char** * pargvDynamic )
{
    HKEY  hkSnortSam = NULL;
    long  lRegRC = 0;
    DWORD dwType;
    DWORD dwDataSize;
    BYTE  byData[MAX_REGISTRY_DATA_LENGTH];
    int   i;

    /**********
     * Read the registry entries for SnortSam command line parameters
     **********/
    lRegRC = RegOpenKeyEx( HKEY_LOCAL_MACHINE,        /* handle to open key      */
                           g_lpszRegistryKey,         /* subkey name             */
                           0,                         /* reserved (must be zero) */
                           KEY_READ,                  /* desired security access */
                           &hkSnortSam                   /* key handle              */
                         );
    if( lRegRC != ERROR_SUCCESS )
    {
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        FatalError(" [SnortSam_SERVICE] Unable to open SnortSam registry entry. "
                   " Perhaps SnortSam has not been installed as a service."
                   " %s", szMsg); 
    }

    memset(byData, 0, sizeof(byData));
    dwDataSize = sizeof(byData);
    lRegRC = RegQueryValueEx( hkSnortSam,                      /* handle to key       */
                              g_lpszRegistryCountFormat,    /* value name          */
                              NULL,                         /* reserved            */
                              &dwType,                      /* type buffer         */
                              byData,                       /* data buffer         */
                              &dwDataSize                   /* size of data buffer */
                            );
    if( lRegRC != ERROR_SUCCESS )
    {
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        FatalError(" [SnortSam_SERVICE] Unable to read SnortSam registry entry '%s'."
                   " Perhaps SnortSam has not been installed as a service."
                   " %s", g_lpszRegistryCountFormat, szMsg); 
    }

    (*piArgCounter) = * ((int*)&byData);

    (*pargvDynamic) = calloc( (*piArgCounter)+2, sizeof(char*) );
    (*pargvDynamic)[0] = _strdup(g_lpszServiceName);


    for( i=1; i<=(*piArgCounter); i++ )
    {
        TCHAR szName[MAX_REGISTRY_KEY_LENGTH];
        sprintf(szName, g_lpszRegistryCmdFormat, i);
        memset(byData, 0, sizeof(byData));
        dwDataSize = sizeof(byData);
        lRegRC = RegQueryValueEx( hkSnortSam,            /* handle to key       */
                                  szName,             /* value name          */
                                  NULL,               /* reserved            */
                                  &dwType,            /* type buffer         */
                                  byData,             /* data buffer         */
                                  &dwDataSize         /* size of data buffer */
                                );
        if( lRegRC != ERROR_SUCCESS )
        {
            TCHAR szMsg[1000];
            SvcFormatMessage(szMsg, sizeof(szMsg));
            FatalError(" [SnortSam_SERVICE] Unable to read SnortSam registry entry '%s'."
                       " Perhaps SnortSam has not been installed as a service."
                       " %s", szName, szMsg); 
        }

        (*pargvDynamic)[i] = _strdup( (char*) byData );
    }
    lRegRC = RegCloseKey( hkSnortSam );
    if( lRegRC != ERROR_SUCCESS )
    {
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        FatalError(" [SnortSam_SERVICE] Unable to close SnortSam registry entry."
                   " Perhaps SnortSam has not been installed as a service."
                   " %s", szMsg); 
    }
    hkSnortSam = NULL;
}


/*******************************************************************************
 * (This documentation was taken from Microsoft's own doc's on how to create
 * a Win32 Service.)
 *
 * Writing a ServiceMain Function
 * -----------------------------------------------------------------------------
 * 
 * The SnortSamServiceStart function in the following example is the entry point for
 * the service. SnortSamServiceStart has access to the command-line arguments, in the
 * way that the main function of a console application does. The first parameter
 * contains the number of arguments being passed to the service. There will
 * always be at least one argument. The second parameter is a pointer to an
 * array of string pointers. The first item in the array always points to the
 * service name. 
 * 
 * The SnortSamServiceStart function first fills in the SERVICE_STATUS structure
 * including the control codes that it accepts. Although this service accepts
 * SERVICE_CONTROL_PAUSE and SERVICE_CONTROL_CONTINUE, it does nothing
 * significant when told to pause. The flags SERVICE_ACCEPT_PAUSE_CONTINUE was
 * included for illustration purposes only; if pausing does not add value to
 * your service, do not support it. 
 * 
 * The SnortSamServiceStart function then calls the RegisterServiceCtrlHandler
 * function to register SnortSamService as the service's Handler function and begin
 * initialization. The following sample initialization function,
 * SnortSamServiceInitialization, is included for illustration purposes; it does not
 * perform any initialization tasks such as creating additional threads. If
 * your service's initialization performs tasks that are expected to take longer
 * than one second, your code must call the SetServiceStatus function
 * periodically to send out wait hints and check points indicating that progress
 * is being made. 
 * 
 * When initialization has completed successfully, the example calls
 * SetServiceStatus with a status of SERVICE_RUNNING and the service continues
 * with its work. If an error has occurred in initialization, SnortSamServiceStart
 * reports SERVICE_STOPPED with the SetServiceStatus function and returns.
 * 
 * Because this sample service does not complete any real tasks, SnortSamServiceStart
 * simply returns control to the caller. However, your service should use this
 * thread to complete whatever tasks it was designed to do. If a service does not
 * need a thread to do its work (such as a service that only processes RPC
 * requests), its ServiceMain function should return control to the caller. It is
 * important for the function to return, rather than call the ExitThread
 * function, because returning allows for cleanup of the memory allocated for the
 * arguments.
 * 
 * To output debugging information, SnortSamServiceStart calls SvcDebugOut. The source
 * code for SvcDebugOut is given in Writing a Service Program's main Function. 
 *******************************************************************************/

void WINAPI SnortSamServiceStart (DWORD argc, LPTSTR *argv) 
{
    int i;
    int iArgCounter;
    char** argvDynamic = NULL;

    DWORD dwStatus; 
    DWORD dwSpecificError = 0; 

    g_SnortSamServiceStatus.dwServiceType             = SERVICE_WIN32; 
    g_SnortSamServiceStatus.dwCurrentState            = SERVICE_START_PENDING; 
    g_SnortSamServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE; 
    g_SnortSamServiceStatus.dwWin32ExitCode           = 0; 
    g_SnortSamServiceStatus.dwServiceSpecificExitCode = 0; 
    g_SnortSamServiceStatus.dwCheckPoint              = 0; 
    g_SnortSamServiceStatus.dwWaitHint                = 0; 

    g_SnortSamServiceStatusHandle = RegisterServiceCtrlHandler(g_lpszServiceName, SnortSamServiceCtrlHandler); 
 
    if (g_SnortSamServiceStatusHandle == (SERVICE_STATUS_HANDLE)0) 
    { 
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        SvcDebugOut(" [SnortSam_SERVICE] RegisterServiceCtrlHandler failed %d\n", GetLastError()); 
        FatalError (" [SnortSam_SERVICE] RegisterServiceCtrlHandler failed %d\n%s\n", GetLastError(), szMsg); 
        return; 
    } 
 
    /* Initialization code goes here. */
    dwStatus = SnortSamServiceInitialization(argc, argv, &dwSpecificError); 
 
    /* Handle error condition */
    if (dwStatus != NO_ERROR) 
    { 
        g_SnortSamServiceStatus.dwCurrentState            = SERVICE_STOPPED; 
        g_SnortSamServiceStatus.dwCheckPoint              = 0; 
        g_SnortSamServiceStatus.dwWaitHint                = 0; 
        g_SnortSamServiceStatus.dwWin32ExitCode           = dwStatus; 
        g_SnortSamServiceStatus.dwServiceSpecificExitCode = dwSpecificError; 
 
        SetServiceStatus (g_SnortSamServiceStatusHandle, &g_SnortSamServiceStatus); 
        return; 
    } 
 
    /* Initialization complete - report running status. */
    g_SnortSamServiceStatus.dwCurrentState       = SERVICE_RUNNING; 
    g_SnortSamServiceStatus.dwCheckPoint         = 0; 
    g_SnortSamServiceStatus.dwWaitHint           = 0; 
 
    if (!SetServiceStatus (g_SnortSamServiceStatusHandle, &g_SnortSamServiceStatus)) 
    { 
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        dwStatus = GetLastError(); 
        SvcDebugOut(" [SnortSam_SERVICE] SetServiceStatus error %ld\n",dwStatus); 
        FatalError (" [SnortSam_SERVICE] SetServiceStatus error %ld\n%s\n",dwStatus,szMsg); 
    } 
    
    /* This is where the service does its work. */
    ReadServiceCommandLineParams( &iArgCounter, &argvDynamic );
    
	main( iArgCounter+1, argvDynamic );

    /* Cleanup now */
    for( i=0; i<=iArgCounter; i++ )
    {
        free( argvDynamic[i] );
        argvDynamic[i] = NULL;
    }
    free( argvDynamic );
    argvDynamic = NULL;

    SvcDebugOut(" [SnortSam_SERVICE] Returning the Main Thread \n",0); 
 
    return; 
} 
 
/* Stub initialization function. */
DWORD SnortSamServiceInitialization(DWORD argc, LPTSTR *argv, DWORD *pdwSpecificError) 
{ 
    argv; 
    argc; 
    pdwSpecificError; 
    return(0); 
} 



/*******************************************************************************
 * (This documentation was taken from Microsoft's own doc's on how to create
 * a Win32 Service.)
 *
 * Writing a Control Handler Function
 * -----------------------------------------------------------------------------
 * 
 * The SnortSamServiceCtrlHandler function in the following example is the Handler
 * function. When this function is called by the dispatcher thread, it handles
 * the control code passed in the Opcode parameter and then calls the
 * SetServiceStatus function to update the service's status. Every time a
 * Handler function receives a control code, it is appropriate to return status
 * with a call to SetServiceStatus regardless of whether the service acts on
 * the control.
 * 
 * When the pause control is received, SnortSamServiceCtrlHandler simply sets the
 * dwCurrentState field in the SERVICE_STATUS structure to SERVICE_PAUSED.
 * Likewise, when the continue control is received, the state is set to
 * SERVICE_RUNNING. Therefore, SnortSamServiceCtrlHandler is not a good example of
 * how to handle the pause and continue controls. Because SnortSamServiceCtrlHandler
 * is a template for a Handler function, code for the pause and continue
 * controls is included for completeness. A service that supports either the
 * pause or continue control should handle these controls in a way that makes
 * sense. Many services support neither the pause or continue control. If the
 * service indicates that it does not support pause or continue with the
 * dwControlsAccepted parameter, then the SCM will not send pause or continue
 * controls to the service's Handler function. 
 * 
 * To output debugging information, SnortSamServiceCtrlHandler calls SvcDebugOut. The
 * source code for SvcDebugOut is listed in Writing a Service Program's main
 * Function. Also, note that the g_SnortSamServiceStatus variable is a global variable
 * and should be initialized as demonstrated in Writing a ServiceMain function. 
 *******************************************************************************/

VOID WINAPI SnortSamServiceCtrlHandler (DWORD dwOpcode) 
{ 
    DWORD dwStatus; 
 
    switch(dwOpcode) 
    { 
        case SERVICE_CONTROL_PAUSE: 

            g_SnortSamServiceStatus.dwCurrentState = SERVICE_PAUSED; 
            break; 
 
        case SERVICE_CONTROL_CONTINUE: 

            g_SnortSamServiceStatus.dwCurrentState = SERVICE_RUNNING; 
            break; 
 
        case SERVICE_CONTROL_STOP: 

            Sleep( READ_TIMEOUT * 2 );  /* wait for 2x the timeout, just to ensure that things
                                         * the service has processed any last packets
                                         */

            g_SnortSamServiceStatus.dwWin32ExitCode = 0; 
            g_SnortSamServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            g_SnortSamServiceStatus.dwCheckPoint    = 0; 
            g_SnortSamServiceStatus.dwWaitHint      = 0; 
 
            if (!SetServiceStatus (g_SnortSamServiceStatusHandle, &g_SnortSamServiceStatus))
            { 
                dwStatus = GetLastError(); 
                SvcDebugOut(" [SnortSam_SERVICE] SetServiceStatus error %ld\n",dwStatus); 
            } 
 
            SvcDebugOut(" [SnortSam_SERVICE] Leaving SnortSamService \n",0); 
            return; 
 
        case SERVICE_CONTROL_INTERROGATE: 
            /* Fall through to send current status. */
            break; 
 
        default: 
            SvcDebugOut(" [SnortSam_SERVICE] Unrecognized opcode %ld\n", dwOpcode); 
    } 
 
    /* Send current status.  */
    if (!SetServiceStatus (g_SnortSamServiceStatusHandle,  &g_SnortSamServiceStatus)) 
    { 
        dwStatus = GetLastError(); 
        SvcDebugOut(" [SnortSam_SERVICE] SetServiceStatus error %ld\n",dwStatus); 
    } 

    return; 
} 



/*******************************************************************************
 * (This documentation was taken from Microsoft's own doc's on how to create
 * a Win32 Service.)
 *
 * Installing a Service
 * -----------------------------------------------------------------------------
 * 
 * A service configuration program uses the CreateService function to install a
 * service in a SCM database. The application-defined schSCManager handle must
 * have SC_MANAGER_CREATE_SERVICE access to the SCManager object. The following
 * example shows how to install a service. 
 *******************************************************************************/

VOID InstallSnortSamService(int argc, char* argv[]) 
{ 
    SC_HANDLE schSCManager, schService;
    char buffer[_MAX_PATH+1];
    LPCTSTR lpszBinaryPathName = NULL;
    HKEY hkSnortSam = NULL;
    long lRegRC = 0;
    int iArgCounter;
    DWORD dwWriteCounter = 0;
#ifdef SET_SERVICE_DESCRIPTION
    SERVICE_DESCRIPTION sdBuf;
#endif


    printf("\n\n");
    printf(" [SNORTSAM_SERVICE] Attempting to install the SnortSam service.\n");

    /**********
     * Build up a string which stores the full path to the SnortSam executable.
     * This takes into account the current working directory, along with a
     * relative path to the SnortSam executable.
     **********/
    memset( buffer, 0, sizeof(buffer) );
	/*
	if( _getcwd( buffer, _MAX_PATH ) == NULL )
    {
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        FatalError(" [SnortSam_SERVICE] Unable to determine current working directory. %s", szMsg); 
    }

    if( buffer[strlen(buffer)-1] != '\\' )
    {
        strcat(buffer, "\\");
    }
	*/
	/*
    strcat(buffer, argv[0]);
    strcat(buffer, " ");
    strcat(buffer, SERVICE_CMDLINE_PARAM);
	lpszBinaryPathName = buffer;
		
    printf("\n");
    printf(" [SnortSam_SERVICE] The full path to the SnortSam binary appears to be:\n");
    printf("    %s\n", lpszBinaryPathName);
	*/

    /**********
     * Create the registry entries for SnortSam command line parameters
     **********/
    lRegRC = RegCreateKeyEx( HKEY_LOCAL_MACHINE,        /* handle to open key       */
                             g_lpszRegistryKey,         /* subkey name              */
                             0,                         /* reserved (must be zero)  */
                             NULL,                      /* class string             */
                             REG_OPTION_NON_VOLATILE,   /* special options          */
                             KEY_ALL_ACCESS,            /* desired security access  */
                             NULL,                      /* inheritance              */
                             &hkSnortSam,                  /* key handle               */
                             NULL                       /* disposition value buffer */
                           );
    if( lRegRC != ERROR_SUCCESS )
    {
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        FatalError(" [SnortSam_SERVICE] Unable to create SnortSam registry entry. %s", szMsg); 
    }

    for( iArgCounter=1; iArgCounter<argc; iArgCounter++ )
    {
        /* ignore the Service command line parameters (/SERVICE, /INSTALL, /UNINSTALL)
         * and store all others in the registry
         */
        if( ( _stricmp(argv[iArgCounter],SERVICE_CMDLINE_PARAM)           == 0 )  ||
            ( _stricmp(argv[iArgCounter],SERVICE_INSTALL_CMDLINE_PARAM)   == 0 )  ||
            ( _stricmp(argv[iArgCounter],SERVICE_UNINSTALL_CMDLINE_PARAM) == 0 )   )
        {
            /* ignore it, because it isn't a real SnortSam command-line parameter */
        }
        else if( strlen(argv[iArgCounter]) > MAX_REGISTRY_DATA_LENGTH )
        {
            FatalError(" [SnortSam_SERVICE] A single command line parameter cannot exceed %d characters.", MAX_REGISTRY_DATA_LENGTH); 
        }
		else if(( _stricmp(argv[iArgCounter],"-path")== 0 ))
		{
			if(iArgCounter+1<argc)
			{
				strcat(buffer, argv[++iArgCounter]);
				strcat(buffer, " ");
				strcat(buffer, SERVICE_CMDLINE_PARAM);

				lpszBinaryPathName = buffer;
				continue;
			}
			else
			{
				FatalError(" [SNORT_SERVICE] Value of path parameter is lost."); 
			}
		}
        else
        {
            char szSubkeyName[30];
            dwWriteCounter++;
            sprintf(szSubkeyName, g_lpszRegistryCmdFormat, dwWriteCounter);
            lRegRC = RegSetValueEx( hkSnortSam,                       /* handle to key to set value for */
                                    szSubkeyName,                  /* name of the value to set       */
                                    0,                             /* reserved                       */
                                    REG_SZ,                        /* flag for value type            */
                                    (LPBYTE) argv[iArgCounter],    /* address of value data          */
                                    strlen(argv[iArgCounter])      /* size of value data             */
                                  );
            if( lRegRC != ERROR_SUCCESS )
            {
                TCHAR szMsg[1000];
                SvcFormatMessage(szMsg, sizeof(szMsg));
                FatalError(" [SnortSam_SERVICE] Unable to write SnortSam registry entry. %s", szMsg); 
            }
        }
    } /* end for() */

    lRegRC = RegSetValueEx( hkSnortSam,                       /* handle to key to set value for */
                            g_lpszRegistryCountFormat,     /* name of the value to set       */
                            0,                             /* reserved                       */
                            REG_DWORD,                     /* flag for value type            */
                            (LPBYTE) &dwWriteCounter,      /* address of value data          */
                            sizeof(dwWriteCounter)         /* size of value data             */
                          );
    if( lRegRC != ERROR_SUCCESS )
    {
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        FatalError(" [SnortSam_SERVICE] Unable to write SnortSam registry entry. %s", szMsg); 
    }

    lRegRC = RegCloseKey( hkSnortSam );
    if( lRegRC != ERROR_SUCCESS )
    {
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        FatalError(" [SnortSam_SERVICE] Unable to close SnortSam registry entry. %s", szMsg); 
    }

    printf("\n");
    printf(" [SnortSam_SERVICE] Successfully added registry keys to:\n");
    printf("    \\HKEY_LOCAL_MACHINE\\%s\\\n", g_lpszRegistryKey);


    /**********
     * Add SnortSam to the Services database
     **********/
    schSCManager = OpenSCManager(NULL,                    /* local machine                        */
                                 NULL,                    /* defaults to SERVICES_ACTIVE_DATABASE */
                                 SC_MANAGER_ALL_ACCESS);  /* full access rights                   */
 
    if (schSCManager == NULL)
    {
        DWORD dwErr = GetLastError();
        LPCTSTR lpszBasicMessage = "Unable to open a connection to the Services database."; 
        TCHAR szMsg[1000];

        SvcFormatMessage(szMsg, sizeof(szMsg));
        switch(dwErr)
        {
        case ERROR_ACCESS_DENIED: 
            FatalError(" [SnortSam_SERVICE] %s Access is denied. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_DATABASE_DOES_NOT_EXIST: 
            FatalError(" [SnortSam_SERVICE] %s Services database does not exist. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_INVALID_PARAMETER: 
            FatalError(" [SnortSam_SERVICE] %s Invalid parameter. %s", lpszBasicMessage, szMsg);
            break;

        default: 
            FatalError(" [SnortSam_SERVICE] %s Unrecognized error (%d). %s", lpszBasicMessage, dwErr, szMsg);
            break;
        }
    }

    schService = CreateService( schSCManager,              /* SCManager database        */
                                g_lpszServiceName,         /* name of service           */
                                g_lpszServiceDisplayName,  /* service name to display   */
                                SERVICE_ALL_ACCESS,        /* desired access            */
                                SERVICE_WIN32_OWN_PROCESS, /* service type              */
                                SERVICE_AUTO_START,		   /* start type                */
                                SERVICE_ERROR_NORMAL,      /* error control type        */
                                lpszBinaryPathName,        /* service's binary          */
                                NULL,                      /* no load ordering group    */
                                NULL,                      /* no tag identifier         */
                                NULL,					   /* dependencies				*/
								NULL,					   /* LocalSystem account       */
                                NULL);					   /* no password               */
 
    if (schService == NULL)
    {
        DWORD dwErr = GetLastError();
        LPCTSTR lpszBasicMessage = "Error while adding the SnortSam service to the Services database."; 
        TCHAR szMsg[1000];

        SvcFormatMessage(szMsg, sizeof(szMsg));
        switch(dwErr)
        {
        case ERROR_ACCESS_DENIED: 
            FatalError(" [SnortSam_SERVICE] %s Access is denied. %s", lpszBasicMessage, szMsg);
            break;
        case ERROR_CIRCULAR_DEPENDENCY:
            FatalError(" [SnortSam_SERVICE] %s Circular dependency. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_DUP_NAME: 
            FatalError(" [SnortSam_SERVICE] %s The display name (\"%s\") is already in use. %s", lpszBasicMessage
                                                                                            , g_lpszServiceDisplayName
                                                                                            , szMsg);
            break;

        case ERROR_INVALID_HANDLE: 
            FatalError(" [SnortSam_SERVICE] %s Invalid handle. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_INVALID_NAME: 
            FatalError(" [SnortSam_SERVICE] %s Invalid service name. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_INVALID_PARAMETER: 
            FatalError(" [SnortSam_SERVICE] %s Invalid parameter. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_INVALID_SERVICE_ACCOUNT: 
            FatalError(" [SnortSam_SERVICE] %s Invalid service account. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_SERVICE_EXISTS: 
            FatalError(" [SnortSam_SERVICE] %s Service already exists. %s", lpszBasicMessage, szMsg);
            break;

        default: 
            FatalError(" [SnortSam_SERVICE] %s Unrecognized error (%d). %s", lpszBasicMessage, dwErr, szMsg);
            break;
        }
    }

#ifdef SET_SERVICE_DESCRIPTION
    /* Apparently, the call to ChangeServiceConfig2() only works on Windows >= 2000 */
    sdBuf.lpDescription = g_lpszServiceDescription;
    if( !ChangeServiceConfig2(schService,                 /* handle to service      */
                              SERVICE_CONFIG_DESCRIPTION, /* change: description    */
                              &sdBuf) )                   /* value: new description */
    {
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        FatalError(" [SnortSam_SERVICE] Unable to add a description to the SnortSam service. %s", szMsg); 
    }
#endif

    printf("\n");
    printf(" [SnortSam_SERVICE] Successfully added the SnortSam service to the Services database.\n"); 
 
    CloseServiceHandle(schService); 
    CloseServiceHandle(schSCManager);
} 



/*******************************************************************************
 * (This documentation was taken from Microsoft's own doc's on how to create
 * a Win32 Service.)
 *
 * Deleting a Service
 * -----------------------------------------------------------------------------
 * 
 * In the following example, a service configuration program uses the
 * OpenService function to get a handle with DELETE access to an installed
 * service object. The program then uses the service object handle in the
 * DeleteService function to remove the service from the SCM database. 
 *******************************************************************************/

VOID UninstallSnortSamService() 
{ 
    SC_HANDLE schSCManager, schService;
    HKEY hkSnortSam = NULL;
    long lRegRC = 0;

    printf("\n\n");
    printf(" [SnortSam_SERVICE] Attempting to uninstall the SnortSam service.\n");


    /**********
     * Removing the registry entries for SnortSam command line parameters
     **********/
    lRegRC = RegDeleteKey( HKEY_LOCAL_MACHINE,  /* handle to open key */
                           g_lpszRegistryKey    /* subkey name        */
                         );
    if( lRegRC != ERROR_SUCCESS )
    {
        TCHAR szMsg[1000];
        SvcFormatMessage(szMsg, sizeof(szMsg));
        printf(" [SnortSam_SERVICE] Warning.  Unable to remove root SnortSam registry entry. %s", szMsg); 
    }

    printf("\n");
    printf(" [SnortSam_SERVICE] Successfully removed registry keys from:\n");
    printf("    \\HKEY_LOCAL_MACHINE\\%s\\\n", g_lpszRegistryKey);


    /**********
     * Remove SnortSam from the Services database
     **********/
    schSCManager = OpenSCManager(NULL,                    /* local machine            */
                                 NULL,                    /* ServicesActive database  */
                                 SC_MANAGER_ALL_ACCESS);  /* full access rights       */
 
    if (schSCManager == NULL) 
    {
        DWORD dwErr = GetLastError();
        LPCTSTR lpszBasicMessage = "Unable to open a connection to the Services database."; 
        TCHAR szMsg[1000];

        SvcFormatMessage(szMsg, sizeof(szMsg));
        switch(dwErr)
        {
        case ERROR_ACCESS_DENIED: 
            FatalError(" [SnortSam_SERVICE] %s Access is denied. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_DATABASE_DOES_NOT_EXIST: 
            FatalError(" [SnortSam_SERVICE] %s Services database does not exist. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_INVALID_PARAMETER: 
            FatalError(" [SnortSam_SERVICE] %s Invalid parameter. %s", lpszBasicMessage, szMsg);
            break;

        default: 
            FatalError(" [SnortSam_SERVICE] %s Unrecognized error (%d). %s", lpszBasicMessage, dwErr, szMsg);
            break;
        }
    }

    schService = OpenService(schSCManager,       /* SCManager database       */
                             g_lpszServiceName,  /* name of service          */
                             DELETE);            /* only need DELETE access  */
 
    if (schService == NULL) 
    {
        DWORD dwErr = GetLastError();
        LPCTSTR lpszBasicMessage = "Unable to locate SnortSam in the Services database."; 
        TCHAR szMsg[1000];

        SvcFormatMessage(szMsg, sizeof(szMsg));
        switch(dwErr)
        {
        case ERROR_ACCESS_DENIED: 
            FatalError(" [SnortSam_SERVICE] %s Access is denied. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_INVALID_HANDLE: 
            FatalError(" [SnortSam_SERVICE] %s Invalid handle. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_INVALID_NAME: 
            FatalError(" [SnortSam_SERVICE] %s Invalid name. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_SERVICE_DOES_NOT_EXIST: 
            FatalError(" [SnortSam_SERVICE] %s Service does not exist. %s", lpszBasicMessage, szMsg);
            break;

        default: 
            FatalError(" [SnortSam_SERVICE] %s Unrecognized error (%d). %s", lpszBasicMessage, dwErr, szMsg);
            break;
        }
    }
 
    if (! DeleteService(schService) ) 
    {
        DWORD dwErr = GetLastError();
        LPCTSTR lpszBasicMessage = "Unable to remove SnortSam from the Services database."; 
        TCHAR szMsg[1000];

        SvcFormatMessage(szMsg, sizeof(szMsg));
        switch(dwErr)
        {
        case ERROR_ACCESS_DENIED: 
            FatalError(" [SnortSam_SERVICE] %s Access is denied. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_INVALID_HANDLE: 
            FatalError(" [SnortSam_SERVICE] %s Invalid handle. %s", lpszBasicMessage, szMsg);
            break;

        case ERROR_SERVICE_MARKED_FOR_DELETE: 
            FatalError(" [SnortSam_SERVICE] %s Service already marked for delete. %s", lpszBasicMessage, szMsg);
            break;

        default: 
            FatalError(" [SnortSam_SERVICE] %s Unrecognized error (%d). %s", lpszBasicMessage, dwErr, szMsg);
            break;
        }
    }

    printf("\n");
    printf(" [SnortSam_SERVICE] Successfully removed the SnortSam service from the Services database.\n"); 
 
    CloseServiceHandle(schService); 
    CloseServiceHandle(schSCManager);
} 


VOID  ShowSnortSamServiceParams()
{
    int     argc;
    char ** argv;
    int i;

    ReadServiceCommandLineParams( &argc, &argv );

    printf("\n"
           "SnortSam is currently configured to run as a Windows service using the following\n"
           "command-line parameters:\n\n"
           "    ");

    for( i=1; i<=argc; i++ )
    {
        if( argv[i] != NULL )
        {
            printf(" %s", argv[i]);
            free( argv[i] );
            argv[i] = NULL;
        }
    }

    free( argv );
    argv = NULL;

    printf("\n");
}


#endif  /* ENABLE_WIN32_SERVICE */
#endif	/* WIN32 */

