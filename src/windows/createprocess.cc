/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Portable Runtime (NSPR).
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

/*
 * All code in this file is copy-pasted from different files in the NSPR source
 * tree. See the original copyright notice above from ntmisc.c (from which most
 * of the code is copied).
 *
 * This file implements the CreateProcessNoWindow() function, a workaround to
 * be used until the NSPR PR_CreateProcess() function has been updated to be
 * able to set the CREATE_NO_WINDOW flag to the Win32 CreateProcess() system
 * call.
 *
 * TODO(roubert): Delete this when NSPR has been updated.
 *
 * https://bugzilla.mozilla.org/show_bug.cgi?id=583223
 */

#define VC_EXTRALEAN /* Prevent windows.h from defining any cruft. */
#include <windows.h>

#include "prerr.h"
#include "prerror.h"
#include "prio.h"
#include "prmem.h"
#include "prtypes.h"

#ifdef _WIN64
typedef __int64 PROsfd;
#else
typedef PRInt32 PROsfd;
#endif

typedef enum {
    _PR_TRI_TRUE = 1,
    _PR_TRI_FALSE = 0,
    _PR_TRI_UNKNOWN = -1
} _PRTriStateBool;

struct _MDFileDesc {
    PROsfd osfd;     /* The osfd can come from one of three spaces:
                      * - For stdin, stdout, and stderr, we are using
                      *   the libc file handle (0, 1, 2), which is an int.
                      * - For files and pipes, we are using Win32 HANDLE,
                      *   which is a void*.
                      * - For sockets, we are using Winsock SOCKET, which
                      *   is a u_int.
                      */
    PRBool io_model_committed;  /* The io model (blocking or nonblocking)
                                 * for this osfd has been committed and
                                 * cannot be changed.  The osfd has been
                                 * either associated with the io
                                 * completion port or made nonblocking. */
    PRBool sync_file_io;        /* Use synchronous file I/O on the osfd
                                 * (a file handle) */
    PRBool accepted_socket;     /* Is this an accepted socket (on the
                                 * server side)? */
    PRNetAddr peer_addr;        /* If this is an accepted socket, cache
                                 * the peer's address returned by
                                 * AcceptEx().  This is to work around
                                 * the bug that getpeername() on an
                                 * socket accepted by AcceptEx() returns
                                 * an all-zero net address. */
};

struct PRFilePrivate {
    PRInt32 state;
    PRBool nonblocking;
    _PRTriStateBool inheritable;
    PRFileDesc *next;
    PRIntn lockCount;   /*   0: not locked
                         *  -1: a native lockfile call is in progress
                         * > 0: # times the file is locked */
#ifdef _PR_HAVE_PEEK_BUFFER
    char *peekBuffer;
    PRInt32 peekBufSize;
    PRInt32 peekBytes;
#endif
#if !defined(_PR_HAVE_O_APPEND)
    PRBool  appendMode; /* Some platforms don't have O_APPEND or its
                         * equivalent, so they have to seek to end of
                         * file on write if the file was opened in
                         * append mode.  See Bugzilla 4090, 276330. */
#endif
    _MDFileDesc md;
#ifdef _PR_NEED_SECRET_AF
    PRUint16 af;        /* If the platform's implementation of accept()
                         * requires knowing the address family of the
			 * socket, we save the address family here. */
#endif
};

struct _MDProcess {
    HANDLE handle;
    DWORD id;
};

struct PRProcess {
    _MDProcess md;
};

struct PRProcessAttr {
    PRFileDesc *stdinFd;
    PRFileDesc *stdoutFd;
    PRFileDesc *stderrFd;
    char *currentDirectory;
    char *fdInheritBuffer;
    PRSize fdInheritBufferSize;
    PRSize fdInheritBufferUsed;
};

/*
 * Assemble the command line by concatenating the argv array.
 * On success, this function returns 0 and the resulting command
 * line is returned in *cmdLine.  On failure, it returns -1.
 */
static int assembleCmdLine(char *const *argv, char **cmdLine)
{
    char *const *arg;
    char *p, *q;
    size_t cmdLineSize;
    int numBackslashes;
    int i;
    int argNeedQuotes;

    /*
     * Find out how large the command line buffer should be.
     */
    cmdLineSize = 0;
    for (arg = argv; *arg; arg++) {
        /*
         * \ and " need to be escaped by a \.  In the worst case,
         * every character is a \ or ", so the string of length
         * may double.  If we quote an argument, that needs two ".
         * Finally, we need a space between arguments, and
         * a null byte at the end of command line.
         */
        cmdLineSize += 2 * strlen(*arg)  /* \ and " need to be escaped */
                + 2                      /* we quote every argument */
                + 1;                     /* space in between, or final null */
    }
    p = *cmdLine = (char *)PR_MALLOC((PRUint32) cmdLineSize);
    if (p == NULL) {
        return -1;
    }

    for (arg = argv; *arg; arg++) {
        /* Add a space to separates the arguments */
        if (arg != argv) {
            *p++ = ' ';
        }
        q = *arg;
        numBackslashes = 0;
        argNeedQuotes = 0;

        /*
         * If the argument is empty or contains white space, it needs to
         * be quoted.
         */
        if (**arg == '\0' || strpbrk(*arg, " \f\n\r\t\v")) {
            argNeedQuotes = 1;
        }

        if (argNeedQuotes) {
            *p++ = '"';
        }
        while (*q) {
            if (*q == '\\') {
                numBackslashes++;
                q++;
            } else if (*q == '"') {
                if (numBackslashes) {
                    /*
                     * Double the backslashes since they are followed
                     * by a quote
                     */
                    for (i = 0; i < 2 * numBackslashes; i++) {
                        *p++ = '\\';
                    }
                    numBackslashes = 0;
                }
                /* To escape the quote */
                *p++ = '\\';
                *p++ = *q++;
            } else {
                if (numBackslashes) {
                    /*
                     * Backslashes are not followed by a quote, so
                     * don't need to double the backslashes.
                     */
                    for (i = 0; i < numBackslashes; i++) {
                        *p++ = '\\';
                    }
                    numBackslashes = 0;
                }
                *p++ = *q++;
            }
        }

        /* Now we are at the end of this argument */
        if (numBackslashes) {
            /*
             * Double the backslashes if we have a quote string
             * delimiter at the end.
             */
            if (argNeedQuotes) {
                numBackslashes *= 2;
            }
            for (i = 0; i < numBackslashes; i++) {
                *p++ = '\\';
            }
        }
        if (argNeedQuotes) {
            *p++ = '"';
        }
    }

    *p = '\0';
    return 0;
}

/*
 * Assemble the environment block by concatenating the envp array
 * (preserving the terminating null byte in each array element)
 * and adding a null byte at the end.
 *
 * Returns 0 on success.  The resulting environment block is returned
 * in *envBlock.  Note that if envp is NULL, a NULL pointer is returned
 * in *envBlock.  Returns -1 on failure.
 */
static int assembleEnvBlock(char **envp, char **envBlock)
{
    char *p;
    char *q;
    char **env;
    char *curEnv;
    char *cwdStart, *cwdEnd;
    size_t envBlockSize;

    if (envp == NULL) {
        *envBlock = NULL;
        return 0;
    }

    curEnv = GetEnvironmentStrings();

    cwdStart = curEnv;
    while (*cwdStart) {
        if (cwdStart[0] == '=' && cwdStart[1] != '\0'
                && cwdStart[2] == ':' && cwdStart[3] == '=') {
            break;
        }
        cwdStart += strlen(cwdStart) + 1;
    }
    cwdEnd = cwdStart;
    if (*cwdEnd) {
        cwdEnd += strlen(cwdEnd) + 1;
        while (*cwdEnd) {
            if (cwdEnd[0] != '=' || cwdEnd[1] == '\0'
                    || cwdEnd[2] != ':' || cwdEnd[3] != '=') {
                break;
            }
            cwdEnd += strlen(cwdEnd) + 1;
        }
    }
    envBlockSize = cwdEnd - cwdStart;

    for (env = envp; *env; env++) {
        envBlockSize += strlen(*env) + 1;
    }
    envBlockSize++;

    p = *envBlock = (char *)PR_MALLOC((PRUint32) envBlockSize);
    if (p == NULL) {
        FreeEnvironmentStrings(curEnv);
        return -1;
    }

    q = cwdStart;
    while (q < cwdEnd) {
        *p++ = *q++;
    }
    FreeEnvironmentStrings(curEnv);

    for (env = envp; *env; env++) {
        q = *env;
        while (*q) {
            *p++ = *q++;
        }
        *p++ = '\0';
    }
    *p = '\0';
    return 0;
}

/*
 * For qsort.  We sort (case-insensitive) the environment strings
 * before generating the environment block.
 */
static int compare(const void *arg1, const void *arg2)
{
    return _stricmp(* (char**)arg1, * (char**)arg2);
}

/*
 * This function does exactly the same as _PR_CreateWindowsProcess() except
 * that it sets the CREATE_NO_WINDOW flag in the CreateProcess() system call.
 */
PRProcess *CreateProcessNoWindow(
    const char *path,
    char *const *argv,
    char *const *envp,
    const PRProcessAttr *attr)
{
    STARTUPINFO startupInfo;
    PROCESS_INFORMATION procInfo;
    BOOL retVal;
    char *cmdLine = NULL;
    char *envBlock = NULL;
    char **newEnvp = NULL;
    const char *cwd = NULL; /* current working directory */
    PRProcess *proc = NULL;
    PRBool hasFdInheritBuffer;

    proc = PR_NEW(PRProcess);
    if (!proc) {
        PR_SetError(PR_OUT_OF_MEMORY_ERROR, 0);
        goto errorExit;
    }

    if (assembleCmdLine(argv, &cmdLine) == -1) {
        PR_SetError(PR_OUT_OF_MEMORY_ERROR, 0);
        goto errorExit;
    }

    /*
     * If attr->fdInheritBuffer is not NULL, we need to insert
     * it into the envp array, so envp cannot be NULL.
     */
    hasFdInheritBuffer = (attr && attr->fdInheritBuffer);
    if ((envp == NULL) && hasFdInheritBuffer) {
        envp = environ;
    }

    if (envp != NULL) {
        int idx;
        int numEnv;
        PRBool found = PR_FALSE;

        numEnv = 0;
        while (envp[numEnv]) {
            numEnv++;
        }
        newEnvp = (char **) PR_MALLOC((numEnv + 2) * sizeof(char *));
        for (idx = 0; idx < numEnv; idx++) {
            newEnvp[idx] = envp[idx];
            if (hasFdInheritBuffer && !found
                    && !strncmp(newEnvp[idx], "NSPR_INHERIT_FDS=", 17)) {
                newEnvp[idx] = attr->fdInheritBuffer;
                found = PR_TRUE;
            }
        }
        if (hasFdInheritBuffer && !found) {
            newEnvp[idx++] = attr->fdInheritBuffer;
        }
        newEnvp[idx] = NULL;
        qsort((void *) newEnvp, (size_t) idx, sizeof(char *), compare);
    }
    if (assembleEnvBlock(newEnvp, &envBlock) == -1) {
        PR_SetError(PR_OUT_OF_MEMORY_ERROR, 0);
        goto errorExit;
    }

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    if (attr) {
        PRBool redirected = PR_FALSE;

        /*
         * XXX the default value for stdin, stdout, and stderr
         * should probably be the console input and output, not
         * those of the parent process.
         */
        startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        if (attr->stdinFd) {
            startupInfo.hStdInput = (HANDLE) attr->stdinFd->secret->md.osfd;
            redirected = PR_TRUE;
        }
        if (attr->stdoutFd) {
            startupInfo.hStdOutput = (HANDLE) attr->stdoutFd->secret->md.osfd;
            redirected = PR_TRUE;
        }
        if (attr->stderrFd) {
            startupInfo.hStdError = (HANDLE) attr->stderrFd->secret->md.osfd;
            redirected = PR_TRUE;
        }
        if (redirected) {
            startupInfo.dwFlags |= STARTF_USESTDHANDLES;
        }
        cwd = attr->currentDirectory;
    }

    retVal = CreateProcess(NULL,
                           cmdLine,
                           NULL,  /* security attributes for the new
                                   * process */
                           NULL,  /* security attributes for the primary
                                   * thread in the new process */
                           TRUE,  /* inherit handles */
                           CREATE_NO_WINDOW,  /* creation flags */
                           envBlock,  /* an environment block, consisting
                                       * of a null-terminated block of
                                       * null-terminated strings.  Each
                                       * string is in the form:
                                       *     name=value
                                       * XXX: usually NULL */
                           cwd,  /* current drive and directory */
                           &startupInfo,
                           &procInfo
                          );

    if (retVal == FALSE) {
        /* XXX what error code? */
        PR_SetError(PR_UNKNOWN_ERROR, GetLastError());
        goto errorExit;
    }

    CloseHandle(procInfo.hThread);
    proc->md.handle = procInfo.hProcess;
    proc->md.id = procInfo.dwProcessId;

    PR_DELETE(cmdLine);
    if (newEnvp) {
        PR_DELETE(newEnvp);
    }
    if (envBlock) {
        PR_DELETE(envBlock);
    }
    return proc;

errorExit:
    if (cmdLine) {
        PR_DELETE(cmdLine);
    }
    if (newEnvp) {
        PR_DELETE(newEnvp);
    }
    if (envBlock) {
        PR_DELETE(envBlock);
    }
    if (proc) {
        PR_DELETE(proc);
    }
    return NULL;
}
