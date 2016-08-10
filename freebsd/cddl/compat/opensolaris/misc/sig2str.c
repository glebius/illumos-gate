/*-
 * Copyright (c) 2016 John H. Baldwin <jhb@FreeBSD.org>
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <signal.h>
#include <stdio.h>
#include <string.h>

/* XXX: Eventually should use sysdecode_signal(). */
int
sig2str(int signum, char *str)
{

	if (signum > 0 && signum < NSIG) {
		strcpy(str, sys_signame[signum]);
		return (0);
	}
	if (signum == SIGTHR) {
		strcpy(str, "THR");
		return (0);
	}
	if (signum == SIGLIBRT) {
		strcpy(str, "LIBRT");
		return (0);
	}
	if (signum == SIGRTMIN) {
		strcpy(str, "RTMIN");
		return (0);
	}
	if (signum == SIGRTMAX) {
		strcpy(str, "RTMAX");
		return (0);
	}
	if (signum > SIGRTMIN && signum < SIGRTMAX) {
		if (signum <= (SIGRTMIN + SIGRTMAX) / 2)
			sprintf(str, "RTMIN+%d", signum - SIGRTMIN);
		else
			sprintf(str, "RTMAX-%d", SIGRTMAX - signum);
		return (0);
	}
	return (-1);
}
