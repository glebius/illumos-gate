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

#include <sys/param.h>
#include <libproc.h>
#include <signal.h>
#include <string.h>

int
proc_str2sig(const char *str, int *signum)
{
	int i;

	/* Require a 'SIG' prefix. */
	if (strncasecmp(str, "SIG", 3) != 0)
		return (-1);
	str += 3;

	if (strcasecmp(str, "THR") == 0 ||
	    strcasecmp(str, "LWP") == 0) {
		*signum = SIGTHR;
		return (0);
	}
	if (strcasecmp(str, "LIBRT") == 0) {
		*signum = SIGLIBRT;
		return (0);
	}
	for (i = 1; i < NSIG; i++) {
		if (strcasecmp(str, sys_signame[i]) == 0) {
			*signum = i;
			return (0);
		}
	}
	return (-1);
}

/* XXX: This isn't really quite right. */
static
#include <sys/kern/syscalls.c>

int
proc_str2sys(const char *str, int *sysnum)
{
	unsigned i;

	for (i = 0; i < nitems(syscallnames); i++)
		if (strcmp(syscallnames[i], str) == 0) {
			*sysnum = i;
			return (0);
		}
	return (-1);
}

/* XXX: I am not sure what fault names this expects. */
int
proc_str2flt(const char *str, int *fltnum)
{
	return (-1);
}
