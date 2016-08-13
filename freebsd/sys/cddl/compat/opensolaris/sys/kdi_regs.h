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
 *
 * $FreeBSD$
 */

#ifndef _OPENSOLARIS_KDI_REGS_H_
#define	_OPENSOLARIS_KDI_REGS_H_

#ifdef __amd64__
/* This matches the order in 'struct trapframe'. */

#define	KDIREG_RDI	0
#define	KDIREG_RSI	1
#define	KDIREG_RDX	2
#define	KDIREG_RCX	3
#define	KDIREG_R8	4
#define	KDIREG_R9	5
#define	KDIREG_RAX	6
#define	KDIREG_RBX	7
#define	KDIREG_RBP	8
#define	KDIREG_R10	9
#define	KDIREG_R11	10
#define	KDIREG_R12	11
#define	KDIREG_R13	12
#define	KDIREG_R14	13
#define	KDIREG_R15	14
#define	KDIREG_TRAPNO	15
#define	KDIREG_FS	16
#define	KDIREG_GS	17
#define	KDIREG_ADDR	18
#define	KDIREG_FLAGS	19
#define	KDIREG_ES	20
#define	KDIREG_DS	21
#define	KDIREG_ERR	22
#define	KDIREG_RIP	23
#define	KDIREG_CS	24
#define	KDIREG_RFLAGS	25
#define	KDIREG_RSP	26
#define	KDIREG_SS	27

#define	KDIREG_NGREG	28

#else
#error "Platform not supported."
#endif

#endif /* _OPENSOLARIS_KDI_REGS_H_ */
