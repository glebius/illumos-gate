/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _OPENSOLARIS_SYS_STROPTS_H
#define	_OPENSOLARIS_SYS_STROPTS_H

/*
 * Flush options
 */

#define	FLUSHR		0x01		/* flush read queue */
#define	FLUSHW		0x02		/* flush write queue */
#define	FLUSHRW		0x03		/* flush both queues */
#define	FLUSHBAND	0x04		/* flush only band specified */

/*
 *  Stream Ioctl defines
 */
#define	STR		('S'<<8)
#define	I_FLUSH		(STR|05)
	
#endif /* _OPENSOLARIS_SYS_STROPTS_H */
