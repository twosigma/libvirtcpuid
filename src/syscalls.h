/*
 * Copyright (C) 2019 Two Sigma Investments, LP.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __SYSCALLS_H__
#define __SYSCALLS_H__

#include <sys/syscall.h>

static inline int tgkill(int tgid, int tid, int sig)
{
	return syscall(SYS_tgkill, tgid, tid, sig);
}

static inline int gettid()
{
	return syscall(SYS_gettid);
}

static inline int arch_prctl(int code, unsigned long addr)
{
	return syscall(SYS_arch_prctl, code, addr);
}

#ifndef ARCH_GET_CPUID
#define ARCH_GET_CPUID 0x1011
#endif

#ifndef ARCH_SET_CPUID
#define ARCH_SET_CPUID 0x1012
#endif

#endif
