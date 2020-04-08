/*
 * The content of this file is adapted from the Linux kernel:
 * - arch/x86/kvm/cpuid.h
 */

/* SPDX-License-Identifier: GPL-2.0 */

struct cpuid_regs {
	uint32_t eax, ebx, ecx, edx;
};

enum cpuid_regs_idx {
	CPUID_EAX = 0,
	CPUID_EBX,
	CPUID_ECX,
	CPUID_EDX,
};

struct cpuid_reg {
	uint32_t leaf;
	uint32_t subleaf;
	int reg;
};

#define SL_UNUSED -1

static const struct cpuid_reg reverse_cpuid[] = {
	[CPUID_1_EDX]         = {         1, SL_UNUSED, CPUID_EDX},
	[CPUID_8000_0001_EDX] = {0x80000001, SL_UNUSED, CPUID_EDX},
	[CPUID_8086_0001_EDX] = {0x80860001, SL_UNUSED, CPUID_EDX},
	[CPUID_1_ECX]         = {         1, SL_UNUSED, CPUID_ECX},
	[CPUID_C000_0001_EDX] = {0xc0000001, SL_UNUSED, CPUID_EDX},
	[CPUID_8000_0001_ECX] = {0x80000001, SL_UNUSED, CPUID_ECX},
	[CPUID_7_0_EBX]       = {         7,         0, CPUID_EBX},
	[CPUID_D_1_EAX]       = {       0xd,         1, CPUID_EAX},
	[CPUID_7_1_EAX]       = {         7,         1, CPUID_EAX},
	[CPUID_8000_0008_EBX] = {0x80000008, SL_UNUSED, CPUID_EBX},
	[CPUID_6_EAX]         = {         6, SL_UNUSED, CPUID_EAX},
	[CPUID_8000_000A_EDX] = {0x8000000a, SL_UNUSED, CPUID_EDX},
	[CPUID_7_ECX]         = {         7,         0, CPUID_ECX},
	[CPUID_8000_0007_EBX] = {0x80000007, SL_UNUSED, CPUID_EBX},
	[CPUID_7_EDX]         = {         7,         0, CPUID_EDX},
};
