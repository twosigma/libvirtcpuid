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

#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ucontext.h>
#include <string.h>
#include <err.h>
#include <ctype.h>
#include <stdbool.h>
#include <signal.h>

#include "syscalls.h"
#include "cpuid.h"
#include "util.h"

#include "linux/cpufeatures.h"
#include "linux/cpuid.h"
#include "linux/cpuid-deps.c"
#include "linux/capflags.c"

/*
 * When this file is part of the loader, the heap must remain untouched. No
 * malloc() is permitted. See src/loader.c for more details.
 */

static bool emit_debug;
static bool suppress_output;

#define debug(s, ...) ({ if (emit_debug && !suppress_output) warnx(s, ##__VA_ARGS__); })

#define secure_err(exit_code, fmt, ...) ({  \
    if (suppress_output)                    \
        exit(exit_code);                    \
    else                                    \
        err(exit_code, fmt, ##__VA_ARGS__); \
})

#define secure_errx(exit_code, fmt, ...) ({  \
    if (suppress_output)                     \
        exit(exit_code);                     \
    else                                     \
        errx(exit_code, fmt, ##__VA_ARGS__); \
})

uint32_t xsavearea_size = -1;
uint32_t cpuid_mask[NCAPINTS];

static enum cpuid_regs_idx get_reg_from_name(const char *regname)
{
    if (!strcmp(regname, "eax")) return CPUID_EAX;
    if (!strcmp(regname, "ebx")) return CPUID_EBX;
    if (!strcmp(regname, "ecx")) return CPUID_ECX;
    if (!strcmp(regname, "edx")) return CPUID_EDX;
    return -1;
}

static const char* get_regname(enum cpuid_regs_idx reg)
{
    switch (reg) {
        case CPUID_EAX: return "eax";
        case CPUID_EBX: return "ebx";
        case CPUID_ECX: return "ecx";
        case CPUID_EDX: return "edx";
        default: return NULL;
    }
}

static void mask_cpuid_feature(int feature)
{
    if (emit_debug) {
        const struct cpuid_reg *lr = &reverse_cpuid[feature/32];
        debug("masking leaf=0x%08x subleaf=0x%02x reg=%s bit=%d",
              lr->leaf, lr->subleaf, get_regname(lr->reg), feature%32);
    }
    cpuid_mask[feature/32] |= (1 << (feature % 32));
}

static bool is_cpuid_feature_masked(int feature)
{
    return !!(cpuid_mask[feature/32] & (1 << (feature % 32)));
}

/*
 * Some of the described features are linux defined features (e.g.
 * cpuid_fault). This function distinguishes this case.
 */
static bool has_feature_register_mask(int feature)
{
    return !!reverse_cpuid[feature/32].leaf;
}

static int get_next_matching_leaf_index(uint32_t leaf, uint32_t subleaf, int from_index)
{
    if (leaf == 0)
        return -1;

    for (int i = from_index; i < NCAPINTS; i++) {
        if (reverse_cpuid[i].leaf == leaf &&
            (reverse_cpuid[i].subleaf == SL_UNUSED ||
             reverse_cpuid[i].subleaf == subleaf))
            return i;
    }

    return -1;
}

static int get_leaf_reg_index(uint32_t leaf, uint32_t subleaf, enum cpuid_regs_idx reg)
{
    int i;

    for (i = get_next_matching_leaf_index(leaf, subleaf, 0); i >= 0;
         i = get_next_matching_leaf_index(leaf, subleaf, i+1)) {
        if (reverse_cpuid[i].reg == reg)
            return i;
    }

    return -1;
}

static void show_help_and_die(void)
{
    printf("VIRT_CPUID_MASK recognizes the following features:\n");

    for (int feature = 0; feature < NCAPINTS*32; feature++) {
        const char *name = x86_cap_flags[feature];
        if (name && has_feature_register_mask(feature))
            printf("%s\n", name);
    }
    exit(0);
}

static int find_cpuid_feature_generic(const char *feature_name)
{
    uint32_t leaf, subleaf;
    char regname[4];
    int leaf_index;
    int reg;
    unsigned int bit;

    if (sscanf(feature_name, "%x_%x_%3[^_]_%u", &leaf, &subleaf, regname, &bit) != 4)
        return -1;

    reg = get_reg_from_name(regname);
    if (reg == -1)
        return -1;

    if (bit > 31)
        return -1;

    leaf_index = get_leaf_reg_index(leaf, subleaf, reg);
    if (leaf_index == -1)
        return -1;

    return leaf_index * 32 + bit;
}

static int find_cpuid_feature(const char *feature_name)
{
    if (!strcmp(feature_name, "avx512"))
        feature_name = "avx512f";

    for (int feature = 0; feature < NCAPINTS*32; feature++) {
        const char *name = x86_cap_flags[feature];
        if (name && !strcmp(name, feature_name) &&
            has_feature_register_mask(feature))
            return feature;
    }

    return find_cpuid_feature_generic(feature_name);
}

static void enable_feature_mask(const char *name)
{
#define XSAVEAREA "xsavearea="
    if (!strncmp(name, XSAVEAREA, sizeof(XSAVEAREA)-1)) {
        xsavearea_size = atoi(name+sizeof(XSAVEAREA)-1);
        debug("Setting xsavearea=%d", xsavearea_size);
        return;
    }

    int feature = find_cpuid_feature(name);
    if (feature == -1) {
        if (!strcmp(name, "help"))
            show_help_and_die();
        secure_errx(1, "Unrecognized cpu feature flag: %s", name);
    }

    mask_cpuid_feature(feature);
}

static void mask_dependent_features(void)
{
    /*
     * This is useful for example when the user masks avx512f. We should
     * ensure in this case that the avx512 friends (e.g., avx512cd,
     * avx512dq) get masked as well.
     */

    bool changed;
    do {
        changed = false;
        for (const struct cpuid_dep *d = cpuid_deps; d->feature; d++) {
            if (is_cpuid_feature_masked(d->depends) &&
                !is_cpuid_feature_masked(d->feature)) {
                mask_cpuid_feature(d->feature);
                changed = true;
            }
        }
    } while (changed);
}

static void init_cpuid_mask(const char *_conf)
{
    size_t len = strlen(_conf);
    char conf[len+1];

    for (int i = 0; i < len+1; i++)
        conf[i] = tolower((unsigned int)_conf[i]);

    char *saveptr;
    const char *sep = ",";
    for (char *tok = strtok_r(conf, sep, &saveptr); tok; tok = strtok_r(NULL, sep, &saveptr))
        enable_feature_mask(tok);

    mask_dependent_features();
}

static void virtualize_cpuid(uint32_t leaf, uint32_t subleaf, struct cpuid_regs *regs)
{
    int i;

    if (leaf == 0x0d && subleaf == 0 && xsavearea_size != -1) {
        debug("Overriding xsavearea=%d", xsavearea_size);
        if (regs->ebx && xsavearea_size && regs->ebx > xsavearea_size)
            secure_errx(1, "xsavearea_size is too small."
                        "It should be at least %d bytes", regs->ebx);

        regs->ebx = xsavearea_size;
        regs->ecx = xsavearea_size;
    }

    for (i = get_next_matching_leaf_index(leaf, subleaf, 0); i >= 0;
         i = get_next_matching_leaf_index(leaf, subleaf, i+1)) {
        switch (reverse_cpuid[i].reg) {
            case CPUID_EAX: regs->eax &= ~cpuid_mask[i]; break;
            case CPUID_EBX: regs->ebx &= ~cpuid_mask[i]; break;
            case CPUID_ECX: regs->ecx &= ~cpuid_mask[i]; break;
            case CPUID_EDX: regs->edx &= ~cpuid_mask[i]; break;
        }
    }
}

static inline void cpuid(uint32_t leaf, uint32_t subleaf,
                         uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    __asm__ ("cpuid"
             : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
             : "0" (leaf), "2" (subleaf)
             : "memory");
}

#define UCTX_REG(uctx, reg)	((ucontext_t *)uctx)->uc_mcontext.gregs[REG_R##reg]

static void cpuid_handle_trap(void *uctx)
{
    uint32_t leaf    = UCTX_REG(uctx, AX);
    uint32_t subleaf = UCTX_REG(uctx, CX);
    struct cpuid_regs regs;

    debug("Intercepted call to CPUID, leaf=0x%08x subleaf=%d", leaf, subleaf);

    /*
     * Disabling CPUID faulting temporarily for the current thread.
     */
    if (arch_prctl(ARCH_SET_CPUID, 1) < 0)
        secure_err(1, "Failed to disable CPUID faulting");

    cpuid(leaf, subleaf, &regs.eax, &regs.ebx, &regs.ecx, &regs.edx);
    if (arch_prctl(ARCH_SET_CPUID, 0) < 0)
        secure_err(1, "Failed to re-enable CPUID faulting");

    virtualize_cpuid(leaf, subleaf, &regs);

    UCTX_REG(uctx, IP) += 2; /* size of CPUID opcode */
    UCTX_REG(uctx, AX) = regs.eax;
    UCTX_REG(uctx, BX) = regs.ebx;
    UCTX_REG(uctx, CX) = regs.ecx;
    UCTX_REG(uctx, DX) = regs.edx;
}

/*
 * Our signal handler has a return value:
 * - It returns true if the signal was handled
 * - It return false otherwise. The signal should be passed to the next
 *   handler.
 */
#define CPUID_OPCODE 0xa20f
static bool sigsegv_handler(int signal, siginfo_t *info, void *uctx)
{
    if (info->si_code != SI_KERNEL)
        return false;

    if (*(uint16_t *)UCTX_REG(uctx, IP) != CPUID_OPCODE)
        return false;

    cpuid_handle_trap(uctx);
    return true;
}

static void setup_sigsegv_cpuid_handler(void)
{
    struct sigaction sa = {
        .sa_sigaction = (void *)sigsegv_handler,
        .sa_flags = SA_SIGINFO,
    };

    if (sigaction(SIGSEGV, &sa, NULL) < 0)
        secure_err(1, "Failed to register SIGSEGV handler");

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGSEGV);
    if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) < 0)
        secure_err(1, "Failed to unblock SIGSEGV");
}

void cpuid_init(bool secure)
{
    /*
     * When we are running in secure mode (setuid), only what is set in the
     * LD_INJECT_ENV_PATH file is visible, not the regular environment.
     * and so using getenv() here is safe.
     *
     * TODO LD_PRELOAD is ignored for setuid programs. We should preload our
     * libvirtcpuid.so even in setuid programs to protect our SIGSEGV handler.
     */
    emit_debug = !!getenv("VIRT_CPUID_DEBUG");

    char *conf = getenv("VIRT_CPUID_MASK");
    if (!conf) {
        debug("VIRT_CPUID_MASK not set. Skipping virtualization");
        return;
    }

    if (!strcmp(conf, "help"))
        show_help_and_die();

    bool faulting_disabled;
    if ((faulting_disabled = arch_prctl(ARCH_GET_CPUID, 0)) < 0)
        secure_err(1, "CPUID faulting feature inaccessible");

    /*
     * When the DSO loads, it calls cpuid_init(). This is to support
     * running without the loader. So we check if we already have
     * the faulting feature enabled.
     */
    if (!faulting_disabled)
        return;

    init_cpuid_mask(conf);
    setup_sigsegv_cpuid_handler();

    if (arch_prctl(ARCH_SET_CPUID, 0) < 0)
        secure_err(1, "Failed to enable CPUID faulting");

    /*
     * For secure programs, we don't want to emit output past the
     * initialization phase. This is to prevent an attacker to write to
     * stderr if it gets re-opened by our current process.
     */
    if (secure)
        suppress_output = true;
}
