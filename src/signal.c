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

#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/ucontext.h>
#include <dlfcn.h>

#include "cpuid.h"
#include "util.h"
#include "syscalls.h"

#include <err.h>
#include <stdbool.h>

/*
 * The goal of this DSO is to protect the signal handler the loader has setup.
 */

static int (*real_sigaction)(int signum, const struct sigaction *act, struct sigaction *oldact);

typedef bool (*chainable_sighandler)(int signal, siginfo_t *info, void *ucontext);

/* Previous signal handler */
static struct sigaction cpuid_sa;
static struct sigaction real_sa = {.sa_handler = SIG_DFL};
bool is_sigsegv_masked;

static bool init_done;

static void fatal_sigsegv() {
	struct sigaction new = { .sa_handler = SIG_DFL };
	if (real_sigaction(SIGSEGV, &new, NULL) < 0)
		err(1, "Failed to change SIGSEGV signal handler");

	/* Signal is fatal, so just re-raise it */
	tgkill(getpid(), gettid(), SIGSEGV);
	for(;;);
}

static void sigsegv_handler(int signal, siginfo_t *info, void *ucontext) {
	if (cpuid_sa.sa_handler != SIG_DFL) {
		/*
		 * Try the CPUID handler. It returns true if the signal was
		 * due to CPUID
		 */
		if (((chainable_sighandler)cpuid_sa.sa_sigaction)(signal, info, ucontext))
			return;
	}

	/* This was not a CPUID related signal. Fall back to original behavior */

	/* Note: sa_handler and sa_sigaction are unioned */
	if (real_sa.sa_handler == SIG_IGN ||
	    real_sa.sa_handler == SIG_DFL ||
	    is_sigsegv_masked) {
		fatal_sigsegv();
		/* not reached */
	}

	if (real_sa.sa_flags & SA_SIGINFO)
		real_sa.sa_sigaction(signal, info, ucontext);
	else
		real_sa.sa_handler(signal);

	if (real_sa.sa_flags & SA_RESETHAND)
		real_sa.sa_handler = SIG_DFL;
}

LIB_EXPORT
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	if (signum != SIGSEGV)
		return real_sigaction(signum, act, oldact);

	if (oldact)
		*oldact = real_sa;

	if (act)
		real_sa = *act;

	return 0;
}

static int (*real_sigprocmask)(int how, const sigset_t *_set, sigset_t *oldset);
LIB_EXPORT
int sigprocmask(int how, const sigset_t *_set, sigset_t *oldset)
{
	bool _is_sigsegv_masked = is_sigsegv_masked;

	const sigset_t *set = _set;

	/* We don't want the application to mask SIGSEGV */

	if (set) {
		sigset_t pset = *set;
		set = &pset;

		/*
		 * This might not work too well with threads.
		 * We might need to take locks.
		 */

		switch (how) {
		case SIG_BLOCK:
			if (sigismember(&pset, SIGSEGV)) {
				_is_sigsegv_masked = true;
				sigdelset(&pset, SIGSEGV);
			}
			break;
		case SIG_UNBLOCK:
			if (sigismember(&pset, SIGSEGV))
				_is_sigsegv_masked = false;
			break;
		case SIG_SETMASK:
			_is_sigsegv_masked = sigismember(&pset, SIGSEGV);
			sigdelset(&pset, SIGSEGV);
			break;
		}
	}

	int ret = real_sigprocmask(how, set, oldset);
	if (ret < 0)
		return ret;

	if (oldset) {
		if (is_sigsegv_masked)
			sigaddset(oldset, SIGSEGV);
		else
			sigdelset(oldset, SIGSEGV);
	}

	is_sigsegv_masked = _is_sigsegv_masked;
	return ret;
}

static void protect_sigsegv_cpuid_handler(void)
{
	struct sigaction sa = {
		.sa_sigaction = sigsegv_handler,
		.sa_flags = SA_SIGINFO,
	};

	/*
	 * XXX is_sigsegv_masked should be set to the old value when the
	 * loader called sigprocmask, But that's hard, so we punt for now.
	 * Note that sigprocmask traverses execve().
	 */

	/* Get the signal handler installed by cpuid_init() */
	if (real_sigaction(SIGSEGV, &sa, &cpuid_sa) < 0)
		err(1, "Failed to get original SIGSEGV handler");
}

/*
 * We can't get the real_dlsym via dlsym, as are overriding it.
 * So we use an internal libc function.
 * Is this a pile of hacks? yes. Does it work? yes.
 */
extern void *_dl_sym (void *handle, const char *name, void *who);

static void *(*real_dlsym)(void *handle, const char *symbol);
LIB_EXPORT
void *dlsym(void *handle, const char *symbol)
{
	/*
	 * Note: here we use __builtin_return_address, using dlsym would
	 * not work as another library might be hijacking it.
	 */
	if (!real_dlsym)
		real_dlsym = _dl_sym(RTLD_NEXT, "dlsym",
				     __builtin_return_address(0));

	/* The JVM gets sigaction via dlsym */
	if (!strcmp(symbol, "sigaction") && init_done)
		return sigaction;
	return real_dlsym(handle, symbol);
}

LIB_MAIN
void libvirtcpuid_init_dso(void)
{
	/*
	 * XXX if an other library init code calls sigaction() before
	 * our init function, we'll crash. It's easy to fix though.
	 */
	real_sigaction = dlsym(RTLD_NEXT, "sigaction");
	real_sigprocmask = dlsym(RTLD_NEXT, "sigprocmask");

	/*
	 * Enable CPUID faulting if the loader hasn't done it already.
	 */
	cpuid_init();

	/*
	 * As we are a shared library, we can interpose on sigaction to
	 * protect the SIGSEGV handler we installed.
	 */
	protect_sigsegv_cpuid_handler();

	init_done = true;
}
