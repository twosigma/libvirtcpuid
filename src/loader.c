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

/*
 * We use pieces of the musl loader to avoid rewriting a loader from scratch.
 * musl loader is comprised of a few stages:
 * - stage1 does relative relocations (useful for our data sections, e.g.,
 *   global variables referring to the addresses of other global variables).
 * - stage2a does symbolic relocations (not that we need them as we don't
 *   export any symbols in our loader).
 * - stage2b initializes the tls. This is useful as errno is setup in the tls.
 * - stage3 does the rest (e.g., loading required libraries, invoking
 *   constructor, main).
 *
 * We replace the stage3 with our own. Note that we include musl .c files
 * because we need access to map_library(), which is a static function.
 */

/*
 * XXX stage2 invokes some syscalls:
 * - arch_prctl(ARCH_SET_FS, 0x7fdf59509428)
 * - set_tid_address(0x7fdf59509bd8)
 * Also, calling sigaction unblocks RT_1 and RT_2:
 * - rt_sigprocmask(SIG_UNBLOCK, [RT_1 RT_2], NULL, 8)
 * Ideally, we would not have any of this behavior, as it's not our
 * prerogative, but it seems to be fine.
 */

/* dlstart.c contains stage1 */
#include "../musl/ldso/dlstart.c"

/* dynlink.c contains stage2 and stage3 */
#undef _GNU_SOURCE /* dynlink.c defines it */
#define __dls3 orig_dls3 /* We override stage3 */
#include "../musl/ldso/dynlink.c"
#undef __dls3

#include "util.h"
#include "cpuid.h"
#include "config.h"
#include <err.h>
#include <stdbool.h>
#include <alloca.h>

/*
 * stage2 and stage3 are resolved via symbol lookup in dynlink.c, so we have
 * to export __dls2b and __dls3.
 */
LIB_EXPORT void __dls2b(size_t *sp);
LIB_EXPORT void __dls3(size_t *sp);
static void stage4(size_t *sp);

static void oom(void)
{
    err(1, "out of memory");
}

static char *xstrdup(const char *s)
{
    char *ret = strdup(s);
    if (!ret)
        oom();
    return ret;
}

static size_t get_file_size(int fd)
{
    struct stat stat;
    if (fstat(fd, &stat) == -1)
        err(1, "Can't stat file");
    return stat.st_size;
}

static void read_all(int fd, char* buf, size_t len)
{
    for (size_t i = 0; i < len;) {
        ssize_t ret = read(fd, buf+i, len-i);
        if (ret < 0)
            err(1, "Can't read file");
        i += ret;
    }
}

/* XXX returns a string on the heap */
static char *_unique_env_append(const char *name, const char *new_env, const char *sep)
{
    char *prev_env = getenv(name);
    if (!prev_env)
        return xstrdup(new_env);

    char *env;
    if (asprintf(&env, "%s%s%s", new_env, sep, prev_env) < 0)
        oom();

    /*
     * env is of the form "/some/lib1.so:/some/lib2.so:/some/lib1.so"
     * We have to take out duplicates, otherwise, we'll append the same
     * variables over and over when forking from a child.
     */

    char **items = NULL;
    int num_items = 0;
    char *saveptr;

    for (char *tok = strtok_r(env, sep, &saveptr); tok; tok = strtok_r(NULL, sep, &saveptr)) {
        bool duplicate = false;
        for (int i = 0; i < num_items; i++) {
            if (!strcmp(tok, items[i]))
                duplicate |= true;
        }

        if (duplicate)
            continue;

        num_items++;
        items = realloc(items, sizeof(*items)*num_items);
        if (!items)
            oom();
        items[num_items-1] = tok;
    }

    /* Join the strings with the separator */
    char *uenv = xstrdup(items[0]);
    for (int i = 1; i < num_items; i++) {
        char *tmp = uenv;
        asprintf(&uenv, "%s%s%s", uenv, sep, items[i]);
        free(tmp);
    }

    free(items);
    free(env);

    return uenv;
}

static char *unique_env_append(const char *name, const char *new_env, const char *sep)
{
    char *new_value = _unique_env_append(name, new_env, sep);
    char *ret;

    if (asprintf(&ret, "%s=%s", name, new_value) < 0)
        oom();

    free(new_value);
    return ret;
}

/* This does not include the NULL entry */
static int num_auxv_entries(size_t *auxv)
{
    int i;
    for (i=0; auxv[2*i]; i++);
    return i;
}

static int num_pointers(char **envp)
{
    int i;
    for (i=0; envp[i]; i++);
    return i;
}

#define GET_VAR_VALUE(tok, key) (                \
    !strncmp(tok, key "=", sizeof(key "=")-1) ?  \
       &tok[sizeof(key "=")-1] : NULL            \
)

static void inject_env_vars_heap(char *conf)
{
    char *saveptr;
    char *value;

    for (char *tok = strtok_r(conf, "\n", &saveptr); tok; tok = strtok_r(NULL, "\n", &saveptr)) {
        if (!strchr(tok, '='))
            err(1, "Incorrect env var: %s", tok);
        char *var = tok;

        if ((value = GET_VAR_VALUE(tok, "LD_PRELOAD")))
            var = unique_env_append("LD_PRELOAD", value, ":");
        else if ((value = GET_VAR_VALUE(tok, "VIRT_CPUID_MASK")))
            var = unique_env_append("VIRT_CPUID_MASK", value, ",");
        else
            var = xstrdup(tok);

        /*
         * Note that putenv() relocates the environ array on the heap,
         * but that's fine as we copy it back on the stack later.
         */
        putenv(var);
    }
}

static char *get_inject_env_file_content(void)
{
    int fd = open(LD_INJECT_ENV_PATH, O_RDONLY);
    if (fd < 0) {
        if (errno != ENOENT)
            err(1, "Can't open %s", LD_INJECT_ENV_PATH);
        return NULL;
    }

    size_t conf_len = get_file_size(fd);
    char *conf = malloc(conf_len+1);
    if (!conf)
        oom();
    conf[conf_len] = '\0';
    read_all(fd, conf, conf_len);
    close(fd);

    return conf;
}

static void inject_env_vars(size_t *sp)
{
    /*
     * We do the following:
     * 1) Locate argv, envp, auxv, similar to musl's stage3.
     * 2) Do nothing if LD_ENV_DISABLE is set
     * 3) Load the configuration file at LD_INJECT_ENV_PATH.
     *    Do nothing if the file doesn't exists
     * 4) The configuration file is a list of environment variables to
     *    set. Set all the variables in our environ. Note that
     *    LD_PRELOAD and VIRT_CPUID_MASK get special treatment of
     *    being appended to instead of overwritten
     * 5) Relocate all env variables on the heap to the stack
     * 6) Create the new argv, envp, auxv arrays on the stack
     * 7) Continue with stage 4
     *
     * The reason why we inject a list of environment variables from a
     * file is to prevent programs from manipulating the environment and
     * avoid our LD_PRELOADs. This will make sure we are in.
     *
     * Note: In the following, we free() pointers, but it doesn't matter,
     * because we'll use brk() to reset the heap, and never use our malloc
     * again.
     */

    int argc = *sp;
    size_t *auxv;
    char **argv = (void *)(sp+1);
    char **envp = argv+argc+1;
    int i;

    uintptr_t orig_brk = __syscall(SYS_brk, 0);

    __progname = LIB_NAME;
    __environ = envp;
    for (i=argc+1; argv[i]; i++);
    auxv = (void *)(argv+i+1);

    if (getenv("LD_ENV_DISABLE"))
        return;

    char *conf = get_inject_env_file_content();
    if (!conf)
        return;

    inject_env_vars_heap(conf);
    free(conf);

    /* Relocate heap allocated environment variables on the stack */
    for (char **var = environ; *var; var++) {
        /*
         * heap variables are necessarily at a lower address than
         * the address of `var`.
         */
        if ((void*)*var >= (void *)&var)
            continue;

        size_t len = strlen(*var);
        char *stackvar = alloca(len);
        memcpy(stackvar, *var, len+1);
        free(*var);
        *var = stackvar;
    }

    /*
     * Finally, construct the argv, envp, and auxv arrays, which must be
     * placed contiguously on the stack. It is what an ELF interpreter
     * expects.
     */
    struct __attribute__((packed)) {
        size_t argc;
        char *argv[argc+1];
        char *envp[num_pointers(environ)+1];
        size_t auxv[2*(num_auxv_entries(auxv)+1)];
    } new;

    new.argc = argc;
    memcpy(new.argv, argv, sizeof(new.argv));
    memcpy(new.envp, environ, sizeof(new.envp));
    memcpy(new.auxv, auxv, sizeof(new.auxv));

    __environ = new.envp; /* We access the environ later */
    __syscall(SYS_brk, orig_brk); /* Restore the heap like it was */

    /*
     * XXX at this point, malloc should no longer be used. we hand off the
     * heap region to the interposed libc.
     */
    stage4((void *)&new);
}

static void stage4(size_t *sp)
{
    /*
     * Install the SIGSEGV signal handler and enable faulting on the CPUID
     * instruction.
     */
    cpuid_init();

    /* And finally load and jump to the interposed libc loader */
    int fd = open(INTERPOSED_LD_PATH, O_RDONLY);
    if (fd < 0)
        err(1, "Can't open %s", INTERPOSED_LD_PATH);

    struct dso dso;
    Ehdr *ehdr = map_library(fd, &dso);
    if (!ehdr)
        errx(1, "Can't load %s", INTERPOSED_LD_PATH);
    close(fd);

    CRTJMP(laddr(&dso, ehdr->e_entry), sp);
    for(;;);
}

void __dls3(size_t *sp)
{
    inject_env_vars(sp);
    stage4(sp);
}
