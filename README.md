# libvirtcpuid

libvirtcpuid provides transparent CPUID virtualization on Linux for the x86-64
architecture, all in userspace.

## Problem description

The x86 CPUID instruction is used by applications to learn information about the
features and capabilities of the current processor. CPUID virtualization allows
one to intercept these queries and report different features and capabilities
than what the CPU actually supports (typically a subset).

Virtualizing CPUID is useful when migrating applications across different
families of CPUs with a tool such as [CRIU](https://criu.org/). The following
examples describe some typical issues encountered without CPUID virtualization:

* Suppose an application is started on a host which supports the AVX instruction
  set. On startup, the application detects the AVX capability by invoking the
  CPUID instruction and chooses to use AVX-enabled versions of certain functions,
  such as `memcpy`. If the running application is migrated to a non-AVX capable
  host, the application, oblivious to the migration, keeps running its AVX code
  paths, and crashes with a `SIGILL` soon after.

  In this example, if we were to hide the AVX feature during application startup,
  it would still run correctly once migrated. Of course this also means that the
  application cannot benefit from the AVX capabilities on the first host,
  incurring a performance penalty.

* Suppose the opposite example, where the application starts on a non-AVX
  capable host, and is then migrated to an AVX capable host. This can lead to
  interesting problems: glibc performs lazy resolution of shared library
  function symbols for performance and compatibility improvements. That is,
  functions like `printf` are only resolved when first called.

  During lazy symbol resolution, glibc must preserve all CPU registers.
  For this, it uses the XSAVE instruction. This pushes up to 3kB of data on the
  stack depending on the CPU features (AVX512 registers are large!). To know how
  much stack space glibc must reserve for the XSAVE instruction, it queries
  the size of the XSAVE area with the CPUID instruction at startup. In our example, the
  application initializes with a small XSAVE area, and then migrates to a
  more capable CPU which requires a larger XSAVE area. Once migrated, at the next lazy
  symbol resolution, glibc executes the XSAVE instruction, which writes past
  the end of the save area, corrupting the stack, resulting in a crash or incorrect
  behavior.

  We can use `libvirtcpuid` to make CPUID report a larger XSAVE area on the
  original host to ensure successful migration to hosts with larger XSAVE areas.

## Usage

### Compilation

Compile with `make`.
It should generate three files:
* `ld-virtcpuid.so`: The loader to replace the real libc loader.
* `libvirtcpuid.so`: The shared library to set as `LD_PRELOAD`.
* `lcd_mask/lcd_mask.py`: Tool for generating feature masks.

### Masking features system-wide via the loader

This is the most robust form of user-space virtualization.

1. Copy `/lib64/ld-linux-x86-64.so.2` to `/lib64/ld-linux-x86-64.so.2.orig`, and
replace `/lib64/ld-linux-x86-64.so.2` with `ld-virtcpuid.so`.

Note that the path of the original libc loader can be configured during
compilation with `make INTERPOSED_LD_PATH=/path/to/ld-orig.so`.

2. Write the following to `/etc/ld-inject.env`:
```bash
LD_PRELOAD=/path/to/libvirtcpuid.so
VIRT_CPUID_MASK=avx512f,hle,rtm,xsavearea=2696
```

Note that the path of the injected environment variables can be configured during
compilation with `make LD_INJECT_ENV_PATH=/path/to/ld-inject.env`

All non-static application should see a virtualized CPUID at this point.
Adapt `VIRT_CPUID_MASK` to your use case. It accepts values that are documented
in the CPU Features section.

Note that the environment variables injection can be disabled for a specific
program by setting the environment variable `LD_ENV_DISABLE=1` prior to running
the program.

### Masking features via the loader for specific programs

1. Instead of replacing the system-wide libc loader, you may use `patchelf` to
target specific binaries as such:
```bash
patchelf --set-interpreter /path/to/ld-virtcpuid.so /path/to/some-program
```
2. Write the `/etc/ld-inject.env` file as previously shown.

### Masking features via the shared library only

If the two previous options are not possible, run your program with:

```bash
LD_PRELOAD=/path/to/libvirtcpuid.so VIRT_CPUID_MASK=avx512f,hle,rtm,xsavearea=2696 some-program
```

This will enable CPUID virtualization right before the program runs, but after
libc initializes, which can be a problem for certain features.

## Implementation details

### Entry point

Our entry point is an ELF interpreter, `ld-libvirtcpuid.so` replacing
`/lib64/ld-linux-x86-64.so.2`, which we move to `/lib64/ld-linux-x86-64.so.2.orig`.
To avoid reinventing the wheel, we reuse the one from the
[musl libc](https://www.musl-libc.org/), an alternative libc.
In the following, the ELF interpreter is refered to as the ld loader, or simply
the loader.  We use musl loader
to do useful things such as applying relative relocations, which the kernel does
not do for us. Further, we can reuse code to load the original libc loader once
we activate CPUID virtualization. For more details, see `src/loader.c`. The
following describes why we choose to interpose the system ld loader.

To trap CPUID instructions, our implementation relies on the
`arch_prctl(ARCH_SET_CPUID)` system call introduced in Linux 4.12. It enables
CPUID instruction faulting for the calling thread.
This requires a CPU feature introduced with
[Ivy Bridge](https://en.wikipedia.org/wiki/Ivy_Bridge_(microarchitecture)).
Once enabled, executing a CPUID instruction triggers a `SIGSEGV`.
We catch the `SIGSEGV`, emulate the instruction, and resume the thread.
The major issue is to trap CPUID before glibc initializes.

The glibc loader performs CPU detection to determine among other things what
lazy resolution routine to use. More specifically, if it should use XSAVE or
XSAVEC, the latter being a compressed version of XSAVE, only present on certain
CPUs. We thus need to activate the CPUID virtualization before the loader.
This means that we must interpose the loader itself.

To understand how we solve this problem, it is useful to understand what happens
when an application starts. When an `execve()` system call is issued for a
specific ELF program, the kernel proceeds to read its headers, map its sections
into memory, perform relocations, prepare the stack with `argv` and `envp`, and,
for statically linked programs, jump to the specified entry point.
For dynamically linked programs (i.e., programs that uses shared
libraries), the kernel loads an interpreter specified in the ELF header instead,
typically `/lib64/ld-linux-x86-64.so.2`. This interpreter
operates in userspace and is in charge of loading the shared libraries of the
program, and the program itself. The interpreter is also known as the ld loader.
It is the one responsible to interpret the `LD_PRELOAD` environment variable if
that rings a bell.

There are two ways to hijack the loader. The first is to use `patchelf
--set-interpreter` on a specific program, modifying its ELF header to use our
interpreter.  The other is to replace `/lib64/ld-linux-x86-64.so.2` with our
version, affecting all programs on the system. We prefer the latter.

Note that this solution is less attractive than using a `LD_PRELOAD` only
solution for a non-root user due to the privileges it requires to apply
system-wide.
We attempted implementing an `LD_PRELOAD` only solution, but this resulted in a
brittle implementation as it required patching the detected CPU features in
glibc after the fact, and more importantly, patching the lazy resolution
routines (e.g., XSAVE vs XSAVEC), or patching already resolved symbols (e.g.,
memmove vs memmove-avx512).


### Environment variables
Other virtualization libraries can be used alongside libvirtcpuid, such as
libvirttime. Our libraries may need to control certain environment variables
such as `VIRT_CPUID_MASK`, or `LD_PRELOAD`. Following the goal of having an
entire container virtualized, we wish to restrict the ability of applications
to clear these environment variables during `execve()`.
We considered two solutions. First, we can interpose `execve()` and manipulate
the environment. Second, we can operate at the loader level. We chose the
latter, where our loader injects environment variables contained in the file
`/etc/ld-inject.env`.

### Trapping CPUID
Our loader installs a `SIGSEGV` signal handler and enables CPUID faulting before
jumping to the real libc loader. Another problem arises: applications can
replace our signal handler with their own, which is why we must virtualize the
`sigaction()` system call. Interposing such system call can be done in two ways.
One is using `ptrace()`, but this is impractical for performance and usability
problems. The second is using an `LD_PRELOAD` library to override the
`sigaction()` symbol. We cannot do that from our loader, as the real libc is
not yet present. Instead, we use a second library, `libvirtcpuid.so`, virtualizing
signal system calls to protect and hide our `SIGSEGV` handler.

### Masking CPU features
The [CPUID instruction](https://en.wikipedia.org/wiki/CPUID) takes two
arguments: one in the EAX register denoting the _leaf_, and one in the ECX
register denoting the _subleaf_. For a given leaf and subleaf, the instruction
returns results in the EAX, EBX, ECX, and EDX registers. Features are
represented by certain bits in these registers. To mask a certain CPU feature,
all we need to do is unset its corresponding bit.

The mapping {CPU feature} to {leaf,subleaf,bit} is poorly documented. However, the
Linux kernel source code contains a fairly up to date mapping. We reuse their
sources without modifications to recognize most CPU features (see `src/linux`).
Additionally, they include dependencies between features.

## CPU Features

### Homogenous CPU features on multiple machines
When running an application on a set of hosts with heterogeneous CPUs, it can
useful to present the application with a homogeneous CPU feature set.
To help find the lowest common denominator of the CPU features, we provide a tool:
`lcd_mask/lcd_mask.py`. It takes a list of files, generated from the output of
`cpuid -1 -r` on each machine. The tool emits a mask suitable for
libvirtcpuid to present a homogeneous feature set by identifying the set of
features which are present on all tested hosts.

### List of CPU Features

libvirtcpuid recognizes the following CPU features:

`3dnow`, `3dnowext`, `3dnowprefetch`, `abm`, `ace`, `ace2`, `ace2_en`, `ace_en`,
`acpi`, `adx`, `aes`, `amd_ibpb`, `amd_ibrs`, `amd_ppin`, `amd_ssbd`,
`amd_ssb_no`, `amd_stibp`, `amd_stibp_always_on`, `apic`, `arat`,
`arch_capabilities`, `avic`, `avx`, `avx2`, `avx512_4fmaps`, `avx512_4vnniw`,
`avx512_bf16`, `avx512_bitalg`, `avx512bw`, `avx512cd`, `avx512dq`, `avx512er`,
`avx512f`, `avx512ifma`, `avx512pf`, `avx512vbmi`, `avx512_vbmi2`, `avx512vl`,
`avx512_vnni`, `avx512_vp2intersect`, `avx512_vpopcntdq`, `bmi1`, `bmi2`,
`bpext`, `cid`, `cldemote`, `clflush`, `clflushopt`, `clwb`, `clzero`, `cmov`,
`cmp_legacy`, `core_capabilities`, `cqm`, `cr8_legacy`, `cx16`, `cx8`, `dca`,
`de`, `decodeassists`, `ds_cpl`, `dtes64`, `dtherm`, `dts`, `erms`, `est`,
`extapic`, `f16c`, `fdp_excptn_only`, `flushbyasid`, `flush_l1d`, `fma`, `fma4`,
`fpu`, `fsgsbase`, `fsrm`, `fxsr`, `fxsr_opt`, `gfni`, `hle`, `ht`, `hwp`,
`hwp_act_window`, `hwp_epp`, `hwp_notify`, `hwp_pkg_req`, `hypervisor`, `ia64`,
`ibs`, `ida`, `intel_pt`, `intel_stibp`, `invpcid`, `irperf`, `la57`, `lahf_lm`,
`lbrv`, `lm`, `longrun`, `lrti`, `lwp`, `mca`, `mce`, `md_clear`, `misalignsse`,
`mmx`, `mmxext`, `monitor`, `movbe`, `movdir64b`, `movdiri`, `mp`, `mpx`, `msr`,
`mtrr`, `mwaitx`, `nodeid_msr`, `npt`, `nrip_save`, `nx`, `ospke`, `osvw`,
`osxsave`, `overflow_recov`, `pae`, `pat`, `pausefilter`, `pbe`, `pcid`,
`pclmulqdq`, `pconfig`, `pdcm`, `pdpe1gb`, `perfctr_core`, `perfctr_llc`,
`perfctr_nb`, `pfthreshold`, `pge`, `phe`, `phe_en`, `pku`, `pln`, `pmm`,
`pmm_en`, `pn`, `pni`, `popcnt`, `pse`, `pse36`, `pts`, `ptsc`, `rdpid`,
`rdpru`, `rdrand`, `rdseed`, `rdt_a`, `rdtscp`, `recovery`, `rng`, `rng_en`,
`rtm`, `sdbg`, `sep`, `sha_ni`, `skinit`, `smap`, `smca`, `smep`, `smx`,
`spec_ctrl`, `spec_ctrl_ssbd`, `ss`, `sse`, `sse2`, `sse4_1`, `sse4_2`, `sse4a`,
`ssse3`, `succor`, `svm`, `svm_lock`, `syscall`, `tbm`, `tce`, `tm`, `tm2`,
`tme`, `topoext`, `tsc`, `tsc_adjust`, `tsc_deadline_timer`, `tsc_scale`,
`tsx_force_abort`, `umip`, `vaes`, `vgif`, `virt_ssbd`, `vmcb_clean`, `vme`,
`vmx`, `vpclmulqdq`, `v_vmsave_vmload`, `waitpkg`, `wbnoinvd`, `wdt`, `x2apic`,
`xgetbv1`, `xop`, `xsave`, `xsavec`, `xsaveerptr`, `xsaveopt`, `xsaves`, `xtpr`,
`zero_fcs_fds`

In addition:
* `xsavearea=SIZE` can be used to set the xsave area size.
* `leaf_subleaf_reg_bit` can be used to mask unknown features. e.g., `7_1_ecx_12`).
   There is a limitation that only known CPUID leaves are supported.

## License

The code is licensed under the GPLv2 license.
It contains sources of Linux (GPLv2), and musl (MIT).
