// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use block::{BLKDISCARD, BLKZEROOUT};
use libc::{FIONBIO, TIOCGWINSZ, TUNSETOFFLOAD};
use seccompiler::SeccompCmpOp::Eq;
use seccompiler::{
    BpfProgram, Error, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCondition as Cond,
    SeccompFilter, SeccompRule,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Thread {
    VirtioBalloon,
    VirtioBlock,
    VirtioConsole,
    VirtioIommu,
    VirtioMem,
    VirtioNet,
    VirtioNetCtl,
    VirtioPmem,
    VirtioRng,
    VirtioRtc,
    VirtioFs,
    VirtioVhostBlock,
    VirtioVhostFs,
    VirtioGenericVhostUser,
    VirtioVhostNet,
    VirtioVhostNetCtl,
    VirtioVsock,
    VirtioWatchdog,
}

impl Thread {
    const ALL: [Self; 18] = [
        Self::VirtioBalloon,
        Self::VirtioBlock,
        Self::VirtioConsole,
        Self::VirtioIommu,
        Self::VirtioMem,
        Self::VirtioNet,
        Self::VirtioNetCtl,
        Self::VirtioPmem,
        Self::VirtioRng,
        Self::VirtioRtc,
        Self::VirtioFs,
        Self::VirtioVhostBlock,
        Self::VirtioVhostFs,
        Self::VirtioGenericVhostUser,
        Self::VirtioVhostNet,
        Self::VirtioVhostNetCtl,
        Self::VirtioVsock,
        Self::VirtioWatchdog,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::VirtioBalloon => "virtio-balloon",
            Self::VirtioBlock => "virtio-block",
            Self::VirtioConsole => "virtio-console",
            Self::VirtioIommu => "virtio-iommu",
            Self::VirtioMem => "virtio-mem",
            Self::VirtioNet => "virtio-net",
            Self::VirtioNetCtl => "virtio-net-ctl",
            Self::VirtioPmem => "virtio-pmem",
            Self::VirtioRng => "virtio-rng",
            Self::VirtioRtc => "virtio-rtc",
            Self::VirtioFs => "virtio-fs",
            Self::VirtioVhostBlock => "virtio-vhost-block",
            Self::VirtioVhostFs => "virtio-vhost-fs",
            Self::VirtioGenericVhostUser => "virtio-generic-vhost-user",
            Self::VirtioVhostNet => "virtio-vhost-net",
            Self::VirtioVhostNetCtl => "virtio-vhost-net-ctl",
            Self::VirtioVsock => "virtio-vsock",
            Self::VirtioWatchdog => "virtio-watchdog",
        }
    }
}

struct CachedFilter {
    action: SeccompAction,
    thread: Thread,
    program: Arc<BpfProgram>,
}

static FILTER_CACHE: OnceLock<Mutex<Vec<CachedFilter>>> = OnceLock::new();

pub(crate) struct FilterLookup {
    pub program: Arc<BpfProgram>,
    pub cache_hit: bool,
    pub build_us: u128,
    pub lookup_us: u128,
}

pub struct PrecompileSummary {
    pub filter_count: usize,
    pub cache_hits: usize,
    pub build_us: u128,
}

/// Shorthand for chaining `SeccompCondition`s with the `and` operator  in a `SeccompRule`.
/// The rule will take the `Allow` action if _all_ the conditions are true.
///
/// [`SeccompCondition`]: struct.SeccompCondition.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! and {
    ($($x:expr),*) => (SeccompRule::new(vec![$($x),*]).unwrap())
}

/// Shorthand for chaining `SeccompRule`s with the `or` operator in a `SeccompFilter`.
///
/// [`SeccompFilter`]: struct.SeccompFilter.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! or {
    ($($x:expr,)*) => (vec![$($x),*]);
    ($($x:expr),*) => (vec![$($x),*])
}

// See include/uapi/linux/vfio.h in the kernel code.
const VFIO_IOMMU_MAP_DMA: u64 = 0x3b71;
const VFIO_IOMMU_UNMAP_DMA: u64 = 0x3b72;

// See include/uapi/linux/iommufd.h in the kernel code.
const IOMMU_IOAS_MAP: u64 = 0x3b85;
const IOMMU_IOAS_UNMAP: u64 = 0x3b86;

#[cfg(feature = "sev_snp")]
fn mshv_sev_snp_ioctl_seccomp_rule() -> SeccompRule {
    and![
        Cond::new(
            1,
            ArgLen::Dword,
            Eq,
            mshv_ioctls::MSHV_MODIFY_GPA_HOST_ACCESS()
        )
        .unwrap()
    ]
}

#[cfg(feature = "sev_snp")]
fn create_mshv_sev_snp_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![mshv_sev_snp_ioctl_seccomp_rule()]
}

fn create_virtio_console_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, TIOCGWINSZ as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn create_virtio_iommu_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_MAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_UNMAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, IOMMU_IOAS_MAP).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, IOMMU_IOAS_UNMAP).unwrap()],
    ]
}

fn create_virtio_mem_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_MAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_UNMAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, IOMMU_IOAS_MAP).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, IOMMU_IOAS_UNMAP).unwrap()],
    ]
}

fn virtio_balloon_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_fallocate, vec![])]
}

fn virtio_block_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_fcntl, vec![]),
        (libc::SYS_fdatasync, vec![]),
        (libc::SYS_fstat, vec![]),
        (libc::SYS_fsync, vec![]),
        (libc::SYS_ftruncate, vec![]),
        (libc::SYS_getrandom, vec![]),
        (libc::SYS_ioctl, create_virtio_block_ioctl_seccomp_rule()),
        (libc::SYS_io_destroy, vec![]),
        (libc::SYS_io_getevents, vec![]),
        (libc::SYS_io_submit, vec![]),
        (libc::SYS_io_uring_enter, vec![]),
        (libc::SYS_lseek, vec![]),
        (libc::SYS_newfstatat, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_preadv, vec![]),
        (libc::SYS_pwritev, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_sched_setaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_statx, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn create_virtio_block_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, BLKDISCARD as _).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, BLKZEROOUT as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn virtio_console_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_ioctl, create_virtio_console_ioctl_seccomp_rule()),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
    ]
}

fn virtio_iommu_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_ioctl, create_virtio_iommu_ioctl_seccomp_rule())]
}

fn virtio_mem_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_ioctl, create_virtio_mem_ioctl_seccomp_rule()),
        (libc::SYS_recvfrom, vec![]),
        (libc::SYS_sendmsg, vec![]),
    ]
}

fn virtio_net_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        #[cfg(feature = "sev_snp")]
        (libc::SYS_ioctl, create_mshv_sev_snp_ioctl_seccomp_rule()),
        (libc::SYS_readv, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
        (libc::SYS_writev, vec![]),
    ]
}

fn create_virtio_net_ctl_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, TUNSETOFFLOAD as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn virtio_net_ctl_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_ioctl, create_virtio_net_ctl_ioctl_seccomp_rule()),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn virtio_pmem_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_fsync, vec![])]
}

fn virtio_rng_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        #[cfg(feature = "sev_snp")]
        (libc::SYS_ioctl, create_mshv_sev_snp_ioctl_seccomp_rule()),
    ]
}

fn virtio_rtc_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        #[cfg(feature = "sev_snp")]
        (libc::SYS_ioctl, create_mshv_sev_snp_ioctl_seccomp_rule()),
    ]
}

fn virtio_vhost_fs_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, create_socket_seccomp_rule()),
        (libc::SYS_timerfd_create, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

pub fn virtio_fs_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_capget, vec![]),
        (libc::SYS_capset, vec![]),
        (libc::SYS_copy_file_range, vec![]),
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_fchdir, vec![]),
        (libc::SYS_fchmod, vec![]),
        (libc::SYS_fchmodat, vec![]),
        (libc::SYS_fchownat, vec![]),
        (libc::SYS_fdatasync, vec![]),
        (libc::SYS_fgetxattr, vec![]),
        (libc::SYS_flistxattr, vec![]),
        (libc::SYS_flock, vec![]),
        (libc::SYS_fremovexattr, vec![]),
        (libc::SYS_fsetxattr, vec![]),
        (libc::SYS_fstat, vec![]),
        (libc::SYS_fstatfs, vec![]),
        (libc::SYS_fsync, vec![]),
        (libc::SYS_ftruncate, vec![]),
        (libc::SYS_getdents64, vec![]),
        (libc::SYS_getegid, vec![]),
        (libc::SYS_geteuid, vec![]),
        (libc::SYS_getpid, vec![]),
        (libc::SYS_getrandom, vec![]),
        (libc::SYS_gettimeofday, vec![]),
        (libc::SYS_getxattr, vec![]),
        (libc::SYS_linkat, vec![]),
        (libc::SYS_listxattr, vec![]),
        (libc::SYS_lseek, vec![]),
        (libc::SYS_membarrier, vec![]),
        (libc::SYS_mkdirat, vec![]),
        (libc::SYS_mknodat, vec![]),
        (libc::SYS_name_to_handle_at, vec![]),
        (libc::SYS_newfstatat, vec![]),
        (libc::SYS_openat2, vec![]),
        (libc::SYS_open_by_handle_at, vec![]),
        (libc::SYS_prctl, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_preadv, vec![]),
        (libc::SYS_preadv2, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_pwritev, vec![]),
        (libc::SYS_pwritev2, vec![]),
        (libc::SYS_readlinkat, vec![]),
        (libc::SYS_readv, vec![]),
        #[cfg(not(target_arch = "riscv64"))]
        (libc::SYS_renameat, vec![]),
        (libc::SYS_renameat2, vec![]),
        (libc::SYS_removexattr, vec![]),
        #[cfg(target_env = "gnu")]
        (libc::SYS_rseq, vec![]),
        (libc::SYS_rt_sigaction, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_sched_yield, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_setgroups, vec![]),
        (libc::SYS_setresgid, vec![]),
        (libc::SYS_setresuid, vec![]),
        (libc::SYS_setxattr, vec![]),
        (libc::SYS_statx, vec![]),
        (libc::SYS_symlinkat, vec![]),
        (libc::SYS_syncfs, vec![]),
        (libc::SYS_tgkill, vec![]),
        (libc::SYS_tkill, vec![]),
        (libc::SYS_umask, vec![]),
        (libc::SYS_unlinkat, vec![]),
        (libc::SYS_unshare, vec![]),
        (libc::SYS_utimensat, vec![]),
        (libc::SYS_writev, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_getdents, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_open, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_time, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_unlink, vec![]),
    ]
}

fn virtio_generic_vhost_user_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, create_socket_seccomp_rule()),
        (libc::SYS_timerfd_create, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn virtio_vhost_net_ctl_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_timerfd_settime, vec![])]
}

fn virtio_vhost_net_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_accept4, vec![]),
        (libc::SYS_bind, vec![]),
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_getcwd, vec![]),
        (libc::SYS_listen, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, create_socket_seccomp_rule()),
        (libc::SYS_timerfd_create, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_unlink, vec![]),
        #[cfg(target_arch = "aarch64")]
        (libc::SYS_unlinkat, vec![]),
    ]
}

fn virtio_vhost_block_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_socket, create_socket_seccomp_rule()),
        (libc::SYS_timerfd_create, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn create_socket_seccomp_rule() -> Vec<SeccompRule> {
    or![and![
        Cond::new(0, ArgLen::Dword, Eq, libc::AF_UNIX as u64).unwrap()
    ]]
}

fn create_vsock_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, FIONBIO as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn virtio_vsock_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_accept4, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_fcntl, vec![]),
        (libc::SYS_ioctl, create_vsock_ioctl_seccomp_rule()),
        (libc::SYS_recvfrom, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_shutdown, vec![]),
        (libc::SYS_socket, create_socket_seccomp_rule()),
    ]
}

fn virtio_watchdog_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn get_seccomp_rules(thread_type: Thread) -> Vec<(i64, Vec<SeccompRule>)> {
    let mut rules = match thread_type {
        Thread::VirtioBalloon => virtio_balloon_thread_rules(),
        Thread::VirtioBlock => virtio_block_thread_rules(),
        Thread::VirtioConsole => virtio_console_thread_rules(),
        Thread::VirtioIommu => virtio_iommu_thread_rules(),
        Thread::VirtioMem => virtio_mem_thread_rules(),
        Thread::VirtioNet => virtio_net_thread_rules(),
        Thread::VirtioNetCtl => virtio_net_ctl_thread_rules(),
        Thread::VirtioPmem => virtio_pmem_thread_rules(),
        Thread::VirtioRng => virtio_rng_thread_rules(),
        Thread::VirtioRtc => virtio_rtc_thread_rules(),
        Thread::VirtioFs => virtio_fs_thread_rules(),
        Thread::VirtioVhostBlock => virtio_vhost_block_thread_rules(),
        Thread::VirtioVhostFs => virtio_vhost_fs_thread_rules(),
        Thread::VirtioGenericVhostUser => virtio_generic_vhost_user_thread_rules(),
        Thread::VirtioVhostNet => virtio_vhost_net_thread_rules(),
        Thread::VirtioVhostNetCtl => virtio_vhost_net_ctl_thread_rules(),
        Thread::VirtioVsock => virtio_vsock_thread_rules(),
        Thread::VirtioWatchdog => virtio_watchdog_thread_rules(),
    };
    rules.append(&mut virtio_thread_common());
    rules
}

fn virtio_thread_common() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_brk, vec![]),
        (libc::SYS_clock_gettime, vec![]),
        (libc::SYS_close, vec![]),
        (libc::SYS_dup, vec![]),
        (libc::SYS_epoll_create1, vec![]),
        (libc::SYS_epoll_ctl, vec![]),
        (libc::SYS_epoll_pwait, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_epoll_wait, vec![]),
        (libc::SYS_exit, vec![]),
        (libc::SYS_fcntl, vec![]),
        (libc::SYS_futex, vec![]),
        (libc::SYS_gettid, vec![]),
        (libc::SYS_madvise, vec![]),
        (libc::SYS_mmap, vec![]),
        (libc::SYS_mprotect, vec![]),
        (libc::SYS_mremap, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_openat, vec![]),
        (libc::SYS_read, vec![]),
        (libc::SYS_rt_sigprocmask, vec![]),
        (libc::SYS_rt_sigreturn, vec![]),
        (libc::SYS_sigaltstack, vec![]),
        (libc::SYS_write, vec![]),
    ]
}

fn build_seccomp_filter(
    seccomp_action: &SeccompAction,
    thread_type: Thread,
) -> Result<BpfProgram, Error> {
    match seccomp_action {
        SeccompAction::Allow => Ok(vec![]),
        _ => SeccompFilter::new(
            get_seccomp_rules(thread_type).into_iter().collect(),
            seccomp_action.clone(),
            SeccompAction::Allow,
            env::consts::ARCH.try_into().unwrap(),
        )
        .and_then(|filter| filter.try_into())
        .map_err(Error::Backend),
    }
}

pub(crate) fn get_cached_seccomp_filter(
    seccomp_action: &SeccompAction,
    thread_type: Thread,
) -> Result<FilterLookup, Error> {
    let lookup_started = Instant::now();
    let cache = FILTER_CACHE.get_or_init(|| Mutex::new(Vec::with_capacity(Thread::ALL.len())));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(entry) = cache
        .iter()
        .find(|entry| entry.action == *seccomp_action && entry.thread == thread_type)
    {
        return Ok(FilterLookup {
            program: entry.program.clone(),
            cache_hit: true,
            build_us: 0,
            lookup_us: lookup_started.elapsed().as_micros(),
        });
    }

    // Compile while holding the cache lock. Cache misses only occur during VMM
    // initialization in normal operation, and serializing them prevents a
    // concurrent restore from compiling the same program twice.
    let build_started = Instant::now();
    let program = Arc::new(build_seccomp_filter(seccomp_action, thread_type)?);
    let build_us = build_started.elapsed().as_micros();
    cache.push(CachedFilter {
        action: seccomp_action.clone(),
        thread: thread_type,
        program: program.clone(),
    });
    Ok(FilterLookup {
        program,
        cache_hit: false,
        build_us,
        lookup_us: lookup_started.elapsed().as_micros(),
    })
}

/// Compile every virtio worker filter while the VMM is still idle.
pub fn precompile_seccomp_filters(
    seccomp_action: &SeccompAction,
) -> Result<PrecompileSummary, Error> {
    let mut cache_hits = 0;
    let mut build_us = 0;
    for thread_type in Thread::ALL {
        let lookup = get_cached_seccomp_filter(seccomp_action, thread_type)?;
        cache_hits += usize::from(lookup.cache_hit);
        build_us += lookup.build_us;
    }
    Ok(PrecompileSummary {
        filter_count: Thread::ALL.len(),
        cache_hits,
        build_us,
    })
}

/// Generate a BPF program based on the seccomp_action value.
///
/// Keep the existing public interface for callers outside this crate. Virtio
/// worker creation uses the shared `Arc` path above to avoid copying the cached
/// program.
pub fn get_seccomp_filter(
    seccomp_action: &SeccompAction,
    thread_type: Thread,
) -> Result<BpfProgram, Error> {
    get_cached_seccomp_filter(seccomp_action, thread_type)
        .map(|lookup| lookup.program.as_ref().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_filter_is_reused() {
        let action = SeccompAction::Trap;
        let first = get_cached_seccomp_filter(&action, Thread::VirtioWatchdog).unwrap();
        let second = get_cached_seccomp_filter(&action, Thread::VirtioWatchdog).unwrap();

        assert!(second.cache_hit);
        assert!(Arc::ptr_eq(&first.program, &second.program));
    }
}
