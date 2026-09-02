// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::thread::{self, JoinHandle};
use std::time::Instant;
use std::{panic, result};

use log::{error, warn};
use seccompiler::{SeccompAction, apply_filter};
use vmm_sys_util::eventfd::EventFd;

use crate::epoll_helper::EpollHelperError;
use crate::seccomp_filters::{Thread, get_cached_seccomp_filter};
use crate::{ActivateError, VirtioInterrupt, mark_device_needs_reset};

#[expect(clippy::too_many_arguments)]
pub(crate) fn spawn_virtio_thread<F>(
    name: &str,
    seccomp_action: &SeccompAction,
    thread_type: Thread,
    epoll_threads: &mut Vec<JoinHandle<()>>,
    exit_evt: &EventFd,
    device_status: Arc<AtomicU8>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    f: F,
) -> Result<(), ActivateError>
where
    F: FnOnce() -> result::Result<(), EpollHelperError>,
    F: Send + 'static,
{
    let seccomp_filter = get_cached_seccomp_filter(seccomp_action, thread_type)
        .map_err(ActivateError::CreateSeccompFilter)?;
    let worker_type = thread_type.name();
    let seccomp_cache_hit = seccomp_filter.cache_hit;
    let seccomp_filter_build_us = seccomp_filter.build_us;
    let seccomp_filter_lookup_us = seccomp_filter.lookup_us;

    let thread_exit_evt = exit_evt.try_clone().map_err(ActivateError::CloneEventFd)?;
    let thread_name = name.to_string();

    let spawn_started = Instant::now();
    let result = thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let apply_started = Instant::now();
            if !seccomp_filter.program.is_empty()
                && let Err(e) = apply_filter(seccomp_filter.program.as_ref())
            {
                error!("Error applying seccomp filter: {e:?}");
                thread_exit_evt.write(1).ok();
                return;
            }
            warn!(
                target: "ch_timing",
                "ch_timing event=ch_virtio_worker_ready worker={} seccomp_apply_us={}",
                worker_type,
                apply_started.elapsed().as_micros(),
            );
            match panic::catch_unwind(AssertUnwindSafe(f)) {
                Err(_) => {
                    error!("{thread_name} thread panicked");
                    thread_exit_evt.write(1).ok();
                }
                Ok(Err(e)) => {
                    mark_device_needs_reset(
                        &device_status,
                        interrupt_cb.as_ref(),
                        format_args!("{thread_name}: worker exited with error: {e:?}"),
                    );
                }
                Ok(Ok(())) => {}
            }
        });
    let thread_spawn_us = spawn_started.elapsed().as_micros();
    warn!(
        target: "ch_timing",
        "ch_timing event=ch_virtio_worker_spawn worker={} seccomp_cache_hit={} seccomp_filter_build_us={} seccomp_filter_lookup_us={} thread_spawn_us={}",
        worker_type,
        u8::from(seccomp_cache_hit),
        seccomp_filter_build_us,
        seccomp_filter_lookup_us,
        thread_spawn_us,
    );
    result
        .map(|thread| epoll_threads.push(thread))
        .map_err(|e| {
            error!("Failed to spawn thread for {name}: {e}");
            ActivateError::ThreadSpawn(e)
        })
}
