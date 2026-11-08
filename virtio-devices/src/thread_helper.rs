// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::cell::RefCell;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::{io, panic, result};

use log::error;
use seccompiler::{SeccompAction, apply_filter};
use vmm_sys_util::eventfd::EventFd;

use crate::epoll_helper::EpollHelperError;
use crate::seccomp_filters::{Thread, get_seccomp_filter};
use crate::thread_name::set_logical_thread_name;
use crate::{ActivateError, VirtioInterrupt, mark_device_needs_reset};

type Job = Box<dyn FnOnce() + Send>;

/// A named job sent to a pre-created worker thread.
struct NamedJob {
    name: String,
    job: Job,
}

/// `TASK_COMM_LEN`, including the NUL terminator. libc and the userspace
/// headers do not export it, so it is spelled out as std does.
const COMM_LEN_WITH_NUL: usize = 16;

/// Copy `name` into a NUL-terminated `comm` buffer, truncating anything
/// longer than the kernel allows, as the standard library's `truncate_cstr`
/// does.
fn thread_name_cstr(name: &str) -> [libc::c_char; COMM_LEN_WITH_NUL] {
    let mut cname = [0; COMM_LEN_WITH_NUL];
    for (dst, src) in cname[..COMM_LEN_WITH_NUL - 1]
        .iter_mut()
        .zip(name.as_bytes())
    {
        *dst = *src as libc::c_char;
    }
    cname
}

/// A single pre-created worker thread that blocks on a channel waiting for
/// a job closure.
pub struct PreparedDeviceWorker {
    sender: mpsc::Sender<NamedJob>,
    handle: JoinHandle<()>,
}

impl PreparedDeviceWorker {
    /// Create one worker thread, blocking on a channel until a job arrives.
    ///
    /// # Errors
    ///
    /// Returns an error if the thread spawn fails.
    pub fn new() -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel::<NamedJob>();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let handle = thread::Builder::new()
            .name("prepared-worker".to_string())
            .spawn(move || {
                if ready_tx.send(()).is_ok()
                    && let Ok(NamedJob { name, job }) = receiver.recv()
                {
                    // Show the device name instead of the placeholder.
                    let cname = thread_name_cstr(&name);
                    // SAFETY: NUL-terminated buffer of 16 bytes, as `comm` requires.
                    unsafe { libc::pthread_setname_np(libc::pthread_self(), cname.as_ptr()) };
                    // The Rust-side name is fixed at spawn time, so record the
                    // logical one for the logger.
                    set_logical_thread_name(&name);
                    job();
                }
            })?;
        // Wait until the worker is ready to accept a job.
        ready_rx
            .recv()
            .map_err(|_| io::Error::other("prepared worker exited"))?;
        Ok(Self { sender, handle })
    }

    /// Dispatch a job to this worker and return the thread handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker has exited.
    fn dispatch(self, name: &str, job: Job) -> io::Result<JoinHandle<()>> {
        self.sender
            .send(NamedJob {
                name: name.to_string(),
                job,
            })
            .map_err(|_| io::Error::other("prepared worker disconnected"))?;
        Ok(self.handle)
    }
}

/// Shared pool of pre-created workers. An empty pool means nothing was
/// prepared, which spawns device threads the same way as no pool.
pub type PreparedDeviceWorkerPool = Arc<Mutex<Vec<PreparedDeviceWorker>>>;

thread_local! {
    /// Pool installed for the duration of one device activation.
    static ACTIVATION_WORKERS: RefCell<Option<PreparedDeviceWorkerPool>> =
        const { RefCell::new(None) };
}

/// Run a device activation with `workers` as the source of the threads it
/// spawns.
///
/// Devices spawn their workers synchronously from `VirtioDevice::activate()`
/// through [`spawn_virtio_thread`], so scoping the pool to the activation call
/// reaches every device type without each of them having to forward it.
pub(crate) fn with_prepared_workers<R>(
    workers: &PreparedDeviceWorkerPool,
    activate: impl FnOnce() -> R,
) -> R {
    struct Restore(Option<PreparedDeviceWorkerPool>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            ACTIVATION_WORKERS.with(|w| *w.borrow_mut() = previous);
        }
    }

    let previous = ACTIVATION_WORKERS.with(|w| w.borrow_mut().replace(Arc::clone(workers)));
    let _restore = Restore(previous);
    activate()
}

/// Take a pre-created worker from the pool of the activation in progress.
fn take_prepared_worker() -> Option<PreparedDeviceWorker> {
    ACTIVATION_WORKERS.with(|w| {
        w.borrow()
            .as_ref()
            .and_then(|pool| pool.lock().unwrap().pop())
    })
}

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
    let seccomp_filter = get_seccomp_filter(seccomp_action, thread_type)
        .map_err(ActivateError::CreateSeccompFilter)?;

    let thread_exit_evt = exit_evt.try_clone().map_err(ActivateError::CloneEventFd)?;
    let thread_name = name.to_string();

    let job = move || {
        if !seccomp_filter.is_empty()
            && let Err(e) = apply_filter(&seccomp_filter)
        {
            error!("Error applying seccomp filter: {e:?}");
            thread_exit_evt.write(1).ok();
            return;
        }
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
    };

    // Prefer a pre-created worker; without one, spawn as usual.
    let handle = match take_prepared_worker() {
        Some(worker) => worker.dispatch(name, Box::new(job)),
        None => thread::Builder::new().name(name.to_string()).spawn(job),
    }
    .map_err(|e| {
        error!("Failed to spawn thread for {name}: {e}");
        ActivateError::ThreadSpawn(e)
    })?;

    epoll_threads.push(handle);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn dispatch_runs_job_on_prepared_worker() {
        let worker = PreparedDeviceWorker::new().unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);
        let handle = worker
            .dispatch(
                "test",
                Box::new(move || {
                    done_clone.store(true, Ordering::SeqCst);
                }),
            )
            .unwrap();
        handle.join().unwrap();
        assert!(done.load(Ordering::SeqCst));
    }

    #[test]
    fn drop_unused_worker_does_not_hang() {
        let worker = PreparedDeviceWorker::new().unwrap();
        drop(worker);
    }

    #[test]
    fn activation_takes_workers_from_scoped_pool_only() {
        let pool: PreparedDeviceWorkerPool = Arc::new(Mutex::new(vec![
            PreparedDeviceWorker::new().unwrap(),
            PreparedDeviceWorker::new().unwrap(),
        ]));

        // Outside an activation the pool is not visible.
        assert!(take_prepared_worker().is_none());

        let taken = with_prepared_workers(&pool, || {
            let worker = take_prepared_worker();
            assert!(worker.is_some());
            worker
        });
        assert_eq!(pool.lock().unwrap().len(), 1);
        drop(taken);

        // The scope is cleared after the activation returns.
        assert!(take_prepared_worker().is_none());
        assert_eq!(pool.lock().unwrap().len(), 1);
    }

    #[test]
    fn thread_name_is_truncated_to_comm_length() {
        // Short names are kept as-is.
        assert_eq!(name_of("virtio-blk"), b"virtio-blk");
        assert_eq!(name_of("0123456789abcde"), b"0123456789abcde");

        // Anything longer keeps its prefix instead of the placeholder.
        assert_eq!(name_of("0123456789abcdef"), b"0123456789abcde");
        assert_eq!(name_of("_virtio-pci-disk0_q0"), b"_virtio-pci-dis");
        assert_eq!(name_of("some-very-long-device-name"), b"some-very-long-");
    }

    #[test]
    fn thread_name_buffer_is_always_nul_terminated() {
        for name in ["", "abc", "_virtio-pci-disk0_q0", "0123456789abcdef"] {
            let cname = thread_name_cstr(name);
            assert_eq!(cname.len(), COMM_LEN_WITH_NUL);

            // The kept prefix is copied verbatim and the rest stays zero, so
            // the kernel never reads past the terminator.
            let len = name.len().min(COMM_LEN_WITH_NUL - 1);
            assert_eq!(name_of(name), &name.as_bytes()[..len]);
            assert!(
                cname[len..].iter().all(|&c| c == 0),
                "name {name} not zero filled"
            );
        }
    }

    /// The bytes the kernel would read from `comm` for `name`.
    fn name_of(name: &str) -> Vec<u8> {
        let cname = thread_name_cstr(name);
        let len = cname.iter().position(|&c| c == 0).unwrap_or(cname.len());
        cname[..len].iter().map(|c| c.to_ne_bytes()[0]).collect()
    }
}
