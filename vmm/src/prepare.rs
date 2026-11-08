// SPDX-License-Identifier: Apache-2.0
//! Optional resources owned by an idle VMM and consumed by one restore.

use std::sync::{Arc, Mutex};
use std::{io, result};

use option_parser::{OptionParser, OptionParserError, Toggle};
use serde::{Deserialize, Serialize};
use virtio_devices::thread_helper::PreparedDeviceWorker;
pub use virtio_devices::thread_helper::PreparedDeviceWorkerPool;

/// Upper bound on the number of pre-created worker threads.
///
/// Enforced both at the request layer ([`PrepareSpec::validate`]) and at the
/// resource layer ([`Preparation::new`]) so no caller can spawn an unbounded
/// number of OS threads.
pub const MAX_PRE_THREADS: u32 = 16;

/// Shared shape for both the `vmm.prepare` request and response.
///
/// The request and response carry the same fields; they are distinguished by
/// the [`PrepareConfig`] / [`PrepareResponse`] type aliases. The request is
/// an explicit description of what to pre-create; the response reports what
/// was actually pre-created.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareSpec {
    /// Whether to pre-create an empty ordinary KVM VM.
    #[serde(default = "default_pre_vm")]
    pub pre_vm: bool,

    /// Number of generic worker threads to pre-create (0–16).
    #[serde(default)]
    pub pre_threads: u32,
}

fn default_pre_vm() -> bool {
    true
}

impl Default for PrepareSpec {
    fn default() -> Self {
        Self {
            pre_vm: true,
            pre_threads: 0,
        }
    }
}

/// Request body for `PUT /api/v1/vmm.prepare`.
pub type PrepareConfig = PrepareSpec;

/// Response body for `PUT /api/v1/vmm.prepare`.
pub type PrepareResponse = PrepareSpec;

impl PrepareSpec {
    /// Command-line syntax for the `prepare` ch-remote subcommand.
    pub const SYNTAX: &'static str = "Pre-create resources in an idle VMM. \
        \nPrepare parameters \"pre_vm=on|off,pre_threads=<n>\" \
        \n`pre_vm` pre-creates an empty KVM VM (default on) \
        \n`pre_threads` pre-creates up to 16 generic worker threads (default 0)";

    /// Parse a `key=value[,key=value...]` prepare configuration string.
    ///
    /// An empty string yields the defaults (`pre_vm=true`, `pre_threads=0`).
    ///
    /// # Errors
    ///
    /// Returns an error on unknown keys, malformed input, or unparsable
    /// values.
    pub fn parse(config: &str) -> result::Result<Self, OptionParserError> {
        let mut parser = OptionParser::new();
        parser.add("pre_vm").add("pre_threads");
        parser.parse(config)?;

        let pre_vm = parser
            .convert::<Toggle>("pre_vm")?
            .unwrap_or(Toggle(true))
            .0;
        let pre_threads = parser.convert::<u32>("pre_threads")?.unwrap_or(0);

        Ok(Self {
            pre_vm,
            pre_threads,
        })
    }

    /// Validates the request fields.
    ///
    /// # Errors
    ///
    /// Returns an error if `pre_threads` exceeds 16, or if both `pre_vm`
    /// is false and `pre_threads` is zero (nothing to prepare).
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.pre_threads > MAX_PRE_THREADS {
            anyhow::bail!("pre_threads exceeds limit");
        }
        if !self.pre_vm && self.pre_threads == 0 {
            anyhow::bail!("nothing to prepare");
        }
        Ok(())
    }
}

/// All pre-created resources held by an idle VMM; consumed by one `vm.restore`,
/// discarded by `vm.create` / `vm.delete`.
///
/// An empty `Preparation` (no VM, empty worker pool) is the canonical "not
/// prepared" state, so no outer `Option` is needed.
#[derive(Default)]
pub struct Preparation {
    /// Pre-created empty ordinary KVM VM.
    pub vm: Option<Arc<dyn hypervisor::Vm>>,
    /// Pre-created generic worker thread pool.
    ///
    /// Shared by reference so the VMM keeps a handle after the pool is handed
    /// over to the VM: `vmm.query_prepare` therefore reports how many worker
    /// threads are still available, not just the initial reservation.
    pub workers: PreparedDeviceWorkerPool,
}

impl Preparation {
    /// Create a new preparation with the given VM and thread count.
    ///
    /// # Errors
    ///
    /// Returns an error if `thread_count` exceeds [`MAX_PRE_THREADS`] or if
    /// any thread spawn fails.
    pub fn new(vm: Option<Arc<dyn hypervisor::Vm>>, thread_count: usize) -> io::Result<Self> {
        if thread_count > MAX_PRE_THREADS as usize {
            return Err(io::Error::other("thread reserve exceeds limit"));
        }
        let mut workers = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            workers.push(PreparedDeviceWorker::new()?);
        }
        Ok(Self {
            vm,
            workers: Arc::new(Mutex::new(workers)),
        })
    }

    /// Whether nothing has been pre-created.
    pub fn is_empty(&self) -> bool {
        self.vm.is_none() && self.worker_count() == 0
    }

    /// Number of worker threads still available in the pool.
    ///
    /// Drops as devices consume workers, so this is the live remaining count
    /// rather than the initial reservation.
    pub fn worker_count(&self) -> usize {
        self.workers.lock().unwrap().len()
    }

    /// Whether the hypervisor backend supports preparation.
    pub fn supported(hypervisor: &dyn hypervisor::Hypervisor) -> bool {
        #[cfg(all(feature = "kvm", any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            hypervisor.hypervisor_type() == hypervisor::HypervisorType::Kvm
        }
        #[cfg(not(all(feature = "kvm", any(target_arch = "x86_64", target_arch = "aarch64"))))]
        {
            let _ = hypervisor;
            false
        }
    }

    /// Whether a pre-created ordinary KVM VM is compatible with the given config.
    ///
    /// The VM is created with a default [`hypervisor::HypervisorVmConfig`].
    /// KVM only consults its confidential-computing fields when creating a
    /// VM, so those are the only ones that can make it unusable.
    pub(crate) fn compatible(_config: &hypervisor::HypervisorVmConfig) -> bool {
        #[cfg(feature = "tdx")]
        if _config.tdx_enabled {
            return false;
        }
        #[cfg(feature = "sev_snp")]
        if _config.sev_snp_enabled {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_excess_threads_and_empty_request() {
        PrepareConfig {
            pre_vm: true,
            pre_threads: 0,
        }
        .validate()
        .unwrap();

        PrepareConfig {
            pre_vm: false,
            pre_threads: 8,
        }
        .validate()
        .unwrap();

        PrepareConfig {
            pre_vm: false,
            pre_threads: 0,
        }
        .validate()
        .unwrap_err();

        PrepareConfig {
            pre_vm: true,
            pre_threads: 16,
        }
        .validate()
        .unwrap();

        PrepareConfig {
            pre_vm: true,
            pre_threads: 17,
        }
        .validate()
        .unwrap_err();
    }

    #[test]
    fn parse_accepts_key_value_and_empty() {
        // Empty input keeps the defaults.
        assert_eq!(PrepareSpec::parse("").unwrap(), PrepareSpec::default());

        // Positional key=value string, as used by ch-remote.
        assert_eq!(
            PrepareSpec::parse("pre_threads=8").unwrap(),
            PrepareSpec {
                pre_vm: true,
                pre_threads: 8,
            }
        );
        assert_eq!(
            PrepareSpec::parse("pre_vm=off,pre_threads=4").unwrap(),
            PrepareSpec {
                pre_vm: false,
                pre_threads: 4,
            }
        );

        // Unknown keys are rejected.
        PrepareSpec::parse("pre_vcpus=2").unwrap_err();
        // Malformed values are rejected.
        PrepareSpec::parse("pre_threads=abc").unwrap_err();
        PrepareSpec::parse("pre_vm=maybe").unwrap_err();
    }
}
