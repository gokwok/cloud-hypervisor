// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};

use anyhow::anyhow;
use event_monitor::event;
use log::{error, info};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};
use thiserror::Error;
use vhost_user_backend::bitmap::BitmapMmapRegion;
use virtio_queue::{Queue, QueueT};
use virtiofsd::descriptor_utils::{Error as DescriptorError, Reader, Writer};
use virtiofsd::filesystem::SerializableFileSystem;
use virtiofsd::passthrough::read_only::PassthroughFsRo;
use virtiofsd::passthrough::{self, CachePolicy, PassthroughFs};
use virtiofsd::server::Server;
use vm_memory::bitmap::Bitmap;
use vm_memory::{
    Address, ByteValued, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryRegion,
    GuestRegionMmap, MmapRegion,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::{
    ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError, EpollHelperHandler,
    Error as DeviceError, GuestMemoryMmap, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_IN_ORDER,
    VIRTIO_F_NOTIFICATION_DATA, VIRTIO_F_ORDER_PLATFORM, VIRTIO_F_RING_INDIRECT_DESC,
    VIRTIO_F_VERSION_1, VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterrupt,
    VirtioInterruptType,
};

const NUM_QUEUE_OFFSET: usize = 1;
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
const VIRTIO_FS_TAG_LEN: usize = 36;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeFsCache {
    Auto,
    Always,
    #[default]
    Never,
}

impl From<NativeFsCache> for CachePolicy {
    fn from(value: NativeFsCache) -> Self {
        match value {
            NativeFsCache::Auto => Self::Auto,
            NativeFsCache::Always => Self::Always,
            NativeFsCache::Never => Self::Never,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct NativeFsConfig {
    pub shared_dir: PathBuf,
    #[serde(default)]
    pub cache: NativeFsCache,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub xattr: bool,
    #[serde(default)]
    pub announce_submounts: bool,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed creating queue reader")]
    QueueReader(#[source] DescriptorError),
    #[error("Failed creating queue writer")]
    QueueWriter(#[source] DescriptorError),
    #[error("Failed processing virtio-fs request")]
    ProcessQueue(#[source] virtiofsd::Error),
    #[error("Failed adding used queue entry")]
    QueueAddUsed(#[source] virtio_queue::Error),
}

enum ServerType {
    ReadWrite(Server<PassthroughFs>),
    ReadOnly(Server<PassthroughFsRo>),
}

impl ServerType {
    fn handle_message(&self, reader: Reader<'_>, writer: Writer<'_>) -> virtiofsd::Result<usize> {
        match self {
            Self::ReadWrite(server) => server.handle_message(reader, writer, None::<&mut ()>),
            Self::ReadOnly(server) => server.handle_message(reader, writer, None::<&mut ()>),
        }
    }

    fn prepare_serialization(&self) {
        let cancel = Arc::new(AtomicBool::new(false));
        match self {
            Self::ReadWrite(server) => server.prepare_serialization(cancel),
            Self::ReadOnly(server) => server.prepare_serialization(cancel),
        }
    }

    fn serialize(&self, state: File) -> io::Result<()> {
        match self {
            Self::ReadWrite(server) => server.serialize(state),
            Self::ReadOnly(server) => server.serialize(state),
        }
    }

    fn deserialize_and_apply(&self, state: File) -> io::Result<()> {
        match self {
            Self::ReadWrite(server) => server.deserialize_and_apply(state),
            Self::ReadOnly(server) => server.deserialize_and_apply(state),
        }
    }
}

struct FsEpollHandler {
    queue_index: u16,
    queue_evt: EventFd,
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    fs_mem: Arc<vm_memory::GuestMemoryMmap<BitmapMmapRegion>>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    server: Arc<ServerType>,
}

impl FsEpollHandler {
    fn process_queue(&mut self) -> result::Result<bool, Error> {
        let mut used_descs = false;
        while let Some(desc_chain) = self.queue.pop_descriptor_chain(self.mem.memory()) {
            let reader = Reader::new(self.fs_mem.as_ref(), desc_chain.clone())
                .map_err(Error::QueueReader)?;
            let writer = Writer::new(self.fs_mem.as_ref(), desc_chain.clone())
                .map_err(Error::QueueWriter)?;
            let memory = self.mem.memory();
            for descriptor in desc_chain.clone().writable() {
                if let Some(region) = memory.find_region(descriptor.addr()) {
                    let offset = descriptor
                        .addr()
                        .checked_sub(region.start_addr().raw_value())
                        .unwrap();
                    region
                        .bitmap()
                        .mark_dirty(offset.raw_value() as usize, descriptor.len() as usize);
                }
            }
            let len = self
                .server
                .handle_message(reader, writer)
                .map_err(Error::ProcessQueue)?;
            self.queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), len as u32)
                .map_err(Error::QueueAddUsed)?;
            used_descs = true;
        }
        Ok(used_descs)
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(self.queue_index))
            .map_err(DeviceError::FailedSignalingUsedQueue)
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)
    }
}

impl EpollHelperHandler for FsEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        match event.data as u16 {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|error| {
                    EpollHelperError::HandleEvent(anyhow!("Failed reading queue event: {error}"))
                })?;
                if self.process_queue().map_err(|error| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed processing virtio-fs queue: {error}"
                    ))
                })? {
                    self.signal_used_queue().map_err(|error| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed signaling virtio-fs queue: {error}"
                        ))
                    })?;
                }
                Ok(())
            }
            event => Err(EpollHelperError::HandleEvent(anyhow!(
                "Unexpected virtio-fs event: {event}"
            ))),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct State {
    avail_features: u64,
    acked_features: u64,
    config: VirtioFsConfig,
    backend_state: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Copy, Deserialize, Serialize)]
#[repr(C, packed)]
struct VirtioFsConfig {
    #[serde_as(as = "Bytes")]
    tag: [u8; VIRTIO_FS_TAG_LEN],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        Self {
            tag: [0; VIRTIO_FS_TAG_LEN],
            num_request_queues: 0,
        }
    }
}

// SAFETY: The structure contains only integers and has no implicit padding.
unsafe impl ByteValued for VirtioFsConfig {}

pub struct Fs {
    common: VirtioCommon,
    id: String,
    config: VirtioFsConfig,
    server: Arc<ServerType>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
}

impl Fs {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        native: &NativeFsConfig,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        access_platform_enabled: bool,
        state: Option<State>,
    ) -> io::Result<Self> {
        let server = Arc::new(Self::create_server(native)?);
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;
        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            info!("Restoring native virtio-fs {id}");
            if !state.backend_state.is_empty() {
                Self::restore_backend_state(server.as_ref(), &state.backend_state)?;
            }
            (
                state.avail_features,
                state.acked_features,
                state.config,
                true,
            )
        } else {
            let mut avail_features = (1u64 << VIRTIO_F_RING_INDIRECT_DESC)
                | (1u64 << VIRTIO_F_VERSION_1)
                | (1u64 << VIRTIO_F_IN_ORDER)
                | (1u64 << VIRTIO_F_ORDER_PLATFORM)
                | (1u64 << VIRTIO_F_NOTIFICATION_DATA);
            if access_platform_enabled {
                avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
            }
            let mut config = VirtioFsConfig::default();
            let tag = tag.as_bytes();
            let len = tag.len().min(config.tag.len());
            config.tag[..len].copy_from_slice(&tag[..len]);
            config.num_request_queues = req_num_queues as u32;
            (avail_features, 0, config, false)
        };

        Ok(Self {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Fs as u32,
                avail_features,
                acked_features,
                queue_sizes: vec![queue_size; num_queues],
                paused_sync: Some(Arc::new(Barrier::new(num_queues + 1))),
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            config,
            server,
            seccomp_action,
            exit_evt,
        })
    }

    fn create_server(config: &NativeFsConfig) -> io::Result<ServerType> {
        let shared_dir = fs::canonicalize(&config.shared_dir)?;
        let root_dir = shared_dir
            .to_str()
            .ok_or_else(|| io::Error::other("Native virtio-fs path is not valid UTF-8"))?;
        let fs_config = passthrough::Config {
            cache_policy: config.cache.into(),
            root_dir: root_dir.to_owned(),
            xattr: config.xattr,
            announce_submounts: config.announce_submounts,
            ..Default::default()
        };
        if config.read_only {
            Ok(ServerType::ReadOnly(Server::new(PassthroughFsRo::new(
                fs_config,
            )?)))
        } else {
            Ok(ServerType::ReadWrite(Server::new(PassthroughFs::new(
                fs_config,
            )?)))
        }
    }

    fn backend_state(&self) -> io::Result<Vec<u8>> {
        self.server.prepare_serialization();
        let mut state = create_state_file()?;
        self.server.serialize(state.try_clone()?)?;
        state.rewind()?;
        let mut bytes = Vec::new();
        state.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn restore_backend_state(server: &ServerType, bytes: &[u8]) -> io::Result<()> {
        let mut state = create_state_file()?;
        state.write_all(bytes)?;
        state.rewind()?;
        server.deserialize_and_apply(state)
    }
}

fn create_state_file() -> io::Result<File> {
    // SAFETY: memfd_create has no pointer lifetime requirements beyond this call, and the
    // returned descriptor is checked before ownership is transferred to File.
    let fd = unsafe { libc::memfd_create(c"native-virtiofs-state".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new descriptor owned by this function.
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl VirtioDevice for Fs {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            queues,
            device_status,
        } = context;
        let fs_mem = Arc::new(memory_view(&mem.memory()).map_err(|error| {
            error!("Failed creating native virtio-fs memory view: {error}");
            crate::ActivateError::BadActivate
        })?);
        self.common.paused_sync = Some(Arc::new(Barrier::new(queues.len() + 1)));
        self.common.activate(&queues, interrupt_cb.clone())?;
        for (queue_index, queue, queue_evt) in queues {
            let (kill_evt, pause_evt) = self.common.dup_eventfds()?;
            let mut handler = FsEpollHandler {
                queue_index: queue_index as u16,
                queue_evt,
                queue,
                mem: mem.clone(),
                fs_mem: Arc::clone(&fs_mem),
                interrupt_cb: interrupt_cb.clone(),
                kill_evt,
                pause_evt,
                server: Arc::clone(&self.server),
            };
            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone().unwrap();
            self.common.spawn_worker(
                &format!("{}_q{queue_index}", self.id),
                &self.seccomp_action,
                Thread::VirtioFs,
                &self.exit_evt,
                device_status.clone(),
                interrupt_cb.clone(),
                move || handler.run(&paused, &paused_sync),
            )?;
        }
        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) {
        self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
    }

    fn shutdown(&mut self) {
        self.common.reset();
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }

    fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        self.common.access_platform()
    }
}

impl Pausable for Fs {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Fs {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        let state = State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
            backend_state: self.backend_state().map_err(|error| {
                MigratableError::Snapshot(anyhow!(
                    "Failed serializing native virtio-fs state: {error}"
                ))
            })?,
        };
        Snapshot::new_from_state(&state)
    }
}

impl Transportable for Fs {}
impl Migratable for Fs {}

fn memory_view(
    memory: &GuestMemoryMmap,
) -> io::Result<vm_memory::GuestMemoryMmap<BitmapMmapRegion>> {
    let regions = memory
        .iter()
        .map(|region| {
            // SAFETY: The returned mapping is a non-owning view of the guest mapping. Each
            // handler also owns a GuestMemoryAtomic clone, so the source mapping outlives it.
            let mapping = unsafe {
                MmapRegion::<BitmapMmapRegion>::build_raw(
                    region.as_ptr(),
                    region.len() as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                )
            }
            .map_err(|error| io::Error::other(error.to_string()))?;
            GuestRegionMmap::new(mapping, region.start_addr())
                .ok_or_else(|| io::Error::other("Native virtio-fs memory range overflow"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    vm_memory::GuestMemoryMmap::from_regions(regions)
        .map_err(|error| io::Error::other(error.to_string()))
}
