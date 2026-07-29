//! Linux `fuser` backend for [`crate::mount_volume`] (ADR-0009).
//!
//! Translates the FUSE lowlevel `Filesystem` trait onto the path-addressed
//! [`blindkey_core::Volume`] virtual FS. No cryptography lives here — the `Volume` owns all keys.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use blindkey_core::{NodeKind, Volume};
use fuser::{
    BackgroundSession, FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};

use crate::{Error, Result};

/// Attribute cache TTL handed to the kernel. Short, because writes mutate the in-memory VFS.
const TTL: Duration = Duration::from_secs(1);
/// Directory permission bits reported to the OS (the on-disk model is uniform — no per-node mode).
const DIR_PERM: u16 = 0o755;
/// File permission bits reported to the OS.
const FILE_PERM: u16 = 0o644;
/// Root inode number, per FUSE convention.
const ROOT_INO: u64 = 1;

/// Bidirectional inode ↔ normalized-path map. The `Volume` VFS is path-addressed; FUSE is
/// inode-addressed, so the adapter assigns stable inode numbers lazily as paths are discovered.
struct InodeTable {
    by_ino: HashMap<u64, String>,
    by_path: HashMap<String, u64>,
    next: u64,
}

impl InodeTable {
    fn new() -> Self {
        let mut by_ino = HashMap::new();
        let mut by_path = HashMap::new();
        by_ino.insert(ROOT_INO, String::new());
        by_path.insert(String::new(), ROOT_INO);
        Self {
            by_ino,
            by_path,
            next: ROOT_INO + 1,
        }
    }

    fn path(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(String::as_str)
    }

    /// Return the inode for `path`, allocating a fresh one on first sight.
    fn intern(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.by_path.get(path) {
            return ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_ino.insert(ino, path.to_string());
        self.by_path.insert(path.to_string(), ino);
        ino
    }

    /// Forget any inode mapping for `path` (after unlink/rmdir). Inode numbers are never reused.
    fn forget_path(&mut self, path: &str) {
        if let Some(ino) = self.by_path.remove(path) {
            self.by_ino.remove(&ino);
        }
    }

    /// Re-point an existing subtree mapping after a rename (best-effort; missing entries are
    /// re-interned lazily on the next lookup).
    fn rename_subtree(&mut self, from: &str, to: &str) {
        let from_prefix = format!("{from}/");
        let moves: Vec<(u64, String)> = self
            .by_ino
            .iter()
            .filter(|(_, p)| p.as_str() == from || p.starts_with(&from_prefix))
            .map(|(ino, p)| (*ino, p.clone()))
            .collect();
        for (ino, old) in moves {
            let new = if old == from {
                to.to_string()
            } else {
                format!("{to}{}", &old[from.len()..])
            };
            self.by_path.remove(&old);
            self.by_ino.insert(ino, new.clone());
            self.by_path.insert(new, ino);
        }
    }
}

/// Join a parent directory path with a child name.
fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn attr(ino: u64, kind: NodeKind, uid: u32, gid: u32) -> FileAttr {
    let (ftype, perm, size) = match kind {
        NodeKind::Dir => (FileType::Directory, DIR_PERM, 0),
        NodeKind::File(len) => (FileType::RegularFile, FILE_PERM, len),
    };
    let blksize: u32 = 4096;
    let blocks = size.div_ceil(u64::from(blksize));
    FileAttr {
        ino,
        size,
        blocks,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: ftype,
        perm,
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        blksize,
        flags: 0,
    }
}

/// FUSE filesystem over an unlocked [`Volume`]. The volume is shared with the [`MountGuard`] behind
/// a [`Mutex`] so the guard can flush and zeroize on unmount.
struct VolumeFs {
    volume: Arc<Mutex<Volume>>,
    inodes: InodeTable,
}

impl VolumeFs {
    fn new(volume: Arc<Mutex<Volume>>) -> Self {
        Self {
            volume,
            inodes: InodeTable::new(),
        }
    }
}

impl Filesystem for VolumeFs {
    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.inodes.path(parent).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(libc::ENOENT);
            return;
        };
        let path = join(&parent_path, name);
        let kind = {
            let vol = self.volume.lock().expect("volume mutex poisoned");
            vol.node_kind(&path)
        };
        match kind {
            Some(kind) => {
                let ino = self.inodes.intern(&path);
                reply.entry(&TTL, &attr(ino, kind, req.uid(), req.gid()), 0);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(path) = self.inodes.path(ino).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let kind = {
            let vol = self.volume.lock().expect("volume mutex poisoned");
            vol.node_kind(&path)
        };
        match kind {
            Some(kind) => reply.attr(&TTL, &attr(ino, kind, req.uid(), req.gid())),
            None => reply.error(libc::ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.inodes.path(ino).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let mut vol = self.volume.lock().expect("volume mutex poisoned");
        // We only honor a size change (truncate/extend); mode/owner/time are advisory and ignored.
        if let Some(len) = size {
            if vol.truncate(&path, len).is_err() {
                reply.error(libc::EIO);
                return;
            }
        }
        match vol.node_kind(&path) {
            Some(kind) => reply.attr(&TTL, &attr(ino, kind, req.uid(), req.gid())),
            None => reply.error(libc::ENOENT),
        }
    }

    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(path) = self.inodes.path(ino).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let vol = self.volume.lock().expect("volume mutex poisoned");
        match vol.read(&path) {
            Ok(data) => {
                let start = offset.max(0) as usize;
                if start >= data.len() {
                    reply.data(&[]);
                    return;
                }
                let end = start.saturating_add(size as usize).min(data.len());
                reply.data(&data[start..end]);
            }
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let Some(path) = self.inodes.path(ino).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let mut vol = self.volume.lock().expect("volume mutex poisoned");
        // Read-modify-write the whole file: the core VFS stores files as contiguous byte vectors.
        let mut buf = vol.read(&path).unwrap_or_default();
        let start = offset.max(0) as usize;
        let end = start.saturating_add(data.len());
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(data);
        match vol.write(&path, &buf) {
            Ok(()) => reply.written(data.len() as u32),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(dir) = self.inodes.path(ino).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let children = {
            let vol = self.volume.lock().expect("volume mutex poisoned");
            match vol.node_kind(&dir) {
                Some(NodeKind::Dir) => vol.list(&dir).unwrap_or_default(),
                Some(NodeKind::File(_)) => {
                    reply.error(libc::ENOTDIR);
                    return;
                }
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Synthetic "." and ".." precede the real entries.
        let mut listing: Vec<(u64, FileType, String)> = Vec::with_capacity(children.len() + 2);
        listing.push((ino, FileType::Directory, ".".to_string()));
        listing.push((ino, FileType::Directory, "..".to_string()));
        for name in children {
            let child_path = join(&dir, &name);
            let (child_ino, ftype) = {
                let vol = self.volume.lock().expect("volume mutex poisoned");
                let ftype = match vol.node_kind(&child_path) {
                    Some(NodeKind::Dir) => FileType::Directory,
                    _ => FileType::RegularFile,
                };
                (self.inodes.intern(&child_path), ftype)
            };
            listing.push((child_ino, ftype, name));
        }

        for (i, (child_ino, ftype, name)) in listing.into_iter().enumerate().skip(offset as usize) {
            // `add` returns true when the reply buffer is full; stop and let the kernel re-ask.
            if reply.add(child_ino, (i + 1) as i64, ftype, name) {
                break;
            }
        }
        reply.ok();
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(parent_path) = self.inodes.path(parent).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let path = join(&parent_path, name);
        let mut vol = self.volume.lock().expect("volume mutex poisoned");
        match vol.write(&path, &[]) {
            Ok(()) => {
                let ino = self.inodes.intern(&path);
                let a = attr(ino, NodeKind::File(0), req.uid(), req.gid());
                reply.created(&TTL, &a, 0, 0, 0);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.inodes.path(parent).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let path = join(&parent_path, name);
        let mut vol = self.volume.lock().expect("volume mutex poisoned");
        match vol.mkdir(&path) {
            Ok(()) => {
                let ino = self.inodes.intern(&path);
                reply.entry(&TTL, &attr(ino, NodeKind::Dir, req.uid(), req.gid()), 0);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.inodes.path(parent).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(libc::ENOENT);
            return;
        };
        let path = join(&parent_path, name);
        let mut vol = self.volume.lock().expect("volume mutex poisoned");
        match vol.unlink(&path) {
            Ok(()) => {
                drop(vol);
                self.inodes.forget_path(&path);
                reply.ok();
            }
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.inodes.path(parent).map(str::to_string) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(libc::ENOENT);
            return;
        };
        let path = join(&parent_path, name);
        let mut vol = self.volume.lock().expect("volume mutex poisoned");
        match vol.rmdir(&path) {
            Ok(()) => {
                drop(vol);
                self.inodes.forget_path(&path);
                reply.ok();
            }
            // The core collapses "non-empty", "not a dir", and "missing" to one error; report
            // ENOTEMPTY so shells surface the common case sensibly.
            Err(_) => reply.error(libc::ENOTEMPTY),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Some(from_dir), Some(to_dir)) = (
            self.inodes.path(parent).map(str::to_string),
            self.inodes.path(newparent).map(str::to_string),
        ) else {
            reply.error(libc::ENOENT);
            return;
        };
        let (Some(name), Some(newname)) = (name.to_str(), newname.to_str()) else {
            reply.error(libc::EINVAL);
            return;
        };
        let from = join(&from_dir, name);
        let to = join(&to_dir, newname);
        let mut vol = self.volume.lock().expect("volume mutex poisoned");
        match vol.rename(&from, &to) {
            Ok(()) => {
                drop(vol);
                self.inodes.rename_subtree(&from, &to);
                reply.ok();
            }
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // Persist on close so umount always sees a consistent, versioned image (C70).
        let mut vol = self.volume.lock().expect("volume mutex poisoned");
        let _ = vol.sync();
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let mut vol = self.volume.lock().expect("volume mutex poisoned");
        match vol.sync() {
            Ok(()) => reply.ok(),
            Err(_) => reply.error(libc::EIO),
        }
    }
}

/// Owns a live FUSE mount. Dropping the guard unmounts the volume, flushes it to disk, and
/// zeroizes all key material (the wrapped [`Volume`] is dropped last — C11/C72).
pub struct MountGuard {
    session: Option<BackgroundSession>,
    volume: Arc<Mutex<Volume>>,
    mountpoint: PathBuf,
}

impl MountGuard {
    /// The mountpoint this guard is bound to.
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Explicitly unmount and flush now (equivalent to dropping the guard).
    pub fn unmount(mut self) {
        self.teardown();
    }

    fn teardown(&mut self) {
        // 1. End the FUSE session first: this unmounts and joins the background thread, after which
        //    the filesystem instance (and its `Arc` clone of the volume) has been dropped.
        if let Some(session) = self.session.take() {
            session.join();
        }
        // 2. Flush the in-memory VFS. Key zeroization happens when the last `Arc` (this one) drops.
        if let Ok(mut vol) = self.volume.lock() {
            let _ = vol.sync();
        }
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl std::fmt::Debug for MountGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountGuard")
            .field("mountpoint", &self.mountpoint)
            .field("mounted", &self.session.is_some())
            .finish()
    }
}

pub fn mount_volume(volume: Volume, mountpoint: &Path) -> Result<MountGuard> {
    let volume = Arc::new(Mutex::new(volume));
    let fs = VolumeFs::new(Arc::clone(&volume));
    let options = vec![
        MountOption::FSName("blindkey".to_string()),
        MountOption::Subtype("vltd".to_string()),
        MountOption::DefaultPermissions,
        MountOption::AutoUnmount,
        MountOption::RW,
    ];
    let session = fuser::spawn_mount2(fs, mountpoint, &options).map_err(Error::Mount)?;
    Ok(MountGuard {
        session: Some(session),
        volume,
        mountpoint: mountpoint.to_path_buf(),
    })
}
