//! Degraded volume "mount": materialize the VFS as a cleartext folder (UC-25 / ADR-0010).
//!
//! Used when userspace FUSE is unavailable (macOS before Fuse packaging, or builds without
//! `volume-mount`). Same residual class as FUSE: OS sees cleartext under `root` while open.
//! On successful [`MaterializedMount::close`], files are read back into the [`Volume`], synced,
//! and the folder is best-effort shredded. On failure, the mount is returned intact so edits
//! are not destroyed.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::{Error, Result, Volume};

/// Failed [`MaterializedMount::close`] — mount is still open; cleartext edits preserved.
#[derive(Debug)]
pub struct CloseMountError {
    /// Why import/sync failed.
    pub error: Error,
    /// Still-open mount (caller should keep it or retry).
    pub mount: MaterializedMount,
}

impl std::fmt::Display for CloseMountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for CloseMountError {}

/// An open cleartext working tree backed by an unlocked [`Volume`].
#[derive(Debug)]
pub struct MaterializedMount {
    volume: Option<Volume>,
    root: PathBuf,
}

impl MaterializedMount {
    /// Export the volume VFS into `root` (created). Caller owns residual-risk UX.
    ///
    /// Refuses a **non-empty** existing `root` so a kill-9 leftover cleartext tree is not
    /// wiped — use [`Self::adopt`] or [`Self::open_or_adopt`] instead.
    pub fn open(volume: Volume, root: &Path) -> Result<Self> {
        if root.exists() {
            if root.is_dir() {
                let nonempty = fs::read_dir(root)
                    .map_err(Error::Io)?
                    .next()
                    .is_some();
                if nonempty {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "cleartext mount folder already exists; adopt leftover tree instead of re-export",
                    )));
                }
                fs::remove_dir(root).map_err(Error::Io)?;
            } else {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "mount path exists and is not a directory",
                )));
            }
        }
        fs::create_dir_all(root).map_err(Error::Io)?;
        export_tree(&volume, "", root)?;
        #[cfg(target_os = "macos")]
        {
            let _ = blindkey_sys::exclude_from_backup(root);
        }
        Ok(Self {
            volume: Some(volume),
            root: root.to_path_buf(),
        })
    }

    /// Open a fresh export, or adopt an existing non-empty cleartext tree (kill-9 recovery).
    pub fn open_or_adopt(volume: Volume, root: &Path) -> Result<Self> {
        if root.is_dir() {
            let nonempty = fs::read_dir(root)
                .map_err(Error::Io)?
                .next()
                .is_some();
            if nonempty {
                return Self::adopt(volume, root);
            }
        }
        Self::open(volume, root)
    }

    /// Adopt an existing cleartext tree (crash recovery) without re-exporting.
    pub fn adopt(volume: Volume, root: &Path) -> Result<Self> {
        if !root.is_dir() {
            return Err(Error::VolumeOpenFailed);
        }
        #[cfg(target_os = "macos")]
        {
            let _ = blindkey_sys::exclude_from_backup(root);
        }
        Ok(Self {
            volume: Some(volume),
            root: root.to_path_buf(),
        })
    }

    /// Cleartext folder path (Finder / file manager).
    pub fn mountpoint(&self) -> &Path {
        &self.root
    }

    /// Read tree back into the volume, sync, shred the folder, return the volume.
    ///
    /// On failure, returns the mount unchanged (no shred) so cleartext edits survive.
    pub fn close(mut self) -> std::result::Result<Volume, CloseMountError> {
        let Some(mut vol) = self.volume.take() else {
            return Err(CloseMountError {
                error: Error::VolumeOpenFailed,
                mount: self,
            });
        };
        if let Err(e) = import_tree(&mut vol, &self.root, "").and_then(|_| {
            vol.sync()?;
            Ok(())
        }) {
            self.volume = Some(vol);
            return Err(CloseMountError {
                error: e,
                mount: self,
            });
        }
        shred_dir(&self.root);
        Ok(vol)
    }
}

impl Drop for MaterializedMount {
    fn drop(&mut self) {
        if let Some(mut vol) = self.volume.take() {
            match import_tree(&mut vol, &self.root, "").and_then(|_| {
                vol.sync()?;
                Ok(())
            }) {
                Ok(()) => shred_dir(&self.root),
                Err(_) => {
                    // Fail closed for data loss: leave cleartext for operator recovery.
                    let _ = fs::write(self.root.join(".bk-unsynced"), b"blindkey: cleartext not sealed\n");
                }
            }
            // vol drops → keys zeroize
        }
    }
}

/// Path of a leftover cleartext folder beside a work `.vltd` (`…/mnt`), if present.
pub fn cleartext_mnt_beside(work_path: &Path) -> Option<PathBuf> {
    let mnt = work_path.parent()?.join("mnt");
    if mnt.is_dir() {
        Some(mnt)
    } else {
        None
    }
}

fn export_tree(vol: &Volume, vpath: &str, dest_dir: &Path) -> Result<()> {
    let names = vol.list(vpath)?;
    for name in names {
        let child_v = if vpath.is_empty() {
            name.clone()
        } else {
            format!("{vpath}/{name}")
        };
        let dest = dest_dir.join(&name);
        match vol.node_kind(&child_v) {
            Some(crate::NodeKind::Dir) => {
                fs::create_dir_all(&dest).map_err(Error::Io)?;
                export_tree(vol, &child_v, &dest)?;
            }
            Some(crate::NodeKind::File(_)) => {
                let data = vol.read(&child_v)?;
                let mut f = File::create(&dest).map_err(Error::Io)?;
                f.write_all(&data).map_err(Error::Io)?;
                f.sync_all().map_err(Error::Io)?;
            }
            None => return Err(Error::VolumeOpenFailed),
        }
    }
    Ok(())
}

fn import_tree(vol: &mut Volume, host_dir: &Path, vpath: &str) -> Result<()> {
    let existing = vol.list(vpath).unwrap_or_default();
    let Ok(rd) = fs::read_dir(host_dir) else {
        return Ok(());
    };
    let mut seen = std::collections::BTreeSet::new();
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." || name == ".bk-unsynced" {
            continue;
        }
        seen.insert(name.clone());
        let child_v = if vpath.is_empty() {
            name.clone()
        } else {
            format!("{vpath}/{name}")
        };
        let path = ent.path();
        if path.is_dir() {
            vol.mkdir(&child_v)?;
            import_tree(vol, &path, &child_v)?;
        } else if path.is_file() {
            let mut f = File::open(&path).map_err(Error::Io)?;
            let mut data = Vec::new();
            f.read_to_end(&mut data).map_err(Error::Io)?;
            vol.write(&child_v, &data)?;
        }
    }
    for name in existing {
        if !seen.contains(&name) {
            let child_v = if vpath.is_empty() {
                name.clone()
            } else {
                format!("{vpath}/{name}")
            };
            let _ = remove_vpath(vol, &child_v);
        }
    }
    Ok(())
}

fn remove_vpath(vol: &mut Volume, vpath: &str) -> Result<()> {
    match vol.node_kind(vpath) {
        Some(crate::NodeKind::File(_)) => vol.unlink(vpath),
        Some(crate::NodeKind::Dir) => {
            for name in vol.list(vpath).unwrap_or_default() {
                let child = if vpath.is_empty() {
                    name
                } else {
                    format!("{vpath}/{name}")
                };
                remove_vpath(vol, &child)?;
            }
            vol.rmdir(vpath)
        }
        None => Ok(()),
    }
}

fn shred_dir(root: &Path) {
    if !root.exists() {
        return;
    }
    if let Ok(walk) = walkdir_files(root) {
        for p in walk {
            if let Ok(meta) = fs::metadata(&p) {
                if meta.is_file() {
                    if let Ok(mut f) = File::create(&p) {
                        let n = meta.len().min(1024 * 1024) as usize;
                        let _ = f.write_all(&vec![0u8; n.max(1)]);
                        let _ = f.sync_all();
                    }
                }
            }
        }
    }
    let _ = fs::remove_dir_all(root);
}

fn walkdir_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for ent in fs::read_dir(dir)? {
            let ent = ent?;
            let p = ent.path();
            if p.is_dir() {
                walk(&p, out)?;
            } else {
                out.push(p);
            }
        }
        Ok(())
    }
    walk(root, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VolumeCreateOpts, VolumeUnlock};

    #[test]
    fn materialize_roundtrip() {
        let dir = std::env::temp_dir().join(format!("bk-mat-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let vltd = dir.join("t.vltd");
        let unlock = VolumeUnlock::password_only(b"test-passphrase-ok");
        let mut vol = Volume::create(&vltd, &unlock, &VolumeCreateOpts::default()).unwrap();
        vol.write("hello.txt", b"hi").unwrap();
        vol.mkdir("sub").unwrap();
        vol.write("sub/a.txt", b"aa").unwrap();
        vol.sync().unwrap();

        let mnt = dir.join("mnt");
        let mat = MaterializedMount::open(vol, &mnt).unwrap();
        assert!(mnt.join("hello.txt").is_file());
        assert_eq!(fs::read(mnt.join("hello.txt")).unwrap(), b"hi");
        fs::write(mnt.join("hello.txt"), b"bye").unwrap();
        fs::write(mnt.join("sub/a.txt"), b"bb").unwrap();

        let vol = mat.close().unwrap();
        assert_eq!(vol.read("hello.txt").unwrap(), b"bye");
        assert_eq!(vol.read("sub/a.txt").unwrap(), b"bb");
        assert!(!mnt.exists());
        vol.close().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_refuses_nonempty_leftover_adopt_recovers() {
        let dir = std::env::temp_dir().join(format!("bk-mat-adopt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let vltd = dir.join("t.vltd");
        let unlock = VolumeUnlock::password_only(b"test-passphrase-ok");
        let mut vol = Volume::create(&vltd, &unlock, &VolumeCreateOpts::default()).unwrap();
        vol.write("a.txt", b"v1").unwrap();
        vol.sync().unwrap();
        let mnt = dir.join("mnt");
        let mat = MaterializedMount::open(vol, &mnt).unwrap();
        fs::write(mnt.join("a.txt"), b"kill9-edit").unwrap();
        // Simulate kill -9: forget without Drop (no import/shred).
        std::mem::forget(mat);
        assert!(mnt.join("a.txt").is_file());

        let vol = Volume::open(&vltd, &unlock).unwrap();
        let err = MaterializedMount::open(vol, &mnt).unwrap_err();
        assert!(matches!(err, Error::Io(_)));

        let vol = Volume::open(&vltd, &unlock).unwrap();
        let mat = MaterializedMount::open_or_adopt(vol, &mnt).unwrap();
        let vol = mat.close().unwrap();
        assert_eq!(vol.read("a.txt").unwrap(), b"kill9-edit");
        vol.close().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn blindfolder_lifecycle_checkout_materialize_checkin() {
        use crate::volume::working_copy::{CheckinOpts, CheckoutOpts, WorkPhase, WorkingCopySession};

        let sync = std::env::temp_dir().join(format!("bk-bf-sync-{}", std::process::id()));
        let work_root = std::env::temp_dir().join(format!("bk-bf-work-{}", std::process::id()));
        let _ = fs::remove_dir_all(&sync);
        let _ = fs::remove_dir_all(&work_root);
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let source = sync.join("cloud.vltd");
        let unlock = VolumeUnlock::password_only(b"test-passphrase-ok");
        let mut vol = Volume::create(&source, &unlock, &VolumeCreateOpts::default()).unwrap();
        vol.write("note.txt", b"hello").unwrap();
        vol.sync().unwrap();
        vol.close().unwrap();

        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &source,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        let work = session.work_path.clone();
        let id = session.id.clone();
        drop(session);

        let vol = Volume::open(&work, &unlock).unwrap();
        let mnt = work.parent().unwrap().join("mnt");
        let mat = MaterializedMount::open(vol, &mnt).unwrap();
        fs::write(mnt.join("note.txt"), b"edited").unwrap();
        let vol = mat.close().unwrap();
        vol.close().unwrap();

        let mut session = WorkingCopySession::resume_in(&id, &work_root).unwrap();
        session.set_phase(WorkPhase::Unmounted).unwrap();
        session
            .checkin_with(CheckinOpts {
                coordinated: false,
            })
            .unwrap();

        let vol = Volume::open(&source, &unlock).unwrap();
        assert_eq!(vol.read("note.txt").unwrap(), b"edited");
        vol.close().unwrap();
        let _ = fs::remove_dir_all(&sync);
        let _ = fs::remove_dir_all(&work_root);
    }
}
