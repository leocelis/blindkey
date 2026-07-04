//! UC-23 sealed-file TUI — `vault-tui seal` / `open` / `peek` (Phase C parity with CLI).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Block, Gauge, Paragraph};
use ratatui::Frame;
use vault_core::pad::PadMode;
use vault_core::sealed::{
    ArchiveEntryMeta, SealOptions, SealedContainer, SealedIoOpts, SealedUnlock, SEALED_OPEN_ERROR,
};
use vault_core::Error;
use zeroize::Zeroizing;

enum JobMsg {
    Progress { done: u64, total: u64 },
    Done(Result<(), String>),
}

fn map_open_err(e: Error) -> String {
    match e {
        Error::HeaderAuth => "Incorrect passphrase.".to_string(),
        Error::WrongContainerKind => "Wrong container type.".to_string(),
        Error::SealedOpenFailed => SEALED_OPEN_ERROR.to_string(),
        Error::Io(e) => e.to_string(),
        _ => SEALED_OPEN_ERROR.to_string(),
    }
}

pub fn default_output_path(paths: &[PathBuf]) -> Result<PathBuf, String> {
    let first = paths.first().ok_or("seal requires at least one path")?;
    let stem = if first.is_dir() {
        first.file_name()
    } else {
        first.file_stem()
    }
    .ok_or_else(|| format!("cannot derive output name from {}", first.display()))?;
    Ok(PathBuf::from(format!("{}.vltf", stem.to_string_lossy())))
}

pub fn write_sealed_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
    }
    let tmp = path.with_extension("vltf.tmp");
    {
        let mut oo = std::fs::OpenOptions::new();
        oo.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            oo.mode(0o600);
        }
        let mut f = oo.open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

fn read_password_confirm() -> Result<Zeroizing<String>, String> {
    let pw = Zeroizing::new(rpassword::prompt_password("Passphrase: ").map_err(|e| e.to_string())?);
    let confirm = Zeroizing::new(
        rpassword::prompt_password("Confirm passphrase: ").map_err(|e| e.to_string())?,
    );
    if *pw != *confirm {
        return Err("Passphrases do not match.".into());
    }
    if pw.is_empty() {
        return Err("Passphrase required.".into());
    }
    Ok(pw)
}

fn read_password() -> Result<Zeroizing<String>, String> {
    let pw = Zeroizing::new(rpassword::prompt_password("Passphrase: ").map_err(|e| e.to_string())?);
    if pw.is_empty() {
        return Err("Passphrase required.".into());
    }
    Ok(pw)
}

fn run_progress_ui(
    title: &str,
    cancel: Arc<AtomicBool>,
    rx: Receiver<JobMsg>,
    handle: thread::JoinHandle<()>,
) -> Result<(), String> {
    let mut terminal = ratatui::init();
    let started = Instant::now();
    let mut done = 0u64;
    let mut total = 1u64;
    let mut finished: Option<Result<(), String>> = None;
    let mut status = String::from("Esc to cancel");

    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                JobMsg::Progress { done: d, total: t } => {
                    done = d;
                    total = t.max(1);
                }
                JobMsg::Done(r) => finished = Some(r),
            }
        }
        if finished.is_some() {
            break;
        }

        terminal
            .draw(|f| {
                render_progress(f, title, done, total, &status, started.elapsed());
            })
            .map_err(|e| e.to_string())?;

        if event::poll(Duration::from_millis(100)).map_err(|e| e.to_string())? {
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Esc {
                    cancel.store(true, Ordering::Relaxed);
                    status = "Cancelling…".into();
                }
            }
        }
    }

    ratatui::restore();
    let _ = handle.join();
    finished.unwrap_or(Err(SEALED_OPEN_ERROR.into()))
}

fn render_progress(
    f: &mut Frame,
    title: &str,
    done: u64,
    total: u64,
    status: &str,
    elapsed: Duration,
) {
    let area = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(f.area());

    let block = Block::bordered().title(title);
    f.render_widget(Paragraph::new(Line::from(status)).block(block), area[0]);

    let frac = (done as f64 / total as f64).clamp(0.0, 1.0);
    let pct = (frac * 100.0) as u16;
    let gauge = Gauge::default()
        .block(Block::bordered().title(format!("{pct}%")))
        .gauge_style(ratatui::style::Style::default().fg(ratatui::style::Color::Cyan))
        .ratio(frac);
    f.render_widget(gauge, area[1]);

    let secs = elapsed.as_secs_f64();
    let phase_rate = if secs > 0.0 {
        done as f64 / total as f64 / secs
    } else {
        0.0
    };
    f.render_widget(
        Paragraph::new(format!(
            "phase {done}/{total} · {:.1} phases/s (coarse until core streams progress)",
            phase_rate
        )),
        area[2],
    );
}

pub fn cmd_seal(
    paths: Vec<PathBuf>,
    output: Option<PathBuf>,
    no_pad: bool,
    allow_weak_kdf: bool,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    append: bool,
) -> Result<(), String> {
    if paths.is_empty() {
        return Err("seal requires at least one path".into());
    }
    for p in &paths {
        if !p.exists() {
            return Err(format!("{}: no such file or directory", p.display()));
        }
    }
    let out = output.unwrap_or_else(|| default_output_path(&paths).unwrap());
    if append {
        if !out.is_file() {
            return Err(format!(
                "--append requires an existing sealed container at {}",
                out.display()
            ));
        }
        eprintln!("Deriving key (Argon2id)…");
        let password = read_password()?;
        let original = std::fs::read(&out).map_err(|e| e.to_string())?;
        let unlock = SealedUnlock::password_only(password.as_bytes());
        let container = SealedContainer::open(&original, &unlock).map_err(map_open_err)?;

        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let c = cancel.clone();
        let paths_clone = paths.clone();
        let out_clone = out.clone();
        let handle = thread::spawn(move || {
            run_append_job(c, tx, original, container, paths_clone, out_clone);
        });

        run_progress_ui("Appending", cancel, rx, handle)?;
        eprintln!("Appended {} path(s) → {}", paths.len(), out.display());
        return Ok(());
    }
    if out.exists() {
        return Err(format!("refusing to overwrite {}", out.display()));
    }

    eprintln!("Deriving key (Argon2id)…");
    let password = read_password_confirm()?;
    let opts = SealOptions {
        m_cost,
        t_cost,
        p_cost,
        allow_weak_kdf,
        pad_mode: if no_pad {
            PadMode::None
        } else {
            PadMode::Padme
        },
    };

    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let c = cancel.clone();
    let paths_clone = paths.clone();
    let out_clone = out.clone();
    let handle = thread::spawn(move || {
        run_seal_job(c, tx, paths_clone, out_clone, password, opts);
    });

    run_progress_ui("Sealing", cancel, rx, handle)?;
    eprintln!("Sealed {} path(s) → {}", paths.len(), out.display());
    Ok(())
}

fn run_seal_job(
    cancel: Arc<AtomicBool>,
    tx: Sender<JobMsg>,
    paths: Vec<PathBuf>,
    output: PathBuf,
    password: Zeroizing<String>,
    opts: SealOptions,
) {
    let progress = |done: u64, total: u64| {
        let _ = tx.send(JobMsg::Progress { done, total });
    };
    let finish = |r: Result<(), String>| {
        let _ = tx.send(JobMsg::Done(r));
    };

    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    progress(0, 1);
    let container = match SealedContainer::create(password.as_bytes(), opts) {
        Ok(c) => c,
        Err(e) => {
            finish(Err(e.to_string()));
            return;
        }
    };
    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    let refs: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
    let mut progress_cb = |done: u64, total: u64| {
        let _ = tx.send(JobMsg::Progress { done, total });
    };
    let mut io = SealedIoOpts {
        cancel: Some(&cancel),
        progress: Some(&mut progress_cb),
    };
    let bytes = match container.seal_paths_with(&refs, &mut io) {
        Ok(b) => b,
        Err(e) => {
            finish(Err(e.to_string()));
            return;
        }
    };
    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    if let Err(e) = write_sealed_atomic(&output, &bytes) {
        finish(Err(e));
        return;
    }
    finish(Ok(()));
}

fn run_append_job(
    cancel: Arc<AtomicBool>,
    tx: Sender<JobMsg>,
    original: Vec<u8>,
    container: SealedContainer,
    paths: Vec<PathBuf>,
    output: PathBuf,
) {
    let finish = |r: Result<(), String>| {
        let _ = tx.send(JobMsg::Done(r));
    };

    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    let refs: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
    let mut progress_cb = |done: u64, total: u64| {
        let _ = tx.send(JobMsg::Progress { done, total });
    };
    let mut io = SealedIoOpts {
        cancel: Some(&cancel),
        progress: Some(&mut progress_cb),
    };
    let bytes = match container.append_paths(&original, &refs, &mut io) {
        Ok(b) => b,
        Err(e) => {
            finish(Err(e.to_string()));
            return;
        }
    };
    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    if let Err(e) = write_sealed_atomic(&output, &bytes) {
        finish(Err(e));
        return;
    }
    finish(Ok(()));
}

pub fn cmd_open(file: PathBuf, dest: Option<PathBuf>, stdout: bool) -> Result<(), String> {
    if !file.is_file() {
        return Err(format!("{}: not a sealed container file", file.display()));
    }
    let bytes = std::fs::read(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let password = read_password()?;

    if stdout {
        eprintln!(
            "WARNING: file contents written to stdout; ensure no AI agent or untrusted process \
             captures this stream."
        );
        let body = SealedContainer::read_single_stdout(
            &bytes,
            &SealedUnlock::password_only(password.as_bytes()),
        )
        .map_err(map_open_err)?;
        std::io::stdout()
            .write_all(&body)
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    let dest = dest.unwrap_or_else(|| PathBuf::from("."));
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let c = cancel.clone();
    let file_clone = file.clone();
    let handle = thread::spawn(move || {
        run_open_job(c, tx, bytes, file_clone, dest, password);
    });

    run_progress_ui("Opening", cancel, rx, handle)?;
    eprintln!("Extracted → {}", file.display());
    Ok(())
}

fn run_open_job(
    cancel: Arc<AtomicBool>,
    tx: Sender<JobMsg>,
    bytes: Vec<u8>,
    _file: PathBuf,
    dest: PathBuf,
    password: Zeroizing<String>,
) {
    let progress = |done: u64, total: u64| {
        let _ = tx.send(JobMsg::Progress { done, total });
    };
    let finish = |r: Result<(), String>| {
        let _ = tx.send(JobMsg::Done(r));
    };

    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    progress(0, 1);
    let unlock = SealedUnlock::password_only(password.as_bytes());
    let mut progress_cb = |done: u64, total: u64| {
        let _ = tx.send(JobMsg::Progress { done, total });
    };
    let mut io = SealedIoOpts {
        cancel: Some(&cancel),
        progress: Some(&mut progress_cb),
    };
    if let Err(e) = SealedContainer::open_to_dir_with(&bytes, &unlock, &dest, &mut io, None) {
        finish(Err(map_open_err(e)));
        return;
    }
    finish(Ok(()));
}

pub fn cmd_peek(file: PathBuf) -> Result<(), String> {
    if !file.is_file() {
        return Err(format!("{}: not a sealed container file", file.display()));
    }
    let bytes = std::fs::read(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let password = read_password()?;
    let entries =
        SealedContainer::peek_entries(&bytes, &SealedUnlock::password_only(password.as_bytes()))
            .map_err(map_open_err)?;
    peek_ui(&file, &entries)
}

fn peek_ui(file: &Path, entries: &[ArchiveEntryMeta]) -> Result<(), String> {
    let mut terminal = ratatui::init();
    let mut scroll: u16 = 0;
    let title = format!(
        "Peek — {} ({} files, metadata only)",
        file.file_name().unwrap_or_default().to_string_lossy(),
        entries.len()
    );

    loop {
        terminal
            .draw(|f| render_peek(f, &title, entries, scroll))
            .map_err(|e| e.to_string())?;

        if event::poll(Duration::from_millis(250)).map_err(|e| e.to_string())? {
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') => break,
                    KeyCode::Down | KeyCode::Char('j') => scroll = scroll.saturating_add(1),
                    KeyCode::Up | KeyCode::Char('k') => scroll = scroll.saturating_sub(1),
                    _ => {}
                }
            }
        }
    }

    ratatui::restore();
    Ok(())
}

fn render_peek(f: &mut Frame, title: &str, entries: &[ArchiveEntryMeta], scroll: u16) {
    use ratatui::widgets::{List, ListItem};

    let block = Block::bordered().title(format!("{title} · ↑/↓ q/Esc — metadata only"));
    let inner = block.inner(f.area());
    f.render_widget(block, f.area());

    if entries.is_empty() {
        f.render_widget(Paragraph::new("(empty container)"), inner);
        return;
    }

    let max_scroll = entries.len().saturating_sub(1) as u16;
    let scroll = scroll.min(max_scroll);
    let visible = 32usize;
    let start = scroll as usize;
    let end = (start + visible).min(entries.len());
    let items: Vec<ListItem> = entries[start..end]
        .iter()
        .map(|e| {
            ListItem::new(format!(
                "{:<40} {:>10} B  {:>4o}  {}",
                truncate_path(&e.path, 40),
                e.size,
                e.mode & 0o7777,
                e.mtime
            ))
        })
        .collect();
    let list = List::new(items);
    f.render_widget(list, inner);
}

fn truncate_path(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("…{}", &s[s.len().saturating_sub(max - 1)..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_stem() {
        let p = default_output_path(&[PathBuf::from("a.pdf")]).unwrap();
        assert_eq!(p, PathBuf::from("a.vltf"));
    }

    #[test]
    fn map_auth_to_plain_message() {
        assert_eq!(map_open_err(Error::HeaderAuth), "Incorrect passphrase.");
    }
}
