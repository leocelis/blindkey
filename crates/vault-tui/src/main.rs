//! `vault-tui` — a fast terminal UI over `vault-core` (the first UC-18 shell).
//!
//! Thin shell: it unlocks the vault via `vault_core`, then lets you type-to-search and press Enter
//! to copy a secret to the clipboard (model-blind — the secret is never rendered). It runs on the
//! **alternate screen** so nothing a secret touches can leak to terminal scrollback (UC-18 §3.4),
//! and the clipboard auto-clears in the background (C13). All secret-touching logic stays in the
//! core; this binary only renders metadata and orchestrates delivery.

#![forbid(unsafe_code)]

mod clip;
mod sealed;

use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};
use ratatui::Frame;
use vault_core::Vault;
use zeroize::Zeroizing;

const CLIPBOARD_TIMEOUT_SECS: u64 = 30;

#[derive(Parser)]
#[command(name = "vault-tui", version, about = "Vault — terminal UI")]
struct Cli {
    /// Vault file for browse mode (default: `$HOME/.vault/vault.vlt`).
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<SealedCommand>,
}

/// UC-23 sealed-file commands (parity with `vault seal` / `open` / `peek`).
#[derive(Subcommand)]
enum SealedCommand {
    /// Seal paths into one `.vltf` container.
    Seal {
        paths: Vec<PathBuf>,
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        #[arg(long)]
        no_pad: bool,
        #[arg(long, hide = true)]
        allow_weak_kdf: bool,
        #[arg(long, hide = true, default_value_t = 65_536)]
        kdf_m_cost: u32,
        #[arg(long, hide = true, default_value_t = 3)]
        kdf_t_cost: u32,
        #[arg(long, hide = true, default_value_t = 4)]
        kdf_p_cost: u32,
        /// Merge new paths into an existing `.vltf` (requires `-o` pointing at the container).
        #[arg(long)]
        append: bool,
    },
    /// Extract a sealed container to a directory.
    Open {
        file: PathBuf,
        #[arg(short = 'C', value_name = "DIR")]
        dest: Option<PathBuf>,
        #[arg(long)]
        stdout: bool,
    },
    /// List inner paths after unlock (metadata only).
    Peek { file: PathBuf },
}

fn main() -> std::process::ExitCode {
    match real_main() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vault-tui: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), String> {
    vault_core::memory::harden_process(); // C25: disable core dumps before touching secrets
    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        return match cmd {
            SealedCommand::Seal {
                paths,
                output,
                no_pad,
                allow_weak_kdf,
                kdf_m_cost,
                kdf_t_cost,
                kdf_p_cost,
                append,
            } => sealed::cmd_seal(
                paths,
                output,
                no_pad,
                allow_weak_kdf,
                kdf_m_cost,
                kdf_t_cost,
                kdf_p_cost,
                append,
            ),
            SealedCommand::Open { file, dest, stdout } => sealed::cmd_open(file, dest, stdout),
            SealedCommand::Peek { file } => sealed::cmd_peek(file),
        };
    }

    let path = vault_path(cli.vault)?;
    let bytes = std::fs::read(&path)
        .map_err(|_| format!("no vault at {} — run `vault init` first", path.display()))?;

    // Unlock BEFORE entering the alternate screen (so the no-echo prompt behaves normally).
    let password = read_password()?;
    let vault = Vault::open(&bytes, password.as_bytes()).map_err(|e| e.to_string())?;

    let mut terminal = ratatui::init();
    let result = App::new(vault).run(&mut terminal);
    ratatui::restore();
    result
}

struct App {
    vault: Vault,
    query: String,
    filtered: Vec<usize>, // indices into vault.entries()
    list: ListState,
    status: String,
    quit: bool,
}

impl App {
    fn new(vault: Vault) -> Self {
        let mut app = App {
            vault,
            query: String::new(),
            filtered: Vec::new(),
            list: ListState::default(),
            status: String::from("type to search · ↑/↓ select · Enter copy · Esc quit"),
            quit: false,
        };
        app.refilter();
        app
    }

    fn entries_count(&self) -> usize {
        self.vault.entries().len()
    }

    fn refilter(&mut self) {
        let q = self.query.to_lowercase();
        self.filtered = self
            .vault
            .entries()
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                q.is_empty()
                    || e.title.to_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .map(|(i, _)| i)
            .collect();
        if self.filtered.is_empty() {
            self.list.select(None);
        } else {
            let sel = self
                .list
                .selected()
                .unwrap_or(0)
                .min(self.filtered.len() - 1);
            self.list.select(Some(sel));
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.filtered.is_empty() {
            return;
        }
        let len = self.filtered.len() as isize;
        let cur = self.list.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(len) as usize;
        self.list.select(Some(next));
    }

    /// Copy the selected entry's password to the clipboard (model-blind) and schedule auto-clear.
    fn copy_selected(&mut self) {
        let Some(&entry_idx) = self.list.selected().and_then(|s| self.filtered.get(s)) else {
            return;
        };
        let entry = &self.vault.entries()[entry_idx];
        let title = entry.title.clone();
        let secret: Zeroizing<Vec<u8>> = Zeroizing::new(entry.password.expose().to_vec());
        match clip::copy(&secret) {
            Ok(()) => {
                clip::schedule_clear(secret, CLIPBOARD_TIMEOUT_SECS);
                self.status =
                    format!("copied {title:?} to clipboard — clears in {CLIPBOARD_TIMEOUT_SECS}s");
            }
            Err(e) => self.status = format!("clipboard error: {e}"),
        }
    }

    fn run(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<(), String> {
        while !self.quit {
            terminal
                .draw(|f| self.render(f))
                .map_err(|e| e.to_string())?;
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    KeyCode::Esc => self.quit = true,
                    KeyCode::Char('c') if ctrl => self.quit = true,
                    KeyCode::Enter => self.copy_selected(),
                    KeyCode::Down => self.move_selection(1),
                    KeyCode::Up => self.move_selection(-1),
                    KeyCode::Backspace => {
                        self.query.pop();
                        self.refilter();
                    }
                    KeyCode::Char(c) => {
                        self.query.push(c);
                        self.refilter();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn render(&mut self, f: &mut Frame) {
        let areas = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(f.area());

        let search = Paragraph::new(Line::from(format!("🔎 {}", self.query)))
            .block(Block::bordered().title("Search"));
        f.render_widget(search, areas[0]);

        let items: Vec<ListItem> = self
            .filtered
            .iter()
            .map(|&i| ListItem::new(sanitize(&self.vault.entries()[i].title)))
            .collect();
        let title = format!("Entries ({}/{})", self.filtered.len(), self.entries_count());
        let list = List::new(items)
            .block(Block::bordered().title(title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶ ");
        f.render_stateful_widget(list, areas[1], &mut self.list);

        f.render_widget(Paragraph::new(Line::from(self.status.clone())), areas[2]);
    }
}

fn read_password() -> Result<Zeroizing<String>, String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        Ok(Zeroizing::new(
            rpassword::prompt_password("Master password: ").map_err(|e| e.to_string())?,
        ))
    } else {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        Ok(Zeroizing::new(s.lines().next().unwrap_or("").to_string()))
    }
}

fn vault_path(opt: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = opt {
        return Ok(p);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or("cannot determine your home directory; pass --vault <PATH>")?;
    Ok(PathBuf::from(home).join(".vault").join("vault.vlt"))
}

/// Render control / ANSI bytes as visible escapes before drawing (constraint C30).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if !c.is_control() {
                c.to_string()
            } else {
                format!("\\x{:02x}", c as u32)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::format::entry::{Entry, Protected};

    fn entry(title: &str) -> Entry {
        Entry {
            id: [0; 16],
            title: title.into(),
            username: String::new(),
            password: Protected::new(b"x".to_vec()),
            url: String::new(),
            notes: String::new(),
            tags: vec![],
            otp_secret: None,
            created_at: 0,
            modified_at: 0,
            expires_at: None,
            custom_fields: vec![],
        }
    }

    fn app_with(titles: &[&str]) -> App {
        let mut v = Vault::create(b"pw", 8192, 1, 1, true).unwrap();
        for t in titles {
            v.add_entry(entry(t));
        }
        App::new(v)
    }

    #[test]
    fn search_filters_case_insensitively() {
        let mut a = app_with(&["github", "gitlab", "aws"]);
        assert_eq!(a.filtered.len(), 3);
        a.query = "GIT".into();
        a.refilter();
        assert_eq!(a.filtered.len(), 2);
        a.query = "zzz".into();
        a.refilter();
        assert!(a.filtered.is_empty());
        assert_eq!(a.list.selected(), None);
    }

    #[test]
    fn selection_wraps_around() {
        let mut a = app_with(&["a", "b", "c"]);
        a.list.select(Some(0));
        a.move_selection(-1);
        assert_eq!(a.list.selected(), Some(2));
        a.move_selection(1);
        assert_eq!(a.list.selected(), Some(0));
    }

    #[test]
    fn sanitize_escapes_control() {
        assert_eq!(sanitize("ok\x1b[31m"), "ok\\x1b[31m");
    }
}
