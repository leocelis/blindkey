# Blindkey v1.1.0

Local-first credential vault for AI-era development. No server, no account, one encrypted file.
**Not independently third-party audited** — keep your own backup of anything you store.
On-disk format v1 remains stable ([ADR-0005](adr/0005-format-v1-freeze.md)).

## Highlights

- **Blindfolder** — keep a `.vltd` in Dropbox, Drive, iCloud, or Syncthing. Blindkey copies it to a local work path, opens a normal folder, and atomically checks it back in. It never live-mounts the sync-path file ([UC-30](specs/UC-30-volume-working-copy.md)).
- **Local encrypted volumes** — `.vltd` workspace containers, Linux FUSE mount, optional macOS macFUSE (`--features macos-fuse`, user-installed only).
- **Desktop craft** — IA, visual craft, component kit, contrast/typography (UC-26–UC-29).
- **MCP broker delivery** — `use_handle` can deliver via a companion `blindkey agent` broker when one is listening.
- **CI / supply chain** — Windows checkin fsync + live-session detection, macOS feature matrix without requiring macFUSE on runners, commit-identity gate against `@*.local` emails.

Full itemized changes: [CHANGELOG.md](../CHANGELOG.md#110---2026-10-15).

## Install (verify the checksum first)

Download the binary for your platform plus `SHA256SUMS.txt`, then verify **just your file**:

```sh
# example: macOS Apple Silicon — swap FILE for your platform's asset name
FILE=blindkey-aarch64-apple-darwin
curl -LO "https://github.com/leocelis/blindkey/releases/download/v1.1.0/$FILE"
curl -LO https://github.com/leocelis/blindkey/releases/download/v1.1.0/SHA256SUMS.txt
grep "$FILE" SHA256SUMS.txt | shasum -a 256 -c -
chmod +x "$FILE" && sudo mv "$FILE" /usr/local/bin/blindkey
```

Assets: `blindkey-x86_64-apple-darwin`, `blindkey-aarch64-apple-darwin`, `blindkey-x86_64-unknown-linux-gnu`, `blindkey-aarch64-unknown-linux-gnu`.

See [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md) and [INSTALL.md](INSTALL.md).
