# CAC Setup

A single-file tool (`cac-setup.py`) for using a **DoD CAC** smartcard on Linux. It does three
jobs:

1. **Install CAC certificates** into every browser's NSS database *and* the shared
   `~/.pki/nssdb`, so the CAC works for web login (client-cert auth) **and** document/email
   signing.
2. **Set up a GUI PDF signer** that signs the *existing signature blocks* in PDF forms with
   your CAC (the one thing LibreOffice/OnlyOffice/JSignPdf can't do on Linux).
3. **Fix a recurring Chromium-family browser crash** on CAC/TLS sites.

Tested on Ubuntu/Zorin 24.04. Package install supports `apt`, `dnf`, `yum`, and `zypper`.
It is intentionally a **single file** — no build step.

---

## Quick start

```bash
# Fresh machine — certs + crash fix + PDF signer in one go:
sudo python3 cac-setup.py --apply-crash-fix --add-pdf-signer
```

Then insert your CAC and you're ready: browsers do CAC login, and "Sign PDF with CAC" is in
your app menu. The à-la-carte commands are below.

## Command reference

| Command | Run as | What it does |
|---|---|---|
| `sudo python3 cac-setup.py` | **root** | Install CAC certs into all NSS DBs + `~/.pki/nssdb` (default) |
| `sudo python3 cac-setup.py --apply-crash-fix` | **root** | Certs **+** browser crash fix |
| `sudo python3 cac-setup.py --add-pdf-signer` | **root** | Certs **+** GUI PDF signer |
| `sudo python3 cac-setup.py --disable-login-smartcard` | **root** | Stop the GDM login screen asking for the CAC/PIN |
| `python3 cac-setup.py crash-fix [--revert]` | user | Apply/undo the browser crash fix |
| `python3 cac-setup.py pdf-signer [--revert]` | user | Install/remove the PDF signer |
| `python3 cac-setup.py trace-locks [nosandbox]` | user | Crash diagnostic (strace mlock) |

`--dry-run` previews any root run; `--revert-crash-fix` / `--remove-pdf-signer` undo the
matching setup and exit. Root operations use `sudo`; the user subcommands must **not** be
sudo'd (they write into your home and refuse to run as root).

---

## 1. Install CAC certificates (run as root)

```bash
sudo python3 cac-setup.py
```

Installs the smartcard packages (OpenSC, pcsc-lite, NSS tools, zenity), downloads the DoD
certificate bundle from militarycac.com, registers the OpenSC PKCS#11 module, and imports the
DoD trust anchors into each browser's NSS database **and the shared `~/.pki/nssdb`** (created
if absent). Certs are imported with NSS trust **`CT,C,C`** so the same anchors validate CAC
web login (SSL) **and** document/email signing (S/MIME + object signing). Re-running is safe
and fast — it imports only missing certs and re-marks any left at an older SSL-only trust, so
re-running an existing setup upgrades it for signing.

Options: `--only-browsers a,b`, `--exclude-browsers a,b`, `--disable-login-smartcard`,
`-v/--verbose`, `-n/--dry-run`. See `python3 cac-setup.py --help`.

---

## 2. Sign PDFs with your CAC

Most DoD PDFs have **pre-placed signature blocks** (often several, for several signers). The
bundled signer fills a chosen block with your CAC signature so it shows up correctly.

```bash
python3 cac-setup.py pdf-signer          # install (undo: pdf-signer --revert)
```

This creates a self-contained Python venv (`~/.venvs/pyhanko`, using [pyHanko] + pypdf),
writes the signer to `~/bin/cac-sign-pdf-gui.py`, and adds a **"Sign PDF with CAC"** launcher
to your app menu and to a PDF's right-click **Open With**.

**To sign:** fill in all form fields first (e.g. in OnlyOffice), insert your CAC, right-click
the PDF → **Open With → Sign PDF with CAC**, pick the block (numbered in document order),
enter your PIN. It writes `<name>_signed.pdf`. Full walkthrough and the multi-signer workflow:
**[CAC-PDF-SIGNING.md](CAC-PDF-SIGNING.md)**.

**Why this tool and not the office suite:** LibreOffice/Draw, OnlyOffice, and JSignPdf all
add a *new* (often invisible) signature and leave the pre-placed block empty; only pyHanko
signs *into* the existing field. (See Gotchas.)

---

## 3. Browser crash fix

Chromium-family browsers crash intermittently on CAC/TLS sites. The fix launches them with
memory locking disabled.

```bash
python3 cac-setup.py crash-fix            # wrap every Chromium-family browser (Chrome, Brave, Edge, …)
python3 cac-setup.py crash-fix --dry-run  # preview
python3 cac-setup.py crash-fix --revert   # undo
```

This writes a per-user `.desktop` override for each installed Chromium-family browser that
starts it under `prlimit --memlock=0`. **Fully quit and relaunch** a browser for it to take
effect; re-run after installing a new browser. Confirm it's active:

```bash
grep 'Max locked memory' /proc/$(pgrep -x chrome | head -1)/limits   # want: 0   0
```

### Why the crash happens

During TLS handshakes (including CAC auth), the browser's crypto service `mlock()`s pages
**inside PartitionAlloc's heap**. When PartitionAlloc later decommits a span overlapping a
still-locked page, `madvise(MADV_DONTNEED)` returns `EINVAL` and the browser treats it as
fatal — a recurring crash, independent of distro, kernel, or browser version. Launching with
`RLIMIT_MEMLOCK=0` makes those `mlock()`s fail harmlessly (crypto falls back to unlocked
memory), so no page is ever locked and the fault can't occur. The CAC private key never
leaves the card, so the security impact is negligible.

### Diagnostic (only if the crash ever returns)

```bash
python3 cac-setup.py trace-locks            # runs Chrome under strace, logs mlock() calls
python3 cac-setup.py trace-locks nosandbox  # if pages won't load under tracing
```

Reproduce the crash, then inspect `~/chrome-lock-trace.log`.

---

## Gotchas & troubleshooting

### Signing

- **Fill the PDF before you sign (safe default).** Whether you can edit *after* signing
  depends on the signature type: this tool makes *approval* signatures that **don't** lock the
  document, so other fields often stay fillable (and the signature stays valid if the edit is
  saved incrementally). Certification (DocMDP P1) signatures and field `/Lock`s *do* freeze it.
  Filling first always works — and note a *full re-save* by an editor destroys any signature.
  See [CAC-PDF-SIGNING.md](CAC-PDF-SIGNING.md#does-signing-lock-the-document).
- **Multiple signers = sequential on one file.** Person A signs their block → sends the signed
  file to B → B signs theirs, etc. All form data must be filled before the *first* signature.
- **Sign with "Certificate for Digital Signature"** (PIV slot 02), not PIV Authentication.
- **OnlyOffice cannot sign with a CAC at all** on Linux — its signer is OpenSSL/file-based
  (`.pfx`/PEM), no PKCS#11, and the CAC key is non-exportable. Its "Sign" button just does
  nothing. Use the bundled pyHanko signer for PDFs, or LibreOffice for whole documents
  (ODT/DOCX).
- **JSignPdf, LibreOffice/Draw, and Okular can't fill an existing signature block** — they add
  a new/invisible signature, leaving the block empty in Acrobat. Okular also rides
  `libpoppler` 24.02, which has a broken-CMS smartcard bug (same as `pdfsig` 24.02, which is
  therefore verify-only: `pdfsig file.pdf -nssdir sql:$HOME/.pki/nssdb`).
- **LibreOffice** (for ODT/DOCX): export `MOZILLA_CERTIFICATE_FOLDER=$HOME/.pki/nssdb` for GUI
  launches (e.g. via `~/.config/environment.d/`), then **fully quit and relaunch** it — it
  reads the NSS DB only at startup.

### Card / reader

- **Insert the CAC *before* launching** the browser or the signer, so the certificate/token is
  present when it's enumerated.
- **`pcscd` must be running:** `systemctl status pcscd`; restart with `sudo systemctl restart
  pcscd`. Verify the card reads with `pkcs11-tool --list-slots`.
- **Card not recognized after a VM shuts down:** a VM using USB passthrough grabbed the reader
  and the host's `pcscd` didn't reclaim it. Fix: `sudo systemctl restart pcscd` (or replug the
  reader) after the VM closes.

### Browsers

- **Fully quit a browser** (not just close the window) for the crash fix — or any NSS change —
  to take effect. Re-run `crash-fix` after installing a new browser.
- **"You can't download this resource from this untrusted device"** on SharePoint/`*.dps.mil`
  is **Entra Conditional Access device trust**, not a browser/CAC problem — spoofing the
  user-agent won't help. Access it from a **compliant/managed device**, e.g. via Azure Virtual
  Desktop (the AVD web client at `https://rdweb.wvd.azure.us/arm/webclient/` for the DoD Gov
  cloud), then open the site from inside that session.

### Privilege model

- The **cert install** and the `--apply-crash-fix` / `--add-pdf-signer` flags need **`sudo`**.
- The `crash-fix`, `pdf-signer`, and `trace-locks` **subcommands must run as your normal user**
  (no sudo) — they write launchers/venv into your home and refuse to run as root. The
  `--apply`/`--add` flags handle this for you by re-invoking as the invoking user.

---

## Notes

- Single file, no build step, not a git repo — deletions are permanent, so keep a copy.
- The PDF signer program is embedded in `cac-setup.py` and written to
  `~/bin/cac-sign-pdf-gui.py` on install; its dependencies live in the `~/.venvs/pyhanko` venv.
- Docs: this README, plus **[CAC-PDF-SIGNING.md](CAC-PDF-SIGNING.md)** for the signing
  walkthrough.

[pyHanko]: https://github.com/MatthiasValvekens/pyHanko
